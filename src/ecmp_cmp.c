#include "ecmp_internal.h"

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>

#include "mbedtls/asn1.h"
#include "mbedtls/asn1write.h"
#include "mbedtls/md.h"
#include "mbedtls/oid.h"

#define ECMP_OUTPUT_BUF_SIZE 8192
#define ECMP_PBM_OID "\x2a\x86\x48\x86\xf6\x7d\x07\x42\x0d"
#define ECMP_IMPLICIT_CONFIRM_OID "\x2b\x06\x01\x05\x05\x07\x04\x0d"
#define ECMP_RFC4210_HMAC_SHA1_OID "\x2b\x06\x01\x05\x05\x08\x01\x02"

typedef struct ecmp_der_view {
    const unsigned char *p;
    const unsigned char *end;
} ecmp_der_view;

static int ecmp_skip_tlv(ecmp_der_view *view);
static int ecmp_parse_directory_name(ecmp_der_view *view, ecmp_buf *name_der);
static int ecmp_verify_signature_protection(const ecmp_crypto_provider *crypto,
                                            const ecmp_message_state *parsed,
                                            const unsigned char *protected_part,
                                            size_t protected_part_len);

static int ecmp_get_md_type(ecmp_hash_alg alg, mbedtls_md_type_t *md_type)
{
    if (md_type == NULL) {
        return ECMP_ERR_PARAM;
    }

    switch (alg) {
        case ECMP_HASH_SHA256:
            *md_type = MBEDTLS_MD_SHA256;
            return 0;
        case ECMP_HASH_SHA384:
            *md_type = MBEDTLS_MD_SHA384;
            return 0;
        case ECMP_HASH_SHA512:
            *md_type = MBEDTLS_MD_SHA512;
            return 0;
        default:
            return ECMP_ERR_UNSUPPORTED;
    }
}

static int ecmp_hash_alg_from_md(mbedtls_md_type_t md_type, ecmp_hash_alg *alg)
{
    if (alg == NULL) {
        return ECMP_ERR_PARAM;
    }

    switch (md_type) {
        case MBEDTLS_MD_SHA256:
            *alg = ECMP_HASH_SHA256;
            return 0;
        case MBEDTLS_MD_SHA384:
            *alg = ECMP_HASH_SHA384;
            return 0;
        case MBEDTLS_MD_SHA512:
            *alg = ECMP_HASH_SHA512;
            return 0;
        default:
            fprintf(stderr, "ecmp: unsupported md type %d\n", (int) md_type);
            return ECMP_ERR_UNSUPPORTED;
    }
}

void ecmp_buf_free(ecmp_buf *buf)
{
    if (buf == NULL) {
        return;
    }

    free(buf->data);
    buf->data = NULL;
    buf->len = 0;
}

int ecmp_buf_dup(ecmp_buf *dst, const unsigned char *src, size_t len)
{
    if (dst == NULL || (src == NULL && len != 0U)) {
        return ECMP_ERR_PARAM;
    }

    ecmp_buf_free(dst);
    if (len == 0U) {
        return 0;
    }

    dst->data = calloc(1, len);
    if (dst->data == NULL) {
        return ECMP_ERR_ALLOC;
    }
    memcpy(dst->data, src, len);
    dst->len = len;
    return 0;
}

void ecmp_message_state_free(ecmp_message_state *state)
{
    if (state == NULL) {
        return;
    }

    ecmp_buf_free(&state->sender_der);
    ecmp_buf_free(&state->recipient_der);
    ecmp_buf_free(&state->sender_kid);
    ecmp_buf_free(&state->transaction_id);
    ecmp_buf_free(&state->sender_nonce);
    ecmp_buf_free(&state->recip_nonce);
    ecmp_buf_free(&state->pbm.salt);
    ecmp_buf_free(&state->protection_alg_oid);
    ecmp_buf_free(&state->issued_cert_der);
    ecmp_buf_free(&state->extra_certs_der);
    ecmp_buf_free(&state->protection);
    memset(state, 0, sizeof(*state));
}

static int ecmp_copy_and_wrap_output(unsigned char *buf, unsigned char *p,
                                     unsigned char **out, size_t *out_len)
{
    size_t len;

    if (buf == NULL || p == NULL || out == NULL || out_len == NULL) {
        return ECMP_ERR_PARAM;
    }

    len = (size_t) (buf + ECMP_OUTPUT_BUF_SIZE - p);
    *out = calloc(1, len);
    if (*out == NULL) {
        return ECMP_ERR_ALLOC;
    }
    memcpy(*out, p, len);
    *out_len = len;
    return 0;
}

static int ecmp_build_protected_part(const unsigned char *header_der, size_t header_len,
                                     const unsigned char *body_der, size_t body_len,
                                     unsigned char **out, size_t *out_len)
{
    unsigned char buf[ECMP_OUTPUT_BUF_SIZE] = { 0 };
    unsigned char *p = buf + sizeof(buf);
    size_t len = 0;
    int ret = 0;

    if (header_der == NULL || body_der == NULL || out == NULL || out_len == NULL) {
        return ECMP_ERR_PARAM;
    }

    MBEDTLS_ASN1_CHK_ADD(len, mbedtls_asn1_write_raw_buffer(&p, buf, body_der, body_len));
    MBEDTLS_ASN1_CHK_ADD(len, mbedtls_asn1_write_raw_buffer(&p, buf, header_der, header_len));
    MBEDTLS_ASN1_CHK_ADD(len, mbedtls_asn1_write_len(&p, buf, len));
    MBEDTLS_ASN1_CHK_ADD(len, mbedtls_asn1_write_tag(&p, buf,
                                                     MBEDTLS_ASN1_CONSTRUCTED |
                                                     MBEDTLS_ASN1_SEQUENCE));
    return ecmp_copy_and_wrap_output(buf, p, out, out_len);
}

static int ecmp_set_message_time(ecmp_message_state *state)
{
    time_t now;
    struct tm *utc_tm;

    if (state == NULL) {
        return ECMP_ERR_PARAM;
    }

    now = time(NULL);
    utc_tm = gmtime(&now);
    if (utc_tm == NULL) {
        return ECMP_ERR_PROTOCOL;
    }
    if (strftime(state->message_time, sizeof(state->message_time),
                 "%Y%m%d%H%M%SZ", utc_tm) == 0) {
        return ECMP_ERR_PROTOCOL;
    }
    state->has_message_time = 1;
    return 0;
}

static int ecmp_write_octet_string(unsigned char **p, unsigned char *start,
                                   const unsigned char *data, size_t data_len)
{
    int ret;
    size_t len = 0;

    MBEDTLS_ASN1_CHK_ADD(len, mbedtls_asn1_write_raw_buffer(p, start, data, data_len));
    MBEDTLS_ASN1_CHK_ADD(len, mbedtls_asn1_write_len(p, start, len));
    MBEDTLS_ASN1_CHK_ADD(len, mbedtls_asn1_write_tag(p, start, MBEDTLS_ASN1_OCTET_STRING));
    return (int) len;
}

static int ecmp_write_explicit_general_name(unsigned char **p, unsigned char *start,
                                            const ecmp_buf *name_der)
{
    int ret;
    size_t len = 0;

    MBEDTLS_ASN1_CHK_ADD(len,
                         mbedtls_asn1_write_raw_buffer(p, start,
                                                       name_der->data, name_der->len));
    MBEDTLS_ASN1_CHK_ADD(len, mbedtls_asn1_write_len(p, start, len));
    MBEDTLS_ASN1_CHK_ADD(len,
                         mbedtls_asn1_write_tag(p, start,
                                                MBEDTLS_ASN1_CONTEXT_SPECIFIC |
                                                MBEDTLS_ASN1_CONSTRUCTED | 4));
    return (int) len;
}

static int ecmp_write_implicit_octet_string(unsigned char **p, unsigned char *start,
                                            int tag_no, const ecmp_buf *buf)
{
    int ret;
    size_t len = 0;

    MBEDTLS_ASN1_CHK_ADD(len, ecmp_write_octet_string(p, start, buf->data, buf->len));
    MBEDTLS_ASN1_CHK_ADD(len, mbedtls_asn1_write_len(p, start, len));
    MBEDTLS_ASN1_CHK_ADD(len,
                         mbedtls_asn1_write_tag(p, start,
                                                MBEDTLS_ASN1_CONTEXT_SPECIFIC |
                                                MBEDTLS_ASN1_CONSTRUCTED | tag_no));
    return (int) len;
}

static int ecmp_write_hash_alg(unsigned char **p, unsigned char *start,
                               ecmp_hash_alg alg)
{
    mbedtls_md_type_t md_type;
    const char *oid = NULL;
    size_t oid_len = 0;
    int ret;

    ret = ecmp_get_md_type(alg, &md_type);
    if (ret != 0) {
        return ret;
    }
    if (mbedtls_oid_get_oid_by_md(md_type, &oid, &oid_len) != 0) {
        return ECMP_ERR_UNSUPPORTED;
    }
    return mbedtls_asn1_write_algorithm_identifier(p, start, oid, oid_len, 0);
}

static int ecmp_write_hmac_alg(unsigned char **p, unsigned char *start,
                               ecmp_hash_alg alg)
{
    const char *oid = NULL;
    size_t oid_len = 0;

    switch (alg) {
        case ECMP_HASH_SHA256:
            oid = MBEDTLS_OID_HMAC_SHA256;
            oid_len = sizeof(MBEDTLS_OID_HMAC_SHA256) - 1;
            break;
        case ECMP_HASH_SHA384:
            oid = MBEDTLS_OID_HMAC_SHA384;
            oid_len = sizeof(MBEDTLS_OID_HMAC_SHA384) - 1;
            break;
        case ECMP_HASH_SHA512:
            oid = MBEDTLS_OID_HMAC_SHA512;
            oid_len = sizeof(MBEDTLS_OID_HMAC_SHA512) - 1;
            break;
        default:
            return ECMP_ERR_UNSUPPORTED;
    }

    return mbedtls_asn1_write_algorithm_identifier(p, start, oid, oid_len, 0);
}

static int ecmp_write_pbm_parameters(unsigned char **p, unsigned char *start,
                                     const ecmp_pbm_params *pbm)
{
    int ret;
    size_t len = 0;

    MBEDTLS_ASN1_CHK_ADD(len, ecmp_write_hmac_alg(p, start, pbm->mac));
    MBEDTLS_ASN1_CHK_ADD(len, mbedtls_asn1_write_int(p, start, pbm->iteration_count));
    MBEDTLS_ASN1_CHK_ADD(len, ecmp_write_hash_alg(p, start, pbm->owf));
    MBEDTLS_ASN1_CHK_ADD(len, ecmp_write_octet_string(p, start,
                                                      pbm->salt.data, pbm->salt.len));
    MBEDTLS_ASN1_CHK_ADD(len, mbedtls_asn1_write_len(p, start, len));
    MBEDTLS_ASN1_CHK_ADD(len, mbedtls_asn1_write_tag(p, start,
                                                     MBEDTLS_ASN1_CONSTRUCTED |
                                                     MBEDTLS_ASN1_SEQUENCE));
    return (int) len;
}

static int ecmp_compute_pbm(const ecmp_crypto_provider *crypto,
                            const ecmp_pbm_params *pbm,
                            const char *secret,
                            const unsigned char *input, size_t input_len,
                            unsigned char **mac, size_t *mac_len)
{
    unsigned char *base = NULL;
    size_t base_len = 0;
    ecmp_buf salted = { 0 };
    ecmp_buf next = { 0 };
    int ret;
    int iter;

    if (crypto == NULL || pbm == NULL || secret == NULL || input == NULL ||
        mac == NULL || mac_len == NULL) {
        return ECMP_ERR_PARAM;
    }

    salted.len = strlen(secret) + pbm->salt.len;
    salted.data = calloc(1, salted.len);
    if (salted.data == NULL) {
        return ECMP_ERR_ALLOC;
    }

    memcpy(salted.data, secret, strlen(secret));
    memcpy(salted.data + strlen(secret), pbm->salt.data, pbm->salt.len);

    ret = crypto->hash(crypto->ctx, pbm->owf, salted.data, salted.len,
                       &base, &base_len);
    if (ret != 0) {
        ret = ECMP_ERR_CRYPTO;
        goto cleanup;
    }

    for (iter = 1; iter < pbm->iteration_count; ++iter) {
        ret = crypto->hash(crypto->ctx, pbm->owf, base, base_len,
                           &next.data, &next.len);
        if (ret != 0) {
            ret = ECMP_ERR_CRYPTO;
            goto cleanup;
        }
        free(base);
        base = next.data;
        base_len = next.len;
        next.data = NULL;
        next.len = 0;
    }

    ret = crypto->hmac(crypto->ctx, pbm->mac, base, base_len, input, input_len,
                       mac, mac_len);
    if (ret != 0) {
        ret = ECMP_ERR_CRYPTO;
    }

cleanup:
    free(base);
    ecmp_buf_free(&salted);
    ecmp_buf_free(&next);
    return ret;
}

static int ecmp_write_pbm_protection(unsigned char **p, unsigned char *start,
                                     const ecmp_crypto_provider *crypto,
                                     const ecmp_message_state *state,
                                     const char *pbm_secret,
                                     const unsigned char *protected_part,
                                     size_t protected_part_len)
{
    unsigned char *mac = NULL;
    size_t mac_len = 0;
    size_t len = 0;
    int ret;

    ret = ecmp_compute_pbm(crypto, &state->pbm, pbm_secret,
                           protected_part, protected_part_len, &mac, &mac_len);
    if (ret != 0) {
        return ret;
    }

    MBEDTLS_ASN1_CHK_ADD(len, mbedtls_asn1_write_raw_buffer(p, start, mac, mac_len));
    if (*p <= start) {
        free(mac);
        return ECMP_ERR_ASN1;
    }
    *--(*p) = 0;
    len += 1;
    MBEDTLS_ASN1_CHK_ADD(len, mbedtls_asn1_write_len(p, start, len));
    MBEDTLS_ASN1_CHK_ADD(len, mbedtls_asn1_write_tag(p, start, MBEDTLS_ASN1_BIT_STRING));
    MBEDTLS_ASN1_CHK_ADD(len, mbedtls_asn1_write_len(p, start, len));
    MBEDTLS_ASN1_CHK_ADD(len, mbedtls_asn1_write_tag(p, start,
                                                     MBEDTLS_ASN1_CONTEXT_SPECIFIC |
                                                     MBEDTLS_ASN1_CONSTRUCTED | 0));
    free(mac);
    return (int) len;
}

static int ecmp_write_pkiheader(unsigned char **p, unsigned char *start,
                                const ecmp_message_state *state,
                                const char *pbm_secret)
{
    int ret;
    size_t len = 0;
    size_t sub_len = 0;
    size_t param_len = 0;
    (void) pbm_secret;

    if (state->implicit_confirm) {
        sub_len = 0;
        MBEDTLS_ASN1_CHK_ADD(sub_len, mbedtls_asn1_write_null(p, start));
        MBEDTLS_ASN1_CHK_ADD(sub_len,
                             mbedtls_asn1_write_oid(p, start,
                                                    ECMP_IMPLICIT_CONFIRM_OID,
                                                    sizeof(ECMP_IMPLICIT_CONFIRM_OID) - 1));
        MBEDTLS_ASN1_CHK_ADD(sub_len, mbedtls_asn1_write_len(p, start, sub_len));
        MBEDTLS_ASN1_CHK_ADD(sub_len, mbedtls_asn1_write_tag(p, start,
                                                             MBEDTLS_ASN1_CONSTRUCTED |
                                                             MBEDTLS_ASN1_SEQUENCE));
        MBEDTLS_ASN1_CHK_ADD(sub_len, mbedtls_asn1_write_len(p, start, sub_len));
        MBEDTLS_ASN1_CHK_ADD(sub_len, mbedtls_asn1_write_tag(p, start,
                                                             MBEDTLS_ASN1_CONSTRUCTED |
                                                             MBEDTLS_ASN1_SEQUENCE));
        MBEDTLS_ASN1_CHK_ADD(sub_len, mbedtls_asn1_write_len(p, start, sub_len));
        MBEDTLS_ASN1_CHK_ADD(sub_len, mbedtls_asn1_write_tag(p, start,
                                                             MBEDTLS_ASN1_CONTEXT_SPECIFIC |
                                                             MBEDTLS_ASN1_CONSTRUCTED | 8));
        len += sub_len;
    }

    if (state->recip_nonce.data != NULL) {
        MBEDTLS_ASN1_CHK_ADD(len, ecmp_write_implicit_octet_string(p, start, 6,
                                                                   &state->recip_nonce));
    }
    MBEDTLS_ASN1_CHK_ADD(len, ecmp_write_implicit_octet_string(p, start, 5,
                                                               &state->sender_nonce));
    MBEDTLS_ASN1_CHK_ADD(len, ecmp_write_implicit_octet_string(p, start, 4,
                                                               &state->transaction_id));
    MBEDTLS_ASN1_CHK_ADD(len, ecmp_write_implicit_octet_string(p, start, 2,
                                                               &state->sender_kid));

    param_len = 0;
    MBEDTLS_ASN1_CHK_ADD(param_len, ecmp_write_pbm_parameters(p, start, &state->pbm));
    sub_len = 0;
    MBEDTLS_ASN1_CHK_ADD(sub_len,
                         mbedtls_asn1_write_algorithm_identifier(
                             p, start, ECMP_PBM_OID, sizeof(ECMP_PBM_OID) - 1,
                             param_len));
    len += sub_len;
    MBEDTLS_ASN1_CHK_ADD(len, mbedtls_asn1_write_len(p, start, sub_len));
    MBEDTLS_ASN1_CHK_ADD(len, mbedtls_asn1_write_tag(p, start,
                                                     MBEDTLS_ASN1_CONTEXT_SPECIFIC |
                                                     MBEDTLS_ASN1_CONSTRUCTED | 1));

    if (state->has_message_time) {
        sub_len = 0;
        MBEDTLS_ASN1_CHK_ADD(sub_len,
                             mbedtls_asn1_write_raw_buffer(
                                 p, start,
                                 (const unsigned char *) state->message_time,
                                 strlen(state->message_time)));
        MBEDTLS_ASN1_CHK_ADD(sub_len, mbedtls_asn1_write_len(p, start, sub_len));
        MBEDTLS_ASN1_CHK_ADD(sub_len,
                             mbedtls_asn1_write_tag(p, start,
                                                    MBEDTLS_ASN1_GENERALIZED_TIME));
        len += sub_len;
        MBEDTLS_ASN1_CHK_ADD(len, mbedtls_asn1_write_len(p, start, sub_len));
        MBEDTLS_ASN1_CHK_ADD(len, mbedtls_asn1_write_tag(p, start,
                                                         MBEDTLS_ASN1_CONTEXT_SPECIFIC |
                                                         MBEDTLS_ASN1_CONSTRUCTED | 0));
    }
    MBEDTLS_ASN1_CHK_ADD(len, ecmp_write_explicit_general_name(p, start,
                                                               &state->recipient_der));
    MBEDTLS_ASN1_CHK_ADD(len, ecmp_write_explicit_general_name(p, start,
                                                               &state->sender_der));
    MBEDTLS_ASN1_CHK_ADD(len, mbedtls_asn1_write_int(p, start, state->pvno));
    MBEDTLS_ASN1_CHK_ADD(len, mbedtls_asn1_write_len(p, start, len));
    MBEDTLS_ASN1_CHK_ADD(len, mbedtls_asn1_write_tag(p, start,
                                                     MBEDTLS_ASN1_CONSTRUCTED |
                                                     MBEDTLS_ASN1_SEQUENCE));
    return (int) len;
}

static int ecmp_write_certrequest(unsigned char **p, unsigned char *start,
                                  const ecmp_buf *subject_der,
                                  const ecmp_buf *spki_der)
{
    int ret;
    size_t len = 0;
    size_t tmpl_len = 0;
    size_t pub_len = 0;
    size_t subj_len = 0;

    MBEDTLS_ASN1_CHK_ADD(pub_len, mbedtls_asn1_write_raw_buffer(p, start,
                                                                spki_der->data + 1,
                                                                spki_der->len - 1));
    MBEDTLS_ASN1_CHK_ADD(pub_len, mbedtls_asn1_write_tag(p, start,
                                                         MBEDTLS_ASN1_CONTEXT_SPECIFIC |
                                                         MBEDTLS_ASN1_CONSTRUCTED | 6));
    tmpl_len += pub_len;

    MBEDTLS_ASN1_CHK_ADD(subj_len, mbedtls_asn1_write_raw_buffer(p, start,
                                                                 subject_der->data,
                                                                 subject_der->len));
    MBEDTLS_ASN1_CHK_ADD(subj_len, mbedtls_asn1_write_len(p, start, subj_len));
    MBEDTLS_ASN1_CHK_ADD(subj_len, mbedtls_asn1_write_tag(p, start,
                                                          MBEDTLS_ASN1_CONTEXT_SPECIFIC |
                                                          MBEDTLS_ASN1_CONSTRUCTED | 5));
    tmpl_len += subj_len;

    MBEDTLS_ASN1_CHK_ADD(tmpl_len, mbedtls_asn1_write_len(p, start, tmpl_len));
    MBEDTLS_ASN1_CHK_ADD(tmpl_len, mbedtls_asn1_write_tag(p, start,
                                                          MBEDTLS_ASN1_CONSTRUCTED |
                                                          MBEDTLS_ASN1_SEQUENCE));
    len += tmpl_len;
    MBEDTLS_ASN1_CHK_ADD(len, mbedtls_asn1_write_int(p, start, 0));
    MBEDTLS_ASN1_CHK_ADD(len, mbedtls_asn1_write_len(p, start, len));
    MBEDTLS_ASN1_CHK_ADD(len, mbedtls_asn1_write_tag(p, start,
                                                     MBEDTLS_ASN1_CONSTRUCTED |
                                                     MBEDTLS_ASN1_SEQUENCE));
    return (int) len;
}

static int ecmp_write_popo(unsigned char **p, unsigned char *start,
                           const ecmp_crypto_provider *crypto,
                           const ecmp_key *key,
                           const unsigned char *certreq_der,
                           size_t certreq_der_len)
{
    unsigned char *sig = NULL;
    size_t sig_len = 0;
    size_t alg_len = 0;
    const char *sig_oid = NULL;
    size_t sig_oid_len = 0;
    size_t len = 0;
    int ret;

    ret = crypto->sign(crypto->ctx, key, ECMP_HASH_SHA256,
                       certreq_der, certreq_der_len, &sig, &sig_len);
    if (ret != 0) {
        return ECMP_ERR_CRYPTO;
    }

    if (mbedtls_oid_get_oid_by_sig_alg(MBEDTLS_PK_ECDSA, MBEDTLS_MD_SHA256,
                                       &sig_oid, &sig_oid_len) != 0) {
        free(sig);
        return ECMP_ERR_UNSUPPORTED;
    }

    MBEDTLS_ASN1_CHK_ADD(len, mbedtls_asn1_write_raw_buffer(p, start, sig, sig_len));
    if (*p <= start) {
        free(sig);
        return ECMP_ERR_ASN1;
    }
    *--(*p) = 0;
    len += 1;
    MBEDTLS_ASN1_CHK_ADD(len, mbedtls_asn1_write_len(p, start, len));
    MBEDTLS_ASN1_CHK_ADD(len, mbedtls_asn1_write_tag(p, start, MBEDTLS_ASN1_BIT_STRING));
    MBEDTLS_ASN1_CHK_ADD(alg_len, mbedtls_asn1_write_oid(p, start, sig_oid, sig_oid_len));
    MBEDTLS_ASN1_CHK_ADD(alg_len, mbedtls_asn1_write_len(p, start, alg_len));
    MBEDTLS_ASN1_CHK_ADD(alg_len, mbedtls_asn1_write_tag(p, start,
                                                         MBEDTLS_ASN1_CONSTRUCTED |
                                                         MBEDTLS_ASN1_SEQUENCE));
    len += alg_len;
    MBEDTLS_ASN1_CHK_ADD(len, mbedtls_asn1_write_len(p, start, len));
    MBEDTLS_ASN1_CHK_ADD(len, mbedtls_asn1_write_tag(p, start,
                                                     MBEDTLS_ASN1_CONTEXT_SPECIFIC |
                                                     MBEDTLS_ASN1_CONSTRUCTED | 1));
    free(sig);
    return (int) len;
}

static int ecmp_write_ir_body(unsigned char **p, unsigned char *start,
                              const ecmp_crypto_provider *crypto,
                              const ecmp_key *key,
                              const ecmp_buf *subject_der,
                              const ecmp_buf *spki_der)
{
    unsigned char certreq_buf[ECMP_OUTPUT_BUF_SIZE];
    unsigned char *tmp_p = certreq_buf + sizeof(certreq_buf);
    unsigned char *certreq_start;
    size_t certreq_len;
    size_t len = 0;
    int ret;

    ret = ecmp_write_certrequest(&tmp_p, certreq_buf, subject_der, spki_der);
    if (ret < 0) {
        return ret;
    }
    certreq_len = (size_t) ret;
    certreq_start = certreq_buf + sizeof(certreq_buf) - certreq_len;

    MBEDTLS_ASN1_CHK_ADD(len, ecmp_write_popo(p, start, crypto, key,
                                              certreq_start, certreq_len));
    MBEDTLS_ASN1_CHK_ADD(len, mbedtls_asn1_write_raw_buffer(p, start,
                                                            certreq_start, certreq_len));
    MBEDTLS_ASN1_CHK_ADD(len, mbedtls_asn1_write_len(p, start, len));
    MBEDTLS_ASN1_CHK_ADD(len, mbedtls_asn1_write_tag(p, start,
                                                     MBEDTLS_ASN1_CONSTRUCTED |
                                                     MBEDTLS_ASN1_SEQUENCE));
    MBEDTLS_ASN1_CHK_ADD(len, mbedtls_asn1_write_len(p, start, len));
    MBEDTLS_ASN1_CHK_ADD(len, mbedtls_asn1_write_tag(p, start,
                                                     MBEDTLS_ASN1_CONSTRUCTED |
                                                     MBEDTLS_ASN1_SEQUENCE));
    MBEDTLS_ASN1_CHK_ADD(len, mbedtls_asn1_write_len(p, start, len));
    MBEDTLS_ASN1_CHK_ADD(len, mbedtls_asn1_write_tag(p, start,
                                                     MBEDTLS_ASN1_CONTEXT_SPECIFIC |
                                                     MBEDTLS_ASN1_CONSTRUCTED | 0));
    return (int) len;
}

static int ecmp_write_certconf_body(unsigned char **p, unsigned char *start,
                                    const ecmp_crypto_provider *crypto,
                                    ecmp_message_state *state)
{
    unsigned char *cert_hash = NULL;
    size_t cert_hash_len = 0;
    size_t len = 0;
    size_t hash_alg_len = 0;
    int ret;

    ret = crypto->hash(crypto->ctx, ECMP_HASH_SHA256,
                       state->issued_cert_der.data, state->issued_cert_der.len,
                       &cert_hash, &cert_hash_len);
    if (ret != 0) {
        return ECMP_ERR_CRYPTO;
    }

    if (state->pvno >= 3) {
        MBEDTLS_ASN1_CHK_ADD(hash_alg_len, ecmp_write_hash_alg(p, start, ECMP_HASH_SHA256));
        len += hash_alg_len;
        MBEDTLS_ASN1_CHK_ADD(len, mbedtls_asn1_write_len(p, start, hash_alg_len));
        MBEDTLS_ASN1_CHK_ADD(len, mbedtls_asn1_write_tag(p, start,
                                                         MBEDTLS_ASN1_CONTEXT_SPECIFIC |
                                                         MBEDTLS_ASN1_CONSTRUCTED | 0));
    }
    MBEDTLS_ASN1_CHK_ADD(len, mbedtls_asn1_write_int(p, start, 0));
    MBEDTLS_ASN1_CHK_ADD(len, ecmp_write_octet_string(p, start, cert_hash, cert_hash_len));
    MBEDTLS_ASN1_CHK_ADD(len, mbedtls_asn1_write_len(p, start, len));
    MBEDTLS_ASN1_CHK_ADD(len, mbedtls_asn1_write_tag(p, start,
                                                     MBEDTLS_ASN1_CONSTRUCTED |
                                                     MBEDTLS_ASN1_SEQUENCE));
    MBEDTLS_ASN1_CHK_ADD(len, mbedtls_asn1_write_len(p, start, len));
    MBEDTLS_ASN1_CHK_ADD(len, mbedtls_asn1_write_tag(p, start,
                                                     MBEDTLS_ASN1_CONSTRUCTED |
                                                     MBEDTLS_ASN1_SEQUENCE));
    MBEDTLS_ASN1_CHK_ADD(len, mbedtls_asn1_write_len(p, start, len));
    MBEDTLS_ASN1_CHK_ADD(len, mbedtls_asn1_write_tag(p, start,
                                                     MBEDTLS_ASN1_CONTEXT_SPECIFIC |
                                                     MBEDTLS_ASN1_CONSTRUCTED | 24));
    free(cert_hash);
    return (int) len;
}

static int ecmp_prepare_ir_state(const ecmp_crypto_provider *crypto,
                                 const ecmp_ir_request *request,
                                 ecmp_message_state *state,
                                 const ecmp_buf *sender_der,
                                 const ecmp_buf *recipient_der)
{
    int ret;

    state->pvno = 2;
    state->implicit_confirm = request->request_implicit_confirm;
    state->body_type = 0;
    state->pbm.owf = ECMP_HASH_SHA256;
    state->pbm.mac = ECMP_HASH_SHA256;
    state->pbm.iteration_count = 1000;

    ret = ecmp_buf_dup(&state->sender_der, sender_der->data, sender_der->len);
    if (ret != 0) {
        return ret;
    }
    ret = ecmp_buf_dup(&state->recipient_der, recipient_der->data, recipient_der->len);
    if (ret != 0) {
        return ret;
    }
    ret = ecmp_buf_dup(&state->sender_kid,
                       (const unsigned char *) request->pbm_kid,
                       strlen(request->pbm_kid));
    if (ret != 0) {
        return ret;
    }
    state->transaction_id.data = calloc(1, 16);
    state->sender_nonce.data = calloc(1, 16);
    state->pbm.salt.data = calloc(1, 16);
    if (state->transaction_id.data == NULL || state->sender_nonce.data == NULL ||
        state->pbm.salt.data == NULL) {
        return ECMP_ERR_ALLOC;
    }
    state->transaction_id.len = 16;
    state->sender_nonce.len = 16;
    state->pbm.salt.len = 16;

    ret = crypto->random_bytes(crypto->ctx,
                               state->transaction_id.data, state->transaction_id.len);
    if (ret != 0) {
        return ECMP_ERR_CRYPTO;
    }
    ret = crypto->random_bytes(crypto->ctx,
                               state->sender_nonce.data, state->sender_nonce.len);
    if (ret != 0) {
        return ECMP_ERR_CRYPTO;
    }
    ret = crypto->random_bytes(crypto->ctx,
                               state->pbm.salt.data, state->pbm.salt.len);
    if (ret != 0) {
        return ECMP_ERR_CRYPTO;
    }

    return ecmp_set_message_time(state);
}

int ecmp_cmp_build_ir(const ecmp_crypto_provider *crypto, const ecmp_key *key,
                      const ecmp_ir_request *request, ecmp_message_state *state,
                      unsigned char **out, size_t *out_len)
{
    unsigned char *buf = NULL;
    unsigned char *p;
    unsigned char body_buf[ECMP_OUTPUT_BUF_SIZE];
    unsigned char header_buf[ECMP_OUTPUT_BUF_SIZE];
    unsigned char prot_buf[ECMP_OUTPUT_BUF_SIZE];
    unsigned char *body_p = body_buf + sizeof(body_buf);
    unsigned char *header_p = header_buf + sizeof(header_buf);
    unsigned char *prot_p = prot_buf + sizeof(prot_buf);
    unsigned char *protected_part = NULL;
    const unsigned char *body_der = NULL;
    const unsigned char *header_der = NULL;
    const unsigned char *prot_der = NULL;
    ecmp_buf sender_der = { 0 };
    ecmp_buf recipient_der = { 0 };
    ecmp_buf subject_der = { 0 };
    ecmp_buf spki_der = { 0 };
    size_t body_len = 0;
    size_t header_len = 0;
    size_t prot_len = 0;
    size_t total_len = 0;
    int ret;

    if (crypto == NULL || key == NULL || request == NULL || state == NULL ||
        out == NULL || out_len == NULL) {
        return ECMP_ERR_PARAM;
    }

    memset(state, 0, sizeof(*state));

    ret = crypto->name_to_der(crypto->ctx, request->sender_dn,
                              &sender_der.data, &sender_der.len);
    if (ret != 0) {
        ret = ECMP_ERR_CRYPTO;
        goto cleanup;
    }
    ret = crypto->name_to_der(crypto->ctx, request->recipient_dn,
                              &recipient_der.data, &recipient_der.len);
    if (ret != 0) {
        ret = ECMP_ERR_CRYPTO;
        goto cleanup;
    }
    ret = crypto->name_to_der(crypto->ctx, request->subject_dn,
                              &subject_der.data, &subject_der.len);
    if (ret != 0) {
        ret = ECMP_ERR_CRYPTO;
        goto cleanup;
    }
    ret = crypto->export_subject_public_key_info_der(crypto->ctx, key,
                                                     &spki_der.data, &spki_der.len);
    if (ret != 0) {
        ret = ECMP_ERR_CRYPTO;
        goto cleanup;
    }

    ret = ecmp_prepare_ir_state(crypto, request, state, &sender_der, &recipient_der);
    if (ret != 0) {
        goto cleanup;
    }

    buf = calloc(1, ECMP_OUTPUT_BUF_SIZE);
    if (buf == NULL) {
        ret = ECMP_ERR_ALLOC;
        goto cleanup;
    }
    p = buf + ECMP_OUTPUT_BUF_SIZE;

    ret = ecmp_write_ir_body(&body_p, body_buf, crypto, key, &subject_der, &spki_der);
    if (ret < 0) {
        goto cleanup;
    }
    body_len = (size_t) ret;
    body_der = body_buf + sizeof(body_buf) - body_len;

    ret = ecmp_write_pkiheader(&header_p, header_buf, state, request->pbm_secret);
    if (ret < 0) {
        goto cleanup;
    }
    header_len = (size_t) ret;
    header_der = header_buf + sizeof(header_buf) - header_len;

    ret = ecmp_build_protected_part(header_der, header_len, body_der, body_len,
                                    &protected_part, &total_len);
    if (ret != 0) {
        goto cleanup;
    }

    ret = ecmp_write_pbm_protection(&prot_p, prot_buf, crypto, state,
                                    request->pbm_secret,
                                    protected_part, total_len);
    if (ret < 0) {
        goto cleanup;
    }
    prot_len = (size_t) ret;
    prot_der = prot_buf + sizeof(prot_buf) - prot_len;

    total_len = 0;
    ret = 0;
    MBEDTLS_ASN1_CHK_ADD(total_len, mbedtls_asn1_write_raw_buffer(&p, buf, prot_der, prot_len));
    MBEDTLS_ASN1_CHK_ADD(total_len, mbedtls_asn1_write_raw_buffer(&p, buf, body_der, body_len));
    MBEDTLS_ASN1_CHK_ADD(total_len, mbedtls_asn1_write_raw_buffer(&p, buf, header_der, header_len));
    MBEDTLS_ASN1_CHK_ADD(total_len, mbedtls_asn1_write_len(&p, buf, total_len));
    MBEDTLS_ASN1_CHK_ADD(total_len, mbedtls_asn1_write_tag(&p, buf,
                                                           MBEDTLS_ASN1_CONSTRUCTED |
                                                           MBEDTLS_ASN1_SEQUENCE));

    ret = ecmp_copy_and_wrap_output(buf, p, out, out_len);
    if (ret != 0) {
        goto cleanup;
    }

cleanup:
    free(buf);
    free(protected_part);
    ecmp_buf_free(&sender_der);
    ecmp_buf_free(&recipient_der);
    ecmp_buf_free(&subject_der);
    ecmp_buf_free(&spki_der);
    return ret;
}

int ecmp_cmp_build_certconf(const ecmp_crypto_provider *crypto,
                            const ecmp_ir_request *request,
                            ecmp_message_state *state,
                            unsigned char **out, size_t *out_len)
{
    unsigned char *buf = NULL;
    unsigned char *p;
    unsigned char body_buf[ECMP_OUTPUT_BUF_SIZE];
    unsigned char header_buf[ECMP_OUTPUT_BUF_SIZE];
    unsigned char prot_buf[ECMP_OUTPUT_BUF_SIZE];
    unsigned char *body_p = body_buf + sizeof(body_buf);
    unsigned char *header_p = header_buf + sizeof(header_buf);
    unsigned char *prot_p = prot_buf + sizeof(prot_buf);
    unsigned char *protected_part = NULL;
    const unsigned char *body_der = NULL;
    const unsigned char *header_der = NULL;
    const unsigned char *prot_der = NULL;
    size_t body_len = 0;
    size_t header_len = 0;
    size_t prot_len = 0;
    size_t total_len = 0;
    ecmp_buf new_sender_der = { 0 };
    ecmp_buf new_recipient_der = { 0 };
    ecmp_buf new_sender_kid = { 0 };
    int ret;

    if (crypto == NULL || request == NULL || state == NULL || out == NULL ||
        out_len == NULL) {
        return ECMP_ERR_PARAM;
    }

    if (state->recipient_der.data != NULL && state->recipient_der.len > 0) {
        ret = ecmp_buf_dup(&new_sender_der, state->recipient_der.data,
                           state->recipient_der.len);
    } else {
        ret = crypto->name_to_der(crypto->ctx, request->sender_dn,
                                  &new_sender_der.data, &new_sender_der.len);
    }
    if (ret != 0) {
        ret = ECMP_ERR_CRYPTO;
        goto cleanup;
    }

    if (state->sender_der.data != NULL && state->sender_der.len > 0) {
        ret = ecmp_buf_dup(&new_recipient_der, state->sender_der.data,
                           state->sender_der.len);
    } else {
        ret = crypto->name_to_der(crypto->ctx, request->recipient_dn,
                                  &new_recipient_der.data, &new_recipient_der.len);
    }
    if (ret != 0) {
        ret = ECMP_ERR_CRYPTO;
        goto cleanup;
    }

    ret = ecmp_buf_dup(&new_sender_kid,
                       (const unsigned char *) request->pbm_kid,
                       strlen(request->pbm_kid));
    if (ret != 0) {
        goto cleanup;
    }

    ecmp_buf_free(&state->sender_der);
    ecmp_buf_free(&state->recipient_der);
    ecmp_buf_free(&state->sender_kid);
    state->sender_der = new_sender_der;
    state->recipient_der = new_recipient_der;
    state->sender_kid = new_sender_kid;
    memset(&new_sender_der, 0, sizeof(new_sender_der));
    memset(&new_recipient_der, 0, sizeof(new_recipient_der));
    memset(&new_sender_kid, 0, sizeof(new_sender_kid));

    state->implicit_confirm = 0;
    state->protection_is_pbm = 1;

    ecmp_buf_free(&state->sender_nonce);
    state->sender_nonce.data = calloc(1, 16);
    if (state->sender_nonce.data == NULL) {
        ret = ECMP_ERR_ALLOC;
        goto cleanup;
    }
    state->sender_nonce.len = 16;
    ret = crypto->random_bytes(crypto->ctx, state->sender_nonce.data,
                               state->sender_nonce.len);
    if (ret != 0) {
        ret = ECMP_ERR_CRYPTO;
        goto cleanup;
    }
    ret = ecmp_set_message_time(state);
    if (ret != 0) {
        goto cleanup;
    }

    buf = calloc(1, ECMP_OUTPUT_BUF_SIZE);
    if (buf == NULL) {
        ret = ECMP_ERR_ALLOC;
        goto cleanup;
    }
    p = buf + ECMP_OUTPUT_BUF_SIZE;

    ret = ecmp_write_certconf_body(&body_p, body_buf, crypto, state);
    if (ret < 0) {
        goto cleanup;
    }
    body_len = (size_t) ret;
    body_der = body_buf + sizeof(body_buf) - body_len;

    ret = ecmp_write_pkiheader(&header_p, header_buf, state, request->pbm_secret);
    if (ret < 0) {
        goto cleanup;
    }
    header_len = (size_t) ret;
    header_der = header_buf + sizeof(header_buf) - header_len;

    ret = ecmp_build_protected_part(header_der, header_len, body_der, body_len,
                                    &protected_part, &total_len);
    if (ret != 0) {
        goto cleanup;
    }

    ret = ecmp_write_pbm_protection(&prot_p, prot_buf, crypto, state,
                                    request->pbm_secret, protected_part,
                                    total_len);
    if (ret < 0) {
        goto cleanup;
    }
    prot_len = (size_t) ret;
    prot_der = prot_buf + sizeof(prot_buf) - prot_len;

    total_len = 0;
    ret = 0;
    MBEDTLS_ASN1_CHK_ADD(total_len, mbedtls_asn1_write_raw_buffer(&p, buf, prot_der, prot_len));
    MBEDTLS_ASN1_CHK_ADD(total_len, mbedtls_asn1_write_raw_buffer(&p, buf, body_der, body_len));
    MBEDTLS_ASN1_CHK_ADD(total_len, mbedtls_asn1_write_raw_buffer(&p, buf, header_der, header_len));
    MBEDTLS_ASN1_CHK_ADD(total_len, mbedtls_asn1_write_len(&p, buf, total_len));
    MBEDTLS_ASN1_CHK_ADD(total_len, mbedtls_asn1_write_tag(&p, buf,
                                                           MBEDTLS_ASN1_CONSTRUCTED |
                                                           MBEDTLS_ASN1_SEQUENCE));

    ret = ecmp_copy_and_wrap_output(buf, p, out, out_len);

cleanup:
    ecmp_buf_free(&new_sender_der);
    ecmp_buf_free(&new_recipient_der);
    ecmp_buf_free(&new_sender_kid);
    free(protected_part);
    free(buf);
    return ret;
}

static int ecmp_expect_tag(ecmp_der_view *view, size_t *len, int tag)
{
    int ret;
    unsigned char *p;

    p = (unsigned char *) view->p;
    ret = mbedtls_asn1_get_tag(&p, view->end, len, tag);
    if (ret != 0) {
        return ECMP_ERR_ASN1;
    }
    view->p = p;
    return 0;
}

static int ecmp_get_int(ecmp_der_view *view, int *value)
{
    int ret;
    unsigned char *p;

    if (view == NULL || value == NULL) {
        return ECMP_ERR_PARAM;
    }

    p = (unsigned char *) view->p;
    ret = mbedtls_asn1_get_int(&p, view->end, value);
    if (ret != 0) {
        return ECMP_ERR_ASN1;
    }
    view->p = p;
    return 0;
}

static int ecmp_parse_algorithm_identifier(ecmp_der_view *view,
                                           mbedtls_asn1_buf *alg_oid,
                                           mbedtls_asn1_buf *params)
{
    ecmp_der_view seq;
    size_t len;
    const unsigned char *param_start;

    if (ecmp_expect_tag(view, &len,
                        MBEDTLS_ASN1_CONSTRUCTED | MBEDTLS_ASN1_SEQUENCE) != 0) {
        return ECMP_ERR_ASN1;
    }

    seq.p = view->p;
    seq.end = view->p + len;
    view->p = seq.end;

    if (ecmp_expect_tag(&seq, &len, MBEDTLS_ASN1_OID) != 0) {
        return ECMP_ERR_ASN1;
    }
    alg_oid->tag = MBEDTLS_ASN1_OID;
    alg_oid->p = (unsigned char *) seq.p;
    alg_oid->len = len;
    seq.p += len;

    params->tag = 0;
    params->p = NULL;
    params->len = 0;
    if (seq.p < seq.end) {
        param_start = seq.p;
        if (ecmp_skip_tlv(&seq) != 0) {
            return ECMP_ERR_ASN1;
        }
        params->tag = param_start[0];
        params->p = (unsigned char *) param_start;
        params->len = (size_t) (seq.p - param_start);
    }

    return 0;
}

static int ecmp_skip_tlv(ecmp_der_view *view)
{
    size_t len;
    int ret;
    unsigned char *p;
    int tag;

    if (view == NULL || view->p >= view->end) {
        return ECMP_ERR_ASN1;
    }

    p = (unsigned char *) view->p;
    tag = p[0];
    ret = mbedtls_asn1_get_tag(&p, view->end, &len, tag);
    if (ret != 0) {
        return ECMP_ERR_ASN1;
    }
    view->p = p + len;
    return 0;
}

static int ecmp_parse_directory_name(ecmp_der_view *view, ecmp_buf *name_der)
{
    ecmp_der_view field;
    size_t len;

    if (view == NULL || name_der == NULL) {
        return ECMP_ERR_PARAM;
    }

    field = *view;
    if (ecmp_expect_tag(&field, &len,
                        MBEDTLS_ASN1_CONTEXT_SPECIFIC |
                        MBEDTLS_ASN1_CONSTRUCTED | 4) != 0) {
        return ecmp_skip_tlv(view);
    }

    if (ecmp_buf_dup(name_der, field.p, len) != 0) {
        return ECMP_ERR_ALLOC;
    }
    view->p = field.p + len;
    return 0;
}

static int ecmp_parse_pbm_params(const unsigned char *params, size_t params_len,
                                 ecmp_pbm_params *pbm)
{
    ecmp_der_view view = { params, params + params_len };
    ecmp_der_view seq;
    mbedtls_asn1_buf alg_oid;
    mbedtls_asn1_buf alg_params;
    mbedtls_md_type_t md_type;
    size_t len;
    int iter_count;
    int ret;

    ret = ecmp_expect_tag(&view, &len,
                          MBEDTLS_ASN1_CONSTRUCTED | MBEDTLS_ASN1_SEQUENCE);
    if (ret != 0) {
        return ret;
    }
    seq.p = view.p;
    seq.end = view.p + len;
    view.p = seq.end;

    ret = ecmp_expect_tag(&seq, &len, MBEDTLS_ASN1_OCTET_STRING);
    if (ret != 0) {
        return ret;
    }
    ret = ecmp_buf_dup(&pbm->salt, seq.p, len);
    if (ret != 0) {
        return ret;
    }
    seq.p += len;

    ret = ecmp_parse_algorithm_identifier(&seq, &alg_oid, &alg_params);
    if (ret != 0) {
        return ret;
    }
    if (mbedtls_oid_get_md_alg(&alg_oid, &md_type) != 0) {
        fprintf(stderr, "ecmp: unsupported PBM owf OID\n");
        return ECMP_ERR_UNSUPPORTED;
    }
    ret = ecmp_hash_alg_from_md(md_type, &pbm->owf);
    if (ret != 0) {
        return ret;
    }

    iter_count = 0;
    if (ecmp_get_int(&seq, &iter_count) != 0) {
        return ECMP_ERR_ASN1;
    }
    pbm->iteration_count = iter_count;

    ret = ecmp_parse_algorithm_identifier(&seq, &alg_oid, &alg_params);
    if (ret != 0) {
        return ret;
    }
    if (alg_oid.len == sizeof(ECMP_RFC4210_HMAC_SHA1_OID) - 1 &&
        memcmp(alg_oid.p, ECMP_RFC4210_HMAC_SHA1_OID, alg_oid.len) == 0) {
        fprintf(stderr, "ecmp: PBM HMAC-SHA1 currently unsupported\n");
        return ECMP_ERR_UNSUPPORTED;
    }
    if (mbedtls_oid_get_md_hmac(&alg_oid, &md_type) != 0) {
        fprintf(stderr, "ecmp: unsupported PBM mac OID\n");
        return ECMP_ERR_UNSUPPORTED;
    }
    ret = ecmp_hash_alg_from_md(md_type, &pbm->mac);
    if (ret != 0) {
        return ret;
    }

    return 0;
}

static int ecmp_parse_status_info(ecmp_der_view *view, int *status,
                                  unsigned int *fail_info, char *status_text,
                                  size_t status_text_len)
{
    ecmp_der_view seq;
    ecmp_der_view text_seq;
    size_t len;
    int status_value;

    if (ecmp_expect_tag(view, &len,
                        MBEDTLS_ASN1_CONSTRUCTED | MBEDTLS_ASN1_SEQUENCE) != 0) {
        return ECMP_ERR_ASN1;
    }
    seq.p = view->p;
    seq.end = view->p + len;
    view->p = seq.end;

    if (ecmp_get_int(&seq, &status_value) != 0) {
        return ECMP_ERR_ASN1;
    }
    *status = status_value;

    if (seq.p < seq.end && *seq.p ==
        (MBEDTLS_ASN1_CONSTRUCTED | MBEDTLS_ASN1_SEQUENCE)) {
        if (ecmp_expect_tag(&seq, &len,
                            MBEDTLS_ASN1_CONSTRUCTED | MBEDTLS_ASN1_SEQUENCE) != 0) {
            return ECMP_ERR_ASN1;
        }
        text_seq.p = seq.p;
        text_seq.end = seq.p + len;
        seq.p = text_seq.end;
        if (text_seq.p < text_seq.end) {
            size_t string_len;
            int tag = *text_seq.p;
            if (tag != MBEDTLS_ASN1_UTF8_STRING &&
                tag != MBEDTLS_ASN1_BMP_STRING &&
                tag != MBEDTLS_ASN1_PRINTABLE_STRING) {
                return ECMP_ERR_ASN1;
            }
            if (ecmp_expect_tag(&text_seq, &string_len, tag) != 0) {
                return ECMP_ERR_ASN1;
            }
            if (string_len >= status_text_len) {
                string_len = status_text_len - 1;
            }
            memcpy(status_text, text_seq.p, string_len);
            status_text[string_len] = '\0';
        }
    }

    if (seq.p < seq.end) {
        size_t bit_len;
        unsigned int bits = 0;

        if (ecmp_expect_tag(&seq, &bit_len, MBEDTLS_ASN1_BIT_STRING) != 0) {
            return ECMP_ERR_ASN1;
        }
        if (bit_len > 1) {
            size_t i;
            const unsigned char *bit_ptr = seq.p + 1;
            size_t octets = bit_len - 1;
            for (i = 0; i < octets && i < sizeof(unsigned int); ++i) {
                bits = (bits << 8) | bit_ptr[i];
            }
        }
        *fail_info = bits;
    }

    return 0;
}

static int ecmp_parse_free_text(ecmp_der_view *view, char *text, size_t text_len)
{
    ecmp_der_view seq;
    size_t len;
    int tag;

    if (view == NULL || text == NULL || text_len == 0) {
        return ECMP_ERR_PARAM;
    }

    if (ecmp_expect_tag(view, &len,
                        MBEDTLS_ASN1_CONSTRUCTED | MBEDTLS_ASN1_SEQUENCE) != 0) {
        return ECMP_ERR_ASN1;
    }
    seq.p = view->p;
    seq.end = view->p + len;
    view->p = seq.end;

    if (seq.p >= seq.end) {
        text[0] = '\0';
        return 0;
    }

    tag = *seq.p;
    if (tag != MBEDTLS_ASN1_UTF8_STRING &&
        tag != MBEDTLS_ASN1_BMP_STRING &&
        tag != MBEDTLS_ASN1_PRINTABLE_STRING) {
        return ECMP_ERR_ASN1;
    }
    if (ecmp_expect_tag(&seq, &len, tag) != 0) {
        return ECMP_ERR_ASN1;
    }
    if (len >= text_len) {
        len = text_len - 1;
    }
    memcpy(text, seq.p, len);
    text[len] = '\0';
    return 0;
}

static int ecmp_parse_general_info(ecmp_der_view *view, int *implicit_confirm)
{
    ecmp_der_view outer;
    ecmp_der_view seq_item;
    ecmp_der_view item;
    size_t len;
    mbedtls_asn1_buf oid;

    if (ecmp_expect_tag(view, &len,
                        MBEDTLS_ASN1_CONTEXT_SPECIFIC |
                        MBEDTLS_ASN1_CONSTRUCTED | 8) != 0) {
        return ECMP_ERR_ASN1;
    }

    outer.p = view->p;
    outer.end = view->p + len;
    view->p = outer.end;

    if (ecmp_expect_tag(&outer, &len,
                        MBEDTLS_ASN1_CONSTRUCTED | MBEDTLS_ASN1_SEQUENCE) != 0) {
        return ECMP_ERR_ASN1;
    }
    seq_item.p = outer.p;
    seq_item.end = outer.p + len;

    while (seq_item.p < seq_item.end) {
        if (ecmp_expect_tag(&seq_item, &len,
                            MBEDTLS_ASN1_CONSTRUCTED | MBEDTLS_ASN1_SEQUENCE) != 0) {
            return ECMP_ERR_ASN1;
        }
        item.p = seq_item.p;
        item.end = seq_item.p + len;
        seq_item.p = item.end;

        if (ecmp_expect_tag(&item, &len, MBEDTLS_ASN1_OID) != 0) {
            return ECMP_ERR_ASN1;
        }
        oid.tag = MBEDTLS_ASN1_OID;
        oid.p = (unsigned char *) item.p;
        oid.len = len;
        item.p += len;

        if (oid.len == sizeof(ECMP_IMPLICIT_CONFIRM_OID) - 1 &&
            memcmp(oid.p, ECMP_IMPLICIT_CONFIRM_OID, oid.len) == 0) {
            *implicit_confirm = 1;
        }

        if (item.p < item.end && ecmp_skip_tlv(&item) != 0) {
            return ECMP_ERR_ASN1;
        }
    }

    return 0;
}

static int ecmp_parse_pkiheader(const unsigned char **p, const unsigned char *end,
                                ecmp_message_state *parsed,
                                const ecmp_message_state *expected_request)
{
    ecmp_der_view view;
    ecmp_der_view seq;
    mbedtls_asn1_buf alg_oid;
    mbedtls_asn1_buf alg_params;
    size_t len;
    int pvno;
    int ret;

    view.p = *p;
    view.end = end;
    ret = ecmp_expect_tag(&view, &len,
                          MBEDTLS_ASN1_CONSTRUCTED | MBEDTLS_ASN1_SEQUENCE);
    if (ret != 0) {
        return ret;
    }
    seq.p = view.p;
    seq.end = view.p + len;
    *p = seq.end;

    if (ecmp_get_int(&seq, &pvno) != 0) {
        return ECMP_ERR_ASN1;
    }
    parsed->pvno = pvno;

    if (ecmp_parse_directory_name(&seq, &parsed->sender_der) != 0) {
        return ECMP_ERR_ASN1;
    }
    if (ecmp_parse_directory_name(&seq, &parsed->recipient_der) != 0) {
        return ECMP_ERR_ASN1;
    }

    while (seq.p < seq.end) {
        int tag_no = seq.p[0] & 0x1F;
        if ((seq.p[0] & MBEDTLS_ASN1_CONTEXT_SPECIFIC) == 0) {
            break;
        }

        switch (tag_no) {
            case 1:
                if (ecmp_expect_tag(&seq, &len,
                                    MBEDTLS_ASN1_CONTEXT_SPECIFIC |
                                    MBEDTLS_ASN1_CONSTRUCTED | 1) != 0) {
                    return ECMP_ERR_ASN1;
                }
                {
                    ecmp_der_view alg_view = { seq.p, seq.p + len };
                    if (ecmp_parse_algorithm_identifier(&alg_view, &alg_oid,
                                                        &alg_params) != 0) {
                        return ECMP_ERR_ASN1;
                    }
                    if (ecmp_buf_dup(&parsed->protection_alg_oid, alg_oid.p,
                                     alg_oid.len) != 0) {
                        return ECMP_ERR_ALLOC;
                    }
                    if (alg_oid.len == sizeof(ECMP_PBM_OID) - 1 &&
                        memcmp(alg_oid.p, ECMP_PBM_OID, alg_oid.len) == 0) {
                        parsed->protection_is_pbm = 1;
                        if (ecmp_parse_pbm_params(alg_params.p, alg_params.len,
                                                  &parsed->pbm) != 0) {
                            return ECMP_ERR_UNSUPPORTED;
                        }
                    } else {
                        parsed->protection_is_pbm = 0;
                    }
                }
                seq.p += len;
                break;
            case 2:
                if (ecmp_expect_tag(&seq, &len,
                                    MBEDTLS_ASN1_CONTEXT_SPECIFIC |
                                    MBEDTLS_ASN1_CONSTRUCTED | 2) != 0) {
                    return ECMP_ERR_ASN1;
                }
                {
                    const unsigned char *field_end = seq.p + len;
                    ecmp_der_view kid = { seq.p, seq.p + len };
                    if (ecmp_expect_tag(&kid, &len, MBEDTLS_ASN1_OCTET_STRING) != 0) {
                        return ECMP_ERR_ASN1;
                    }
                    if (ecmp_buf_dup(&parsed->sender_kid, kid.p, len) != 0) {
                        return ECMP_ERR_ALLOC;
                    }
                    seq.p = field_end;
                }
                break;
            case 4:
                if (ecmp_expect_tag(&seq, &len,
                                    MBEDTLS_ASN1_CONTEXT_SPECIFIC |
                                    MBEDTLS_ASN1_CONSTRUCTED | 4) != 0) {
                    return ECMP_ERR_ASN1;
                }
                {
                    const unsigned char *field_end = seq.p + len;
                    ecmp_der_view field = { seq.p, seq.p + len };
                    if (ecmp_expect_tag(&field, &len, MBEDTLS_ASN1_OCTET_STRING) != 0) {
                        return ECMP_ERR_ASN1;
                    }
                    if (expected_request != NULL) {
                        if (expected_request->transaction_id.len != len ||
                            memcmp(expected_request->transaction_id.data, field.p, len) != 0) {
                            return ECMP_ERR_PROTOCOL;
                        }
                    }
                    if (ecmp_buf_dup(&parsed->transaction_id, field.p, len) != 0) {
                        return ECMP_ERR_ALLOC;
                    }
                    seq.p = field_end;
                }
                break;
            case 5:
                if (ecmp_expect_tag(&seq, &len,
                                    MBEDTLS_ASN1_CONTEXT_SPECIFIC |
                                    MBEDTLS_ASN1_CONSTRUCTED | 5) != 0) {
                    return ECMP_ERR_ASN1;
                }
                {
                    const unsigned char *field_end = seq.p + len;
                    ecmp_der_view field = { seq.p, seq.p + len };
                    if (ecmp_expect_tag(&field, &len, MBEDTLS_ASN1_OCTET_STRING) != 0) {
                        return ECMP_ERR_ASN1;
                    }
                    if (ecmp_buf_dup(&parsed->recip_nonce, field.p, len) != 0) {
                        return ECMP_ERR_ALLOC;
                    }
                    seq.p = field_end;
                }
                break;
            case 6:
                if (ecmp_expect_tag(&seq, &len,
                                    MBEDTLS_ASN1_CONTEXT_SPECIFIC |
                                    MBEDTLS_ASN1_CONSTRUCTED | 6) != 0) {
                    return ECMP_ERR_ASN1;
                }
                {
                    const unsigned char *field_end = seq.p + len;
                    ecmp_der_view field = { seq.p, seq.p + len };
                    if (ecmp_expect_tag(&field, &len, MBEDTLS_ASN1_OCTET_STRING) != 0) {
                        return ECMP_ERR_ASN1;
                    }
                    if (expected_request != NULL) {
                        if (expected_request->sender_nonce.len != len ||
                            memcmp(expected_request->sender_nonce.data, field.p, len) != 0) {
                            return ECMP_ERR_PROTOCOL;
                        }
                    }
                    if (ecmp_buf_dup(&parsed->sender_nonce, field.p, len) != 0) {
                        return ECMP_ERR_ALLOC;
                    }
                    seq.p = field_end;
                }
                break;
            case 8:
                if (ecmp_parse_general_info(&seq, &parsed->implicit_confirm_granted) != 0) {
                    return ECMP_ERR_ASN1;
                }
                break;
            default:
                if (ecmp_expect_tag(&seq, &len, seq.p[0]) != 0) {
                    return ECMP_ERR_ASN1;
                }
                seq.p += len;
                break;
        }
    }

    return 0;
}

static int ecmp_verify_signature_protection(const ecmp_crypto_provider *crypto,
                                            const ecmp_message_state *parsed,
                                            const unsigned char *protected_part,
                                            size_t protected_part_len)
{
    ecmp_der_view certs;
    size_t certs_len;
    int saw_candidate = 0;
    int saw_kid_match = 0;

    if (crypto == NULL || parsed == NULL || protected_part == NULL) {
        return ECMP_ERR_PARAM;
    }
    if (crypto->verify_signature_from_cert == NULL) {
        return ECMP_ERR_PARAM;
    }
    if (parsed->protection_alg_oid.data == NULL || parsed->protection_alg_oid.len == 0 ||
        parsed->protection.data == NULL || parsed->protection.len == 0) {
        return ECMP_ERR_PROTOCOL;
    }
    if (parsed->extra_certs_der.data == NULL || parsed->extra_certs_der.len == 0) {
        fprintf(stderr, "ecmp: signed response has no extraCerts signer chain\n");
        return ECMP_ERR_PROTOCOL;
    }

    certs.p = parsed->extra_certs_der.data;
    certs.end = parsed->extra_certs_der.data + parsed->extra_certs_der.len;
    if (ecmp_expect_tag(&certs, &certs_len,
                        MBEDTLS_ASN1_CONSTRUCTED | MBEDTLS_ASN1_SEQUENCE) != 0) {
        return ECMP_ERR_ASN1;
    }
    certs.end = certs.p + certs_len;

    while (certs.p < certs.end) {
        const unsigned char *cert_start = certs.p;
        size_t cert_len;
        int match = 1;
        int verified = 0;
        int ret;

        if (ecmp_expect_tag(&certs, &cert_len,
                            MBEDTLS_ASN1_CONSTRUCTED | MBEDTLS_ASN1_SEQUENCE) != 0) {
            return ECMP_ERR_ASN1;
        }

        if (parsed->sender_kid.data != NULL && parsed->sender_kid.len > 0) {
            if (crypto->certificate_matches_subject_key_id == NULL) {
                return ECMP_ERR_PARAM;
            }
            ret = crypto->certificate_matches_subject_key_id(
                crypto->ctx, cert_start, (size_t) (certs.p + cert_len - cert_start),
                parsed->sender_kid.data, parsed->sender_kid.len, &match);
            if (ret != 0) {
                return ECMP_ERR_CRYPTO;
            }
            if (!match) {
                certs.p += cert_len;
                continue;
            }
            saw_kid_match = 1;
        }

        saw_candidate = 1;
        ret = crypto->verify_signature_from_cert(
            crypto->ctx, cert_start, (size_t) (certs.p + cert_len - cert_start),
            parsed->protection_alg_oid.data, parsed->protection_alg_oid.len,
            protected_part, protected_part_len,
            parsed->protection.data, parsed->protection.len, &verified);
        if (ret != 0) {
            return ECMP_ERR_CRYPTO;
        }
        if (verified) {
            fprintf(stderr, "ecmp: response signature verified\n");
            certs.p += cert_len;
            return 0;
        }

        certs.p += cert_len;
    }

    if (parsed->sender_kid.data != NULL && parsed->sender_kid.len > 0 && !saw_kid_match) {
        fprintf(stderr, "ecmp: no signer in extraCerts matched senderKID\n");
        return ECMP_ERR_PROTOCOL;
    }
    if (!saw_candidate) {
        fprintf(stderr, "ecmp: signed response had no candidate signer certificate\n");
        return ECMP_ERR_PROTOCOL;
    }

    fprintf(stderr, "ecmp: response signature mismatch\n");
    return ECMP_ERR_PROTOCOL;
}

static int ecmp_parse_certified_key_pair(ecmp_der_view *view,
                                         ecmp_message_state *parsed)
{
    ecmp_der_view pair;
    ecmp_der_view cert_choice;
    ecmp_der_view cert_view;
    size_t len;
    const unsigned char *cert_start;

    if (ecmp_expect_tag(view, &len,
                        MBEDTLS_ASN1_CONSTRUCTED | MBEDTLS_ASN1_SEQUENCE) != 0) {
        return ECMP_ERR_ASN1;
    }
    pair.p = view->p;
    pair.end = view->p + len;
    view->p = pair.end;

    if (ecmp_expect_tag(&pair, &len,
                        MBEDTLS_ASN1_CONTEXT_SPECIFIC |
                        MBEDTLS_ASN1_CONSTRUCTED | 0) != 0) {
        return ECMP_ERR_ASN1;
    }
    cert_choice.p = pair.p;
    cert_choice.end = pair.p + len;
    pair.p = cert_choice.end;

    cert_start = cert_choice.p;
    if (ecmp_expect_tag(&cert_choice, &len,
                        MBEDTLS_ASN1_CONSTRUCTED | MBEDTLS_ASN1_SEQUENCE) != 0) {
        return ECMP_ERR_ASN1;
    }
    cert_view.p = cert_choice.p;
    cert_view.end = cert_choice.p + len;

    return ecmp_buf_dup(&parsed->issued_cert_der, cert_start,
                        (size_t) (cert_view.end - cert_start));
}

static int ecmp_parse_ip_body(ecmp_der_view *body_view, ecmp_message_state *parsed)
{
    ecmp_der_view ip_seq;
    ecmp_der_view responses;
    ecmp_der_view response;
    size_t len;
    int cert_req_id;
    int ret;

    if (ecmp_expect_tag(body_view, &len,
                        MBEDTLS_ASN1_CONTEXT_SPECIFIC |
                        MBEDTLS_ASN1_CONSTRUCTED | ECMP_CMP_BODY_IP) != 0) {
        return ECMP_ERR_ASN1;
    }
    ip_seq.p = body_view->p;
    ip_seq.end = body_view->p + len;
    body_view->p = ip_seq.end;

    if (ecmp_expect_tag(&ip_seq, &len,
                        MBEDTLS_ASN1_CONSTRUCTED | MBEDTLS_ASN1_SEQUENCE) != 0) {
        return ECMP_ERR_ASN1;
    }
    responses.p = ip_seq.p;
    responses.end = ip_seq.p + len;
    ip_seq.p = responses.end;

    if (responses.p < responses.end &&
        *responses.p == (MBEDTLS_ASN1_CONTEXT_SPECIFIC |
                         MBEDTLS_ASN1_CONSTRUCTED | 1)) {
        if (ecmp_expect_tag(&responses, &len,
                            MBEDTLS_ASN1_CONTEXT_SPECIFIC |
                            MBEDTLS_ASN1_CONSTRUCTED | 1) != 0) {
            return ECMP_ERR_ASN1;
        }
        responses.p += len;
    }

    if (ecmp_expect_tag(&responses, &len,
                        MBEDTLS_ASN1_CONSTRUCTED | MBEDTLS_ASN1_SEQUENCE) != 0) {
        return ECMP_ERR_ASN1;
    }
    response.p = responses.p;
    response.end = responses.p + len;

    if (ecmp_expect_tag(&response, &len,
                        MBEDTLS_ASN1_CONSTRUCTED | MBEDTLS_ASN1_SEQUENCE) != 0) {
        return ECMP_ERR_ASN1;
    }
    responses.p = response.p;
    responses.end = response.p + len;

    if (ecmp_get_int(&responses, &cert_req_id) != 0 || cert_req_id != 0) {
        return ECMP_ERR_PROTOCOL;
    }
    ret = ecmp_parse_status_info(&responses, &parsed->status, &parsed->fail_info,
                                 parsed->status_text, sizeof(parsed->status_text));
    if (ret != 0) {
        return ret;
    }
    if (parsed->status == 0 || parsed->status == 1) {
        if (ecmp_parse_certified_key_pair(&responses, parsed) != 0) {
            return ECMP_ERR_ASN1;
        }
    }

    return 0;
}

static int ecmp_parse_error_body(ecmp_der_view *body_view, ecmp_message_state *parsed)
{
    ecmp_der_view err_seq;
    ecmp_der_view err_content;
    size_t len;
    int error_code;
    int ret;

    if (ecmp_expect_tag(body_view, &len,
                        MBEDTLS_ASN1_CONTEXT_SPECIFIC |
                        MBEDTLS_ASN1_CONSTRUCTED | ECMP_CMP_BODY_ERROR) != 0) {
        return ECMP_ERR_ASN1;
    }
    err_seq.p = body_view->p;
    err_seq.end = body_view->p + len;
    body_view->p = err_seq.end;

    if (ecmp_expect_tag(&err_seq, &len,
                        MBEDTLS_ASN1_CONSTRUCTED | MBEDTLS_ASN1_SEQUENCE) != 0) {
        return ECMP_ERR_ASN1;
    }
    err_content.p = err_seq.p;
    err_content.end = err_seq.p + len;

    ret = ecmp_parse_status_info(&err_content, &parsed->status, &parsed->fail_info,
                                 parsed->status_text, sizeof(parsed->status_text));
    if (ret != 0) {
        return ret;
    }

    if (err_content.p < err_content.end && *err_content.p == MBEDTLS_ASN1_INTEGER) {
        ret = ecmp_get_int(&err_content, &error_code);
        if (ret != 0) {
            return ret;
        }
        (void) error_code;
    }

    if (err_content.p < err_content.end &&
        *err_content.p == (MBEDTLS_ASN1_CONSTRUCTED | MBEDTLS_ASN1_SEQUENCE)) {
        char detail[sizeof(parsed->status_text)];

        detail[0] = '\0';
        ret = ecmp_parse_free_text(&err_content, detail, sizeof(detail));
        if (ret != 0) {
            return ret;
        }
        if (detail[0] != '\0') {
            if (parsed->status_text[0] == '\0') {
                memcpy(parsed->status_text, detail, strlen(detail) + 1);
            } else {
                size_t used = strlen(parsed->status_text);
                size_t remaining = sizeof(parsed->status_text) - used - 1;
                if (remaining > 3) {
                    size_t copy_len;

                    memcpy(parsed->status_text + used, " | ", 3);
                    used += 3;
                    remaining -= 3;
                    copy_len = strlen(detail);
                    if (copy_len > remaining) {
                        copy_len = remaining;
                    }
                    memcpy(parsed->status_text + used, detail, copy_len);
                    parsed->status_text[used + copy_len] = '\0';
                }
            }
        }
    }

    return 0;
}

static int ecmp_parse_pkiconf_body(ecmp_der_view *body_view)
{
    size_t len;
    ecmp_der_view conf;

    if (ecmp_expect_tag(body_view, &len,
                        MBEDTLS_ASN1_CONTEXT_SPECIFIC |
                        MBEDTLS_ASN1_CONSTRUCTED | ECMP_CMP_BODY_PKICONF) != 0) {
        return ECMP_ERR_ASN1;
    }
    conf.p = body_view->p;
    conf.end = body_view->p + len;
    body_view->p = conf.end;
    if (ecmp_expect_tag(&conf, &len, MBEDTLS_ASN1_NULL) != 0) {
        return ECMP_ERR_ASN1;
    }
    return 0;
}

int ecmp_cmp_parse_message(const ecmp_crypto_provider *crypto,
                           const unsigned char *message, size_t message_len,
                           const char *pbm_secret,
                           const ecmp_message_state *expected_request,
                           ecmp_message_state *parsed)
{
    ecmp_der_view view;
    ecmp_der_view body_view;
    unsigned char *computed = NULL;
    unsigned char *protected_part = NULL;
    size_t computed_len = 0;
    const unsigned char *protected_part_start;
    const unsigned char *protection_wrapper;
    const unsigned char *message_end;
    size_t top_len;
    size_t protection_len;
    size_t bit_string_len;
    int ret;
    int body_tag;

    if (crypto == NULL || message == NULL || parsed == NULL) {
        return ECMP_ERR_PARAM;
    }

    memset(parsed, 0, sizeof(*parsed));
    view.p = message;
    view.end = message + message_len;
    message_end = view.end;

    ret = ecmp_expect_tag(&view, &top_len,
                          MBEDTLS_ASN1_CONSTRUCTED | MBEDTLS_ASN1_SEQUENCE);
    if (ret != 0) {
        return ret;
    }
    if ((size_t) (view.end - view.p) < top_len) {
        return ECMP_ERR_ASN1;
    }

    protected_part_start = view.p;
    ret = ecmp_parse_pkiheader(&view.p, view.end, parsed, expected_request);
    if (ret != 0) {
        goto cleanup;
    }

    body_view.p = view.p;
    body_view.end = view.end;
    body_tag = body_view.p[0] & 0x1F;
    parsed->body_type = body_tag;
    if (body_tag == ECMP_CMP_BODY_IP) {
        ret = ecmp_parse_ip_body(&body_view, parsed);
    } else if (body_tag == ECMP_CMP_BODY_ERROR) {
        ret = ecmp_parse_error_body(&body_view, parsed);
    } else if (body_tag == ECMP_CMP_BODY_PKICONF) {
        ret = ecmp_parse_pkiconf_body(&body_view);
    } else {
        ret = ECMP_ERR_UNSUPPORTED;
    }
    if (ret != 0) {
        goto cleanup;
    }
    view.p = body_view.p;

    protection_wrapper = view.p;
    ret = ecmp_expect_tag(&view, &protection_len,
                          MBEDTLS_ASN1_CONTEXT_SPECIFIC |
                          MBEDTLS_ASN1_CONSTRUCTED | 0);
    if (ret != 0) {
        goto cleanup;
    }
    {
        ecmp_der_view prot_view = { view.p, view.p + protection_len };
        if (ecmp_expect_tag(&prot_view, &bit_string_len, MBEDTLS_ASN1_BIT_STRING) != 0) {
            ret = ECMP_ERR_ASN1;
            goto cleanup;
        }
        if (bit_string_len < 1 || *prot_view.p != 0) {
            ret = ECMP_ERR_PROTOCOL;
            goto cleanup;
        }
        ret = ecmp_buf_dup(&parsed->protection, prot_view.p + 1, bit_string_len - 1);
        if (ret != 0) {
            goto cleanup;
        }
    }
    view.p += protection_len;

    if (view.p < message_end) {
        size_t extra_len;
        ecmp_der_view extra_view = { view.p, message_end };
        if ((extra_view.p[0] & 0x1F) == 1 &&
            ecmp_expect_tag(&extra_view, &extra_len,
                            MBEDTLS_ASN1_CONTEXT_SPECIFIC |
                            MBEDTLS_ASN1_CONSTRUCTED | 1) == 0) {
            const unsigned char *seq_start = extra_view.p;
            size_t seq_len;
            if (ecmp_expect_tag(&extra_view, &seq_len,
                                MBEDTLS_ASN1_CONSTRUCTED |
                                MBEDTLS_ASN1_SEQUENCE) == 0) {
                ret = ecmp_buf_dup(&parsed->extra_certs_der, seq_start,
                                   (size_t) ((extra_view.p + seq_len) - seq_start));
                if (ret != 0) {
                    goto cleanup;
                }
            }
        }
    }

    ret = ecmp_build_protected_part(protected_part_start,
                                    (size_t) (body_view.p - protected_part_start),
                                    protection_wrapper, (size_t) 0,
                                    &protected_part, &computed_len);
    if (ret != 0) {
        goto cleanup;
    }

    if (parsed->protection_is_pbm) {
        if (pbm_secret == NULL) {
            ret = ECMP_ERR_PARAM;
            goto cleanup;
        }
        ret = ecmp_compute_pbm(crypto, &parsed->pbm, pbm_secret,
                               protected_part, computed_len,
                               &computed, &computed_len);
        if (ret != 0) {
            fprintf(stderr, "ecmp: response PBM compute failed (%d)\n", ret);
            goto cleanup;
        }
        if (computed_len != parsed->protection.len ||
            memcmp(computed, parsed->protection.data, computed_len) != 0) {
            ret = ECMP_ERR_PROTOCOL;
            fprintf(stderr, "ecmp: response PBM mismatch\n");
            goto cleanup;
        }
        fprintf(stderr, "ecmp: response PBM verified\n");
    } else {
        ret = ecmp_verify_signature_protection(crypto, parsed,
                                               protected_part, computed_len);
        if (ret != 0) {
            goto cleanup;
        }
    }

    ret = 0;

cleanup:
    free(computed);
    free(protected_part);
    if (ret != 0) {
        ecmp_message_state_free(parsed);
    }
    return ret;
}
