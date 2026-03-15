#include "ecmp/ecmp_crypto.h"
#include "ecmp/ecmp_error.h"

#include <stdlib.h>
#include <string.h>

#include "mbedtls/asn1.h"
#include "mbedtls/asn1write.h"
#include "mbedtls/build_info.h"
#include "mbedtls/ctr_drbg.h"
#include "mbedtls/entropy.h"
#include "mbedtls/error.h"
#include "mbedtls/md.h"
#include "mbedtls/oid.h"
#include "mbedtls/pem.h"
#include "mbedtls/pk.h"
#include "mbedtls/platform.h"
#include "mbedtls/x509.h"
#include "mbedtls/x509_crt.h"

int mbedtls_x509_write_names(unsigned char **p, unsigned char *start,
                             mbedtls_asn1_named_data *first);

struct ecmp_key {
    mbedtls_pk_context pk;
};

typedef struct ecmp_mbedtls_ctx {
    mbedtls_entropy_context entropy;
    mbedtls_ctr_drbg_context ctr_drbg;
} ecmp_mbedtls_ctx;

static int ecmp_mbedtls_md_info(ecmp_hash_alg alg,
                                const mbedtls_md_info_t **md_info)
{
    mbedtls_md_type_t md_type;

    if (md_info == NULL) {
        return ECMP_ERR_PARAM;
    }

    switch (alg) {
        case ECMP_HASH_SHA256:
            md_type = MBEDTLS_MD_SHA256;
            break;
        case ECMP_HASH_SHA384:
            md_type = MBEDTLS_MD_SHA384;
            break;
        case ECMP_HASH_SHA512:
            md_type = MBEDTLS_MD_SHA512;
            break;
        default:
            return ECMP_ERR_UNSUPPORTED;
    }

    *md_info = mbedtls_md_info_from_type(md_type);
    return *md_info == NULL ? ECMP_ERR_UNSUPPORTED : 0;
}

static void ecmp_mbedtls_free_ctx(void *ctx)
{
    ecmp_mbedtls_ctx *mbedtls_ctx = (ecmp_mbedtls_ctx *) ctx;

    if (mbedtls_ctx == NULL) {
        return;
    }

    mbedtls_ctr_drbg_free(&mbedtls_ctx->ctr_drbg);
    mbedtls_entropy_free(&mbedtls_ctx->entropy);
    free(mbedtls_ctx);
}

static int ecmp_mbedtls_random_bytes(void *ctx, unsigned char *out, size_t out_len)
{
    ecmp_mbedtls_ctx *mbedtls_ctx = (ecmp_mbedtls_ctx *) ctx;
    return mbedtls_ctr_drbg_random(&mbedtls_ctx->ctr_drbg, out, out_len);
}

static int ecmp_mbedtls_generate_ec_key(void *ctx, const char *curve_name, ecmp_key **key)
{
    ecmp_mbedtls_ctx *mbedtls_ctx = (ecmp_mbedtls_ctx *) ctx;
    const mbedtls_ecp_curve_info *curve_info;
    ecmp_key *new_key;
    int ret;

    if (curve_name == NULL || key == NULL) {
        return ECMP_ERR_PARAM;
    }

    curve_info = mbedtls_ecp_curve_info_from_name(curve_name);
    if (curve_info == NULL) {
        return ECMP_ERR_UNSUPPORTED;
    }

    new_key = calloc(1, sizeof(*new_key));
    if (new_key == NULL) {
        return ECMP_ERR_ALLOC;
    }
    mbedtls_pk_init(&new_key->pk);

    ret = mbedtls_pk_setup(&new_key->pk, mbedtls_pk_info_from_type(MBEDTLS_PK_ECKEY));
    if (ret != 0) {
        mbedtls_pk_free(&new_key->pk);
        free(new_key);
        return ret;
    }

    ret = mbedtls_ecp_gen_key(curve_info->grp_id, mbedtls_pk_ec(new_key->pk),
                              mbedtls_ctr_drbg_random, &mbedtls_ctx->ctr_drbg);
    if (ret != 0) {
        mbedtls_pk_free(&new_key->pk);
        free(new_key);
        return ret;
    }

    *key = new_key;
    return 0;
}

static void ecmp_mbedtls_free_key(void *ctx, ecmp_key *key)
{
    (void) ctx;
    if (key == NULL) {
        return;
    }
    mbedtls_pk_free(&key->pk);
    free(key);
}

static int ecmp_mbedtls_name_to_der(void *ctx, const char *name,
                                    unsigned char **out, size_t *out_len)
{
    mbedtls_asn1_named_data *head = NULL;
    unsigned char buf[1024];
    unsigned char *p = buf + sizeof(buf);
    int ret;
    size_t len;
    (void) ctx;

    if (name == NULL || out == NULL || out_len == NULL) {
        return ECMP_ERR_PARAM;
    }

    ret = mbedtls_x509_string_to_names(&head, name);
    if (ret != 0) {
        return ret;
    }

    len = (size_t) mbedtls_x509_write_names(&p, buf, head);
    if ((int) len < 0) {
        mbedtls_asn1_free_named_data_list(&head);
        return (int) len;
    }

    *out = calloc(1, len);
    if (*out == NULL) {
        mbedtls_asn1_free_named_data_list(&head);
        return ECMP_ERR_ALLOC;
    }
    memcpy(*out, p, len);
    *out_len = len;
    mbedtls_asn1_free_named_data_list(&head);
    return 0;
}

static int ecmp_mbedtls_export_spki_der(void *ctx, const ecmp_key *key,
                                        unsigned char **out, size_t *out_len)
{
    unsigned char buf[1024];
    int len;
    (void) ctx;

    if (key == NULL || out == NULL || out_len == NULL) {
        return ECMP_ERR_PARAM;
    }

    len = mbedtls_pk_write_pubkey_der(&key->pk, buf, sizeof(buf));
    if (len < 0) {
        return len;
    }

    *out = calloc(1, (size_t) len);
    if (*out == NULL) {
        return ECMP_ERR_ALLOC;
    }
    memcpy(*out, buf + sizeof(buf) - len, (size_t) len);
    *out_len = (size_t) len;
    return 0;
}

static int ecmp_mbedtls_sign(void *ctx, const ecmp_key *key, ecmp_hash_alg hash_alg,
                             const unsigned char *input, size_t input_len,
                             unsigned char **sig, size_t *sig_len)
{
    ecmp_mbedtls_ctx *mbedtls_ctx = (ecmp_mbedtls_ctx *) ctx;
    const mbedtls_md_info_t *md_info;
    unsigned char hash[MBEDTLS_MD_MAX_SIZE];
    unsigned char *signature;
    size_t signature_len = 0;
    int ret;

    if (key == NULL || input == NULL || sig == NULL || sig_len == NULL) {
        return ECMP_ERR_PARAM;
    }
    if (ecmp_mbedtls_md_info(hash_alg, &md_info) != 0) {
        return ECMP_ERR_UNSUPPORTED;
    }

    ret = mbedtls_md(md_info, input, input_len, hash);
    if (ret != 0) {
        return ret;
    }

    signature = calloc(1, MBEDTLS_ECDSA_MAX_LEN);
    if (signature == NULL) {
        return ECMP_ERR_ALLOC;
    }

    ret = mbedtls_pk_sign((mbedtls_pk_context *) &key->pk,
                          mbedtls_md_get_type(md_info),
                          hash, mbedtls_md_get_size(md_info),
                          signature, MBEDTLS_ECDSA_MAX_LEN, &signature_len,
                          mbedtls_ctr_drbg_random, &mbedtls_ctx->ctr_drbg);
    if (ret != 0) {
        free(signature);
        return ret;
    }

    *sig = signature;
    *sig_len = signature_len;
    return 0;
}

static int ecmp_mbedtls_hash(void *ctx, ecmp_hash_alg hash_alg,
                             const unsigned char *input, size_t input_len,
                             unsigned char **digest, size_t *digest_len)
{
    const mbedtls_md_info_t *md_info;
    unsigned char *out;
    size_t out_len;
    int ret;
    (void) ctx;

    if (input == NULL || digest == NULL || digest_len == NULL) {
        return ECMP_ERR_PARAM;
    }
    if (ecmp_mbedtls_md_info(hash_alg, &md_info) != 0) {
        return ECMP_ERR_UNSUPPORTED;
    }

    out_len = mbedtls_md_get_size(md_info);
    out = calloc(1, out_len);
    if (out == NULL) {
        return ECMP_ERR_ALLOC;
    }

    ret = mbedtls_md(md_info, input, input_len, out);
    if (ret != 0) {
        free(out);
        return ret;
    }

    *digest = out;
    *digest_len = out_len;
    return 0;
}

static int ecmp_mbedtls_hmac(void *ctx, ecmp_hash_alg hash_alg,
                             const unsigned char *key, size_t key_len,
                             const unsigned char *input, size_t input_len,
                             unsigned char **mac, size_t *mac_len)
{
    const mbedtls_md_info_t *md_info;
    unsigned char *out;
    size_t out_len;
    int ret;
    (void) ctx;

    if (key == NULL || input == NULL || mac == NULL || mac_len == NULL) {
        return ECMP_ERR_PARAM;
    }
    if (ecmp_mbedtls_md_info(hash_alg, &md_info) != 0) {
        return ECMP_ERR_UNSUPPORTED;
    }

    out_len = mbedtls_md_get_size(md_info);
    out = calloc(1, out_len);
    if (out == NULL) {
        return ECMP_ERR_ALLOC;
    }

    ret = mbedtls_md_hmac(md_info, key, key_len, input, input_len, out);
    if (ret != 0) {
        free(out);
        return ret;
    }

    *mac = out;
    *mac_len = out_len;
    return 0;
}

static int ecmp_mbedtls_certificate_matches_subject_key_id(void *ctx,
                                                           const unsigned char *cert_der,
                                                           size_t cert_der_len,
                                                           const unsigned char *key_id,
                                                           size_t key_id_len,
                                                           int *match)
{
    mbedtls_x509_crt crt;
    int ret;
    (void) ctx;

    if (cert_der == NULL || key_id == NULL || match == NULL) {
        return ECMP_ERR_PARAM;
    }

    *match = 0;
    mbedtls_x509_crt_init(&crt);
    ret = mbedtls_x509_crt_parse_der(&crt, cert_der, cert_der_len);
    if (ret != 0) {
        mbedtls_x509_crt_free(&crt);
        return ret;
    }

    if (crt.subject_key_id.len == key_id_len &&
        key_id_len > 0 &&
        memcmp(crt.subject_key_id.p, key_id, key_id_len) == 0) {
        *match = 1;
    }

    mbedtls_x509_crt_free(&crt);
    return 0;
}

static int ecmp_mbedtls_verify_signature_from_cert(void *ctx,
                                                   const unsigned char *cert_der,
                                                   size_t cert_der_len,
                                                   const unsigned char *sig_alg_oid,
                                                   size_t sig_alg_oid_len,
                                                   const unsigned char *input,
                                                   size_t input_len,
                                                   const unsigned char *sig,
                                                   size_t sig_len,
                                                   int *verified)
{
    mbedtls_asn1_buf oid;
    mbedtls_x509_crt crt;
    const mbedtls_md_info_t *md_info;
    mbedtls_md_type_t md_alg;
    mbedtls_pk_type_t pk_alg;
    unsigned char hash[MBEDTLS_MD_MAX_SIZE];
    int ret;
    (void) ctx;

    if (cert_der == NULL || sig_alg_oid == NULL || input == NULL ||
        sig == NULL || verified == NULL) {
        return ECMP_ERR_PARAM;
    }

    *verified = 0;
    mbedtls_x509_crt_init(&crt);
    ret = mbedtls_x509_crt_parse_der(&crt, cert_der, cert_der_len);
    if (ret != 0) {
        mbedtls_x509_crt_free(&crt);
        return ret;
    }

    oid.tag = MBEDTLS_ASN1_OID;
    oid.p = (unsigned char *) sig_alg_oid;
    oid.len = sig_alg_oid_len;
    ret = mbedtls_oid_get_sig_alg(&oid, &md_alg, &pk_alg);
    if (ret != 0) {
        mbedtls_x509_crt_free(&crt);
        return ret;
    }

    if (md_alg == MBEDTLS_MD_NONE) {
        mbedtls_x509_crt_free(&crt);
        return 0;
    }

    /*
     * The certificate may expose a generic key type such as MBEDTLS_PK_ECKEY
     * even if the signature algorithm OID denotes ECDSA. Let mbedtls_pk_verify()
     * perform the final compatibility check.
     */
    (void) pk_alg;

    md_info = mbedtls_md_info_from_type(md_alg);
    if (md_info == NULL) {
        mbedtls_x509_crt_free(&crt);
        return ECMP_ERR_UNSUPPORTED;
    }

    ret = mbedtls_md(md_info, input, input_len, hash);
    if (ret != 0) {
        mbedtls_x509_crt_free(&crt);
        return ret;
    }

    ret = mbedtls_pk_verify(&crt.pk, md_alg, hash, mbedtls_md_get_size(md_info),
                            sig, sig_len);
    if (ret == 0) {
        *verified = 1;
    } else {
        ret = 0;
    }

    mbedtls_x509_crt_free(&crt);
    return ret;
}

static int ecmp_mbedtls_write_private_key_pem(void *ctx, const ecmp_key *key,
                                              unsigned char **pem, size_t *pem_len)
{
    unsigned char *buf;
    int ret;
    (void) ctx;

    if (key == NULL || pem == NULL || pem_len == NULL) {
        return ECMP_ERR_PARAM;
    }

    buf = calloc(1, 4096);
    if (buf == NULL) {
        return ECMP_ERR_ALLOC;
    }

    ret = mbedtls_pk_write_key_pem(&key->pk, buf, 4096);
    if (ret != 0) {
        free(buf);
        return ret;
    }

    *pem_len = strlen((const char *) buf);
    *pem = buf;
    return 0;
}

static int ecmp_mbedtls_der_to_pem(const char *header, const char *footer,
                                   const unsigned char *der, size_t der_len,
                                   unsigned char **pem, size_t *pem_len)
{
    unsigned char *buf;
    size_t olen = 0;
    int ret;

    buf = calloc(1, der_len * 3 + 128);
    if (buf == NULL) {
        return ECMP_ERR_ALLOC;
    }

    ret = mbedtls_pem_write_buffer(header, footer, der, der_len,
                                   buf, der_len * 3 + 128, &olen);
    if (ret != 0) {
        free(buf);
        return ret;
    }

    *pem = buf;
    *pem_len = olen - 1;
    return 0;
}

static int ecmp_mbedtls_write_certificate_pem(void *ctx, const unsigned char *der,
                                              size_t der_len,
                                              unsigned char **pem, size_t *pem_len)
{
    (void) ctx;
    return ecmp_mbedtls_der_to_pem("-----BEGIN CERTIFICATE-----\n",
                                   "-----END CERTIFICATE-----\n",
                                   der, der_len, pem, pem_len);
}

static int ecmp_mbedtls_write_certificate_sequence_pem(void *ctx,
                                                       const unsigned char *der,
                                                       size_t der_len,
                                                       unsigned char **pem,
                                                       size_t *pem_len)
{
    const unsigned char *p = der;
    const unsigned char *end = der + der_len;
    unsigned char *combined = NULL;
    size_t combined_len = 0;
    size_t seq_len;
    int ret;
    (void) ctx;

    if (der == NULL || pem == NULL || pem_len == NULL) {
        return ECMP_ERR_PARAM;
    }

    ret = mbedtls_asn1_get_tag((unsigned char **) &p, end, &seq_len,
                               MBEDTLS_ASN1_CONSTRUCTED | MBEDTLS_ASN1_SEQUENCE);
    if (ret != 0) {
        return ret;
    }
    end = p + seq_len;

    while (p < end) {
        const unsigned char *cert_start = p;
        size_t cert_len;
        unsigned char *one_pem = NULL;
        size_t one_pem_len = 0;
        unsigned char *tmp;

        ret = mbedtls_asn1_get_tag((unsigned char **) &p, end, &cert_len,
                                   MBEDTLS_ASN1_CONSTRUCTED | MBEDTLS_ASN1_SEQUENCE);
        if (ret != 0) {
            free(combined);
            return ret;
        }
        p += cert_len;

        ret = ecmp_mbedtls_der_to_pem("-----BEGIN CERTIFICATE-----\n",
                                      "-----END CERTIFICATE-----\n",
                                      cert_start, (size_t) (p - cert_start),
                                      &one_pem, &one_pem_len);
        if (ret != 0) {
            free(combined);
            return ret;
        }

        tmp = realloc(combined, combined_len + one_pem_len + 1);
        if (tmp == NULL) {
            free(one_pem);
            free(combined);
            return ECMP_ERR_ALLOC;
        }
        combined = tmp;
        memcpy(combined + combined_len, one_pem, one_pem_len);
        combined_len += one_pem_len;
        combined[combined_len] = '\0';
        free(one_pem);
    }

    *pem = combined;
    *pem_len = combined_len;
    return 0;
}

int ecmp_crypto_mbedtls_init(ecmp_crypto_provider *provider)
{
    static const unsigned char personalization[] = "eCMP";
    ecmp_mbedtls_ctx *ctx;
    int ret;

    if (provider == NULL) {
        return ECMP_ERR_PARAM;
    }

    memset(provider, 0, sizeof(*provider));
    ctx = calloc(1, sizeof(*ctx));
    if (ctx == NULL) {
        return ECMP_ERR_ALLOC;
    }

    mbedtls_entropy_init(&ctx->entropy);
    mbedtls_ctr_drbg_init(&ctx->ctr_drbg);

    ret = mbedtls_ctr_drbg_seed(&ctx->ctr_drbg, mbedtls_entropy_func, &ctx->entropy,
                                personalization, sizeof(personalization) - 1);
    if (ret != 0) {
        ecmp_mbedtls_free_ctx(ctx);
        return ret;
    }

    provider->ctx = ctx;
    provider->free_ctx = ecmp_mbedtls_free_ctx;
    provider->random_bytes = ecmp_mbedtls_random_bytes;
    provider->generate_ec_key = ecmp_mbedtls_generate_ec_key;
    provider->free_key = ecmp_mbedtls_free_key;
    provider->name_to_der = ecmp_mbedtls_name_to_der;
    provider->export_subject_public_key_info_der = ecmp_mbedtls_export_spki_der;
    provider->sign = ecmp_mbedtls_sign;
    provider->hash = ecmp_mbedtls_hash;
    provider->hmac = ecmp_mbedtls_hmac;
    provider->certificate_matches_subject_key_id = ecmp_mbedtls_certificate_matches_subject_key_id;
    provider->verify_signature_from_cert = ecmp_mbedtls_verify_signature_from_cert;
    provider->write_private_key_pem = ecmp_mbedtls_write_private_key_pem;
    provider->write_certificate_pem = ecmp_mbedtls_write_certificate_pem;
    provider->write_certificate_sequence_pem = ecmp_mbedtls_write_certificate_sequence_pem;
    return 0;
}

void ecmp_crypto_provider_free(ecmp_crypto_provider *provider)
{
    if (provider == NULL) {
        return;
    }
    if (provider->free_ctx != NULL) {
        provider->free_ctx(provider->ctx);
    }
    memset(provider, 0, sizeof(*provider));
}
