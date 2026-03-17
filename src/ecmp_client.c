#include "ecmp_internal.h"

#include <stdlib.h>
#include <string.h>
#include <stdio.h>

static int ecmp_is_known_error(int code)
{
    switch (code) {
        case ECMP_OK:
        case ECMP_ERR_PARAM:
        case ECMP_ERR_ALLOC:
        case ECMP_ERR_CRYPTO:
        case ECMP_ERR_ASN1:
        case ECMP_ERR_PROTOCOL:
        case ECMP_ERR_TRANSPORT:
        case ECMP_ERR_SERVER_REJECTED:
        case ECMP_ERR_UNSUPPORTED:
        case ECMP_ERR_IO:
        case ECMP_ERR_HTTP:
        case ECMP_ERR_NETWORK:
        case ECMP_ERR_CRYPTO_BACKEND:
            return 1;
        default:
            return 0;
    }
}

const char *ecmp_cmp_status_str(int status)
{
    switch (status) {
        case ECMP_CMP_STATUS_ACCEPTED:
            return "accepted";
        case ECMP_CMP_STATUS_GRANTED_WITH_MODS:
            return "grantedWithMods";
        case ECMP_CMP_STATUS_REJECTION:
            return "rejection";
        case ECMP_CMP_STATUS_WAITING:
            return "waiting";
        case ECMP_CMP_STATUS_REVOCATION_WARNING:
            return "revocationWarning";
        case ECMP_CMP_STATUS_REVOCATION_NOTIFICATION:
            return "revocationNotification";
        case ECMP_CMP_STATUS_KEY_UPDATE_WARNING:
            return "keyUpdateWarning";
        default:
            return "unknownStatus";
    }
}

const char *ecmp_cmp_body_type_str(int body_type)
{
    switch (body_type) {
        case ECMP_CMP_BODY_IR:
            return "ir";
        case ECMP_CMP_BODY_IP:
            return "ip";
        case ECMP_CMP_BODY_PKICONF:
            return "pkiConf";
        case ECMP_CMP_BODY_ERROR:
            return "error";
        default:
            return "unknownBodyType";
    }
}

const char *ecmp_cmp_failinfo_bit_str(unsigned int bit)
{
    switch (bit) {
        case ECMP_CMP_FAILINFO_BAD_ALG:
            return "badAlg";
        case ECMP_CMP_FAILINFO_BAD_MESSAGE_CHECK:
            return "badMessageCheck";
        case ECMP_CMP_FAILINFO_BAD_REQUEST:
            return "badRequest";
        case ECMP_CMP_FAILINFO_BAD_TIME:
            return "badTime";
        case ECMP_CMP_FAILINFO_BAD_CERT_ID:
            return "badCertId";
        case ECMP_CMP_FAILINFO_BAD_DATA_FORMAT:
            return "badDataFormat";
        case ECMP_CMP_FAILINFO_WRONG_AUTHORITY:
            return "wrongAuthority";
        case ECMP_CMP_FAILINFO_INCORRECT_DATA:
            return "incorrectData";
        case ECMP_CMP_FAILINFO_MISSING_TIME_STAMP:
            return "missingTimeStamp";
        case ECMP_CMP_FAILINFO_BAD_POP:
            return "badPOP";
        case ECMP_CMP_FAILINFO_CERT_REVOKED:
            return "certRevoked";
        case ECMP_CMP_FAILINFO_CERT_CONFIRMED:
            return "certConfirmed";
        case ECMP_CMP_FAILINFO_WRONG_INTEGRITY:
            return "wrongIntegrity";
        case ECMP_CMP_FAILINFO_BAD_RECIPIENT_NONCE:
            return "badRecipientNonce";
        case ECMP_CMP_FAILINFO_TIME_NOT_AVAILABLE:
            return "timeNotAvailable";
        case ECMP_CMP_FAILINFO_UNACCEPTED_POLICY:
            return "unacceptedPolicy";
        case ECMP_CMP_FAILINFO_UNACCEPTED_EXTENSION:
            return "unacceptedExtension";
        case ECMP_CMP_FAILINFO_ADD_INFO_NOT_AVAILABLE:
            return "addInfoNotAvailable";
        case ECMP_CMP_FAILINFO_BAD_SENDER_NONCE:
            return "badSenderNonce";
        case ECMP_CMP_FAILINFO_BAD_CERT_TEMPLATE:
            return "badCertTemplate";
        case ECMP_CMP_FAILINFO_SIGNER_NOT_TRUSTED:
            return "signerNotTrusted";
        case ECMP_CMP_FAILINFO_TRANSACTION_ID_IN_USE:
            return "transactionIdInUse";
        case ECMP_CMP_FAILINFO_UNSUPPORTED_VERSION:
            return "unsupportedVersion";
        case ECMP_CMP_FAILINFO_NOT_AUTHORIZED:
            return "notAuthorized";
        case ECMP_CMP_FAILINFO_SYSTEM_UNAVAIL:
            return "systemUnavail";
        case ECMP_CMP_FAILINFO_SYSTEM_FAILURE:
            return "systemFailure";
        case ECMP_CMP_FAILINFO_DUPLICATE_CERT_REQ:
            return "duplicateCertReq";
        default:
            return "unknownFailInfo";
    }
}

int ecmp_cmp_failinfo_to_string(unsigned int fail_info, char *buf, unsigned long buf_len)
{
    unsigned int bit;
    size_t used = 0;
    int first = 1;

    if (buf == NULL || buf_len == 0) {
        return ECMP_ERR_PARAM;
    }

    if (fail_info == 0) {
        if (buf_len < 5) {
            return ECMP_ERR_PARAM;
        }
        memcpy(buf, "none", 5);
        return ECMP_OK;
    }

    buf[0] = '\0';
    for (bit = 0; bit < 32; ++bit) {
        unsigned int mask = 1u << bit;
        const char *name;
        int written;

        if ((fail_info & mask) == 0) {
            continue;
        }

        name = ecmp_cmp_failinfo_bit_str(mask);
        written = snprintf(buf + used, (size_t) buf_len - used,
                           "%s%s", first ? "" : "|", name);
        if (written < 0 || used + (size_t) written >= (size_t) buf_len) {
            return ECMP_ERR_ALLOC;
        }
        used += (size_t) written;
        first = 0;
    }

    return ECMP_OK;
}

static int ecmp_normalize_error(int code, int fallback)
{
    return ecmp_is_known_error(code) ? code : fallback;
}

static void ecmp_copy_cmp_result_fields(ecmp_ir_result *result,
                                        const ecmp_message_state *state)
{
    ecmp_buf tmp = { 0 };

    if (result == NULL || state == NULL) {
        return;
    }

    /* Replace any previously copied response metadata with a fresh snapshot. */
    free(result->protection_alg_oid);
    free(result->sender_der);
    free(result->recipient_der);
    free(result->sender_kid);
    free(result->transaction_id);
    free(result->sender_nonce);
    free(result->recip_nonce);
    result->protection_alg_oid = NULL;
    result->sender_der = NULL;
    result->recipient_der = NULL;
    result->sender_kid = NULL;
    result->transaction_id = NULL;
    result->sender_nonce = NULL;
    result->recip_nonce = NULL;
    result->protection_alg_oid_len = 0;
    result->sender_der_len = 0;
    result->recipient_der_len = 0;
    result->sender_kid_len = 0;
    result->transaction_id_len = 0;
    result->sender_nonce_len = 0;
    result->recip_nonce_len = 0;

    result->response_body_type = state->body_type;
    result->cmp_status = state->status;
    result->cmp_fail_info = state->fail_info;
    memcpy(result->cmp_status_text, state->status_text,
           sizeof(result->cmp_status_text));

    /* Keep result ownership independent from the transient parser state. */
    if (ecmp_buf_dup(&tmp, state->protection_alg_oid.data,
                     state->protection_alg_oid.len) == 0) {
        result->protection_alg_oid = tmp.data;
        result->protection_alg_oid_len = tmp.len;
        memset(&tmp, 0, sizeof(tmp));
    }
    if (ecmp_buf_dup(&tmp, state->sender_der.data,
                     state->sender_der.len) == 0) {
        result->sender_der = tmp.data;
        result->sender_der_len = tmp.len;
        memset(&tmp, 0, sizeof(tmp));
    }
    if (ecmp_buf_dup(&tmp, state->recipient_der.data,
                     state->recipient_der.len) == 0) {
        result->recipient_der = tmp.data;
        result->recipient_der_len = tmp.len;
        memset(&tmp, 0, sizeof(tmp));
    }
    if (ecmp_buf_dup(&tmp, state->sender_kid.data,
                     state->sender_kid.len) == 0) {
        result->sender_kid = tmp.data;
        result->sender_kid_len = tmp.len;
        memset(&tmp, 0, sizeof(tmp));
    }
    if (ecmp_buf_dup(&tmp, state->transaction_id.data,
                     state->transaction_id.len) == 0) {
        result->transaction_id = tmp.data;
        result->transaction_id_len = tmp.len;
        memset(&tmp, 0, sizeof(tmp));
    }
    if (ecmp_buf_dup(&tmp, state->sender_nonce.data,
                     state->sender_nonce.len) == 0) {
        result->sender_nonce = tmp.data;
        result->sender_nonce_len = tmp.len;
        memset(&tmp, 0, sizeof(tmp));
    }
    if (ecmp_buf_dup(&tmp, state->recip_nonce.data,
                     state->recip_nonce.len) == 0) {
        result->recip_nonce = tmp.data;
        result->recip_nonce_len = tmp.len;
    }
}

static void ecmp_zero_result(ecmp_ir_result *result)
{
    memset(result, 0, sizeof(*result));
}

void ecmp_ir_result_free(ecmp_ir_result *result)
{
    if (result == NULL) {
        return;
    }

    free(result->request_der);
    free(result->response_der);
    free(result->issued_cert_der);
    free(result->extra_certs_der);
    free(result->private_key_pem);
    free(result->protection_alg_oid);
    free(result->sender_der);
    free(result->recipient_der);
    free(result->sender_kid);
    free(result->transaction_id);
    free(result->sender_nonce);
    free(result->recip_nonce);
    ecmp_zero_result(result);
}

const char *ecmp_strerror(int code)
{
    switch (code) {
        case ECMP_OK:
            return "success";
        case ECMP_ERR_PARAM:
            return "invalid parameter";
        case ECMP_ERR_ALLOC:
            return "allocation failed";
        case ECMP_ERR_CRYPTO:
            return "crypto operation failed";
        case ECMP_ERR_ASN1:
            return "ASN.1 encoding or decoding failed";
        case ECMP_ERR_PROTOCOL:
            return "CMP protocol validation failed";
        case ECMP_ERR_TRANSPORT:
            return "transport exchange failed";
        case ECMP_ERR_SERVER_REJECTED:
            return "server returned a rejection";
        case ECMP_ERR_UNSUPPORTED:
            return "unsupported feature";
        case ECMP_ERR_IO:
            return "I/O operation failed";
        case ECMP_ERR_HTTP:
            return "invalid HTTP exchange";
        case ECMP_ERR_NETWORK:
            return "network operation failed";
        case ECMP_ERR_CRYPTO_BACKEND:
            return "crypto backend operation failed";
        default:
            return "unknown error";
    }
}

int ecmp_initial_registration(const ecmp_crypto_provider *crypto,
                              const ecmp_transport *transport,
                              const ecmp_ir_request *request,
                              ecmp_ir_result *result)
{
    ecmp_message_state request_state;
    ecmp_message_state response_state;
    ecmp_key *new_key = NULL;
    unsigned char *request_der = NULL;
    unsigned char *response_der = NULL;
    unsigned char *certconf_der = NULL;
    size_t request_der_len = 0;
    size_t response_der_len = 0;
    size_t certconf_der_len = 0;
    int ret;

    if (crypto == NULL || transport == NULL || request == NULL || result == NULL) {
        return ECMP_ERR_PARAM;
    }
    if (crypto->generate_ec_key == NULL || crypto->write_private_key_pem == NULL ||
        transport->send_receive == NULL) {
        return ECMP_ERR_PARAM;
    }

    memset(&request_state, 0, sizeof(request_state));
    memset(&response_state, 0, sizeof(response_state));
    ecmp_zero_result(result);

    ret = crypto->generate_ec_key(crypto->ctx, request->new_key_curve, &new_key);
    if (ret != 0 || new_key == NULL) {
        ret = ret != 0 ? ecmp_normalize_error(ret, ECMP_ERR_CRYPTO) : ECMP_ERR_CRYPTO;
        goto cleanup;
    }

    ret = ecmp_cmp_build_ir(crypto, new_key, request, &request_state,
                            &request_der, &request_der_len);
    if (ret != 0) {
        goto cleanup;
    }

    ret = transport->send_receive(transport->ctx, request_der, request_der_len,
                                  &response_der, &response_der_len);
    if (ret != 0) {
        ret = ecmp_normalize_error(ret, ECMP_ERR_TRANSPORT);
        goto cleanup;
    }

    ret = ecmp_cmp_parse_message(crypto, response_der, response_der_len,
                                 request->pbm_secret, &request_state,
                                 &response_state);
    if (ret != 0) {
        goto cleanup;
    }

    /* Preserve parsed rejection details so callers can inspect CMP-level errors. */
    if (response_state.status != 0 && response_state.status != 1) {
        ecmp_copy_cmp_result_fields(result, &response_state);
        ret = ECMP_ERR_SERVER_REJECTED;
        goto cleanup;
    }

    if (response_state.issued_cert_der.data == NULL ||
        response_state.issued_cert_der.len == 0) {
        ret = ECMP_ERR_PROTOCOL;
        goto cleanup;
    }

    if (!response_state.implicit_confirm_granted) {
        free(response_der);
        response_der = NULL;
        response_der_len = 0;

        ret = ecmp_cmp_build_certconf(crypto, request, &response_state,
                                      &certconf_der, &certconf_der_len);
        if (ret != 0) {
            goto cleanup;
        }

        free(request_der);
        request_der = certconf_der;
        request_der_len = certconf_der_len;
        certconf_der = NULL;
        certconf_der_len = 0;

        ret = transport->send_receive(transport->ctx, request_der, request_der_len,
                                      &response_der, &response_der_len);
        if (ret != 0) {
            ret = ecmp_normalize_error(ret, ECMP_ERR_TRANSPORT);
            goto cleanup;
        }

        ecmp_message_state_free(&request_state);
        memset(&request_state, 0, sizeof(request_state));
        ret = ecmp_cmp_parse_message(crypto, response_der, response_der_len,
                                     request->pbm_secret, &response_state,
                                     &request_state);
        if (ret != 0) {
            goto cleanup;
        }
        if (request_state.body_type != ECMP_CMP_BODY_PKICONF) {
            ret = ECMP_ERR_PROTOCOL;
            goto cleanup;
        }

        ecmp_message_state_free(&request_state);
        memset(&request_state, 0, sizeof(request_state));
    }

    result->request_der = request_der;
    result->request_der_len = request_der_len;
    result->response_der = response_der;
    result->response_der_len = response_der_len;
    request_der = NULL;
    response_der = NULL;
    request_der_len = 0;
    response_der_len = 0;

    result->issued_cert_der = calloc(1, response_state.issued_cert_der.len);
    if (result->issued_cert_der == NULL) {
        ret = ECMP_ERR_ALLOC;
        goto cleanup;
    }
    memcpy(result->issued_cert_der, response_state.issued_cert_der.data,
           response_state.issued_cert_der.len);
    result->issued_cert_der_len = response_state.issued_cert_der.len;

    if (response_state.extra_certs_der.data != NULL &&
        response_state.extra_certs_der.len > 0) {
        ecmp_buf tmp = { 0 };
        ret = ecmp_buf_dup(&tmp, response_state.extra_certs_der.data,
                           response_state.extra_certs_der.len);
        if (ret != 0) {
            goto cleanup;
        }
        result->extra_certs_der = tmp.data;
        result->extra_certs_der_len = tmp.len;
    }

    ret = crypto->write_private_key_pem(crypto->ctx, new_key,
                                        &result->private_key_pem,
                                        &result->private_key_pem_len);
    if (ret != 0) {
        ret = ecmp_normalize_error(ret, ECMP_ERR_CRYPTO);
        goto cleanup;
    }

    result->implicit_confirm_granted = response_state.implicit_confirm_granted;
    ecmp_copy_cmp_result_fields(result, &response_state);
    ret = ECMP_OK;

cleanup:
    free(request_der);
    free(response_der);
    free(certconf_der);
    ecmp_message_state_free(&request_state);
    ecmp_message_state_free(&response_state);
    if (crypto->free_key != NULL && new_key != NULL) {
        crypto->free_key(crypto->ctx, new_key);
    }
    if (ret != ECMP_OK && ret != ECMP_ERR_SERVER_REJECTED) {
        ecmp_ir_result_free(result);
    }
    return ret;
}
