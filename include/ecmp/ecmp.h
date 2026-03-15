#ifndef ECMP_H
#define ECMP_H

#include <stddef.h>

#include "ecmp_error.h"
#include "ecmp_cmp_status.h"
#include "ecmp_crypto.h"
#include "ecmp_transport.h"

#ifdef __cplusplus
extern "C" {
#endif

typedef struct ecmp_ir_request {
    const char *sender_dn;
    const char *recipient_dn;
    const char *subject_dn;
    const char *pbm_secret;
    const char *pbm_kid;
    const char *new_key_curve;
    int request_implicit_confirm;
} ecmp_ir_request;

typedef struct ecmp_ir_result {
    unsigned char *request_der;
    size_t request_der_len;
    unsigned char *response_der;
    size_t response_der_len;
    unsigned char *issued_cert_der;
    size_t issued_cert_der_len;
    unsigned char *extra_certs_der;
    size_t extra_certs_der_len;
    unsigned char *private_key_pem;
    size_t private_key_pem_len;
    unsigned char *protection_alg_oid;
    size_t protection_alg_oid_len;
    unsigned char *sender_der;
    size_t sender_der_len;
    unsigned char *recipient_der;
    size_t recipient_der_len;
    unsigned char *sender_kid;
    size_t sender_kid_len;
    unsigned char *transaction_id;
    size_t transaction_id_len;
    unsigned char *sender_nonce;
    size_t sender_nonce_len;
    unsigned char *recip_nonce;
    size_t recip_nonce_len;
    int response_body_type;
    int cmp_status;
    unsigned int cmp_fail_info;
    char cmp_status_text[256];
    int implicit_confirm_granted;
} ecmp_ir_result;

int ecmp_initial_registration(const ecmp_crypto_provider *crypto,
                              const ecmp_transport *transport,
                              const ecmp_ir_request *request,
                              ecmp_ir_result *result);
void ecmp_ir_result_free(ecmp_ir_result *result);
const char *ecmp_strerror(int code);

#ifdef __cplusplus
}
#endif

#endif
