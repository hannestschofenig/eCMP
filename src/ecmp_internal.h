#ifndef ECMP_INTERNAL_H
#define ECMP_INTERNAL_H

#include <stddef.h>
#include <time.h>

#include "ecmp/ecmp.h"

typedef struct ecmp_buf {
    unsigned char *data;
    size_t len;
} ecmp_buf;

typedef struct ecmp_pbm_params {
    ecmp_buf salt;
    ecmp_hash_alg owf;
    int iteration_count;
    ecmp_hash_alg mac;
} ecmp_pbm_params;

typedef struct ecmp_message_state {
    ecmp_buf sender_der;
    ecmp_buf recipient_der;
    ecmp_buf sender_kid;
    ecmp_buf transaction_id;
    ecmp_buf sender_nonce;
    ecmp_buf recip_nonce;
    char message_time[16];
    int has_message_time;
    ecmp_pbm_params pbm;
    int protection_is_pbm;
    ecmp_buf protection_alg_oid;
    int pvno;
    int implicit_confirm;
    int body_type;
    int status;
    unsigned int fail_info;
    char status_text[256];
    ecmp_buf issued_cert_der;
    ecmp_buf extra_certs_der;
    ecmp_buf protection;
    int implicit_confirm_granted;
} ecmp_message_state;

void ecmp_buf_free(ecmp_buf *buf);
int ecmp_buf_dup(ecmp_buf *dst, const unsigned char *src, size_t len);
int ecmp_cmp_build_ir(const ecmp_crypto_provider *crypto, const ecmp_key *key,
                      const ecmp_ir_request *request, ecmp_message_state *state,
                      unsigned char **out, size_t *out_len);
int ecmp_cmp_build_certconf(const ecmp_crypto_provider *crypto,
                            const ecmp_ir_request *request,
                            ecmp_message_state *state,
                            unsigned char **out, size_t *out_len);
int ecmp_cmp_parse_message(const ecmp_crypto_provider *crypto,
                           const unsigned char *message, size_t message_len,
                           const char *pbm_secret,
                           const ecmp_message_state *expected_request,
                           ecmp_message_state *parsed);
void ecmp_message_state_free(ecmp_message_state *state);

#endif
