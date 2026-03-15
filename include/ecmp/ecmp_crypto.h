#ifndef ECMP_CRYPTO_H
#define ECMP_CRYPTO_H

#include <stddef.h>

#ifdef __cplusplus
extern "C" {
#endif

typedef enum ecmp_hash_alg {
    ECMP_HASH_SHA256 = 1,
    ECMP_HASH_SHA384 = 2,
    ECMP_HASH_SHA512 = 3
} ecmp_hash_alg;

typedef struct ecmp_key ecmp_key;

typedef struct ecmp_crypto_provider {
    void *ctx;
    void (*free_ctx)(void *ctx);
    int (*random_bytes)(void *ctx, unsigned char *out, size_t out_len);
    int (*generate_ec_key)(void *ctx, const char *curve_name, ecmp_key **key);
    void (*free_key)(void *ctx, ecmp_key *key);
    int (*name_to_der)(void *ctx, const char *name, unsigned char **out, size_t *out_len);
    int (*export_subject_public_key_info_der)(void *ctx, const ecmp_key *key,
                                              unsigned char **out, size_t *out_len);
    int (*sign)(void *ctx, const ecmp_key *key, ecmp_hash_alg hash_alg,
                const unsigned char *input, size_t input_len,
                unsigned char **sig, size_t *sig_len);
    int (*hash)(void *ctx, ecmp_hash_alg hash_alg, const unsigned char *input,
                size_t input_len, unsigned char **digest, size_t *digest_len);
    int (*hmac)(void *ctx, ecmp_hash_alg hash_alg, const unsigned char *key,
                size_t key_len, const unsigned char *input, size_t input_len,
                unsigned char **mac, size_t *mac_len);
    int (*certificate_matches_subject_key_id)(void *ctx,
                                              const unsigned char *cert_der,
                                              size_t cert_der_len,
                                              const unsigned char *key_id,
                                              size_t key_id_len,
                                              int *match);
    int (*verify_signature_from_cert)(void *ctx,
                                      const unsigned char *cert_der,
                                      size_t cert_der_len,
                                      const unsigned char *sig_alg_oid,
                                      size_t sig_alg_oid_len,
                                      const unsigned char *input,
                                      size_t input_len,
                                      const unsigned char *sig,
                                      size_t sig_len,
                                      int *verified);
    int (*write_private_key_pem)(void *ctx, const ecmp_key *key,
                                 unsigned char **pem, size_t *pem_len);
    int (*write_certificate_pem)(void *ctx, const unsigned char *der, size_t der_len,
                                 unsigned char **pem, size_t *pem_len);
    int (*write_certificate_sequence_pem)(void *ctx, const unsigned char *der,
                                          size_t der_len, unsigned char **pem,
                                          size_t *pem_len);
} ecmp_crypto_provider;

int ecmp_crypto_mbedtls_init(ecmp_crypto_provider *provider);
void ecmp_crypto_provider_free(ecmp_crypto_provider *provider);

#ifdef __cplusplus
}
#endif

#endif
