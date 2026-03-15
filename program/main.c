#include "ecmp/ecmp.h"
#include "ecmp/ecmp_error.h"

#include <errno.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/stat.h>
#include <sys/types.h>

#include "mbedtls/asn1.h"
#include "mbedtls/oid.h"
#include "mbedtls/x509.h"

typedef struct cli_config {
    const char *host;
    const char *port;
    const char *path;
    const char *sender;
    const char *recipient;
    const char *subject;
    const char *secret;
    const char *kid;
    const char *curve;
    const char *output_dir;
    int implicit_confirm;
    int write_debug_meta;
} cli_config;

#define ECMP_PBM_OID "\x2a\x86\x48\x86\xf6\x7d\x07\x42\x0d"

/* Internal Mbed TLS helper used only for CLI debug rendering of Name DER. */
int mbedtls_x509_get_name(unsigned char **p, const unsigned char *end,
                          mbedtls_x509_name *cur);

static int ensure_dir(const char *path)
{
    struct stat st;

    if (stat(path, &st) == 0) {
        return S_ISDIR(st.st_mode) ? 0 : ECMP_ERR_IO;
    }
    if (mkdir(path, 0775) != 0 && errno != EEXIST) {
        return ECMP_ERR_IO;
    }
    return 0;
}

static int write_file(const char *path, const unsigned char *data, size_t len)
{
    FILE *f = fopen(path, "wb");
    if (f == NULL) {
        return ECMP_ERR_IO;
    }
    if (len > 0 && fwrite(data, 1, len, f) != len) {
        fclose(f);
        return ECMP_ERR_IO;
    }
    fclose(f);
    return 0;
}

static int format_hex(const unsigned char *data, size_t len, char *out, size_t out_len)
{
    size_t i;

    if (out == NULL || out_len == 0) {
        return ECMP_ERR_PARAM;
    }
    if (data == NULL && len != 0) {
        return ECMP_ERR_PARAM;
    }
    if (len == 0) {
        if (out_len < 5) {
            return ECMP_ERR_PARAM;
        }
        memcpy(out, "none", 5);
        return ECMP_OK;
    }
    if (out_len < len * 2 + 1) {
        return ECMP_ERR_ALLOC;
    }

    for (i = 0; i < len; ++i) {
        snprintf(out + i * 2, out_len - i * 2, "%02x", data[i]);
    }
    return ECMP_OK;
}

static const char *protection_alg_name(const unsigned char *oid, size_t oid_len)
{
    mbedtls_asn1_buf oid_buf;
    mbedtls_md_type_t md_alg;
    mbedtls_pk_type_t pk_alg;
    const char *desc = NULL;

    if (oid == NULL || oid_len == 0) {
        return "none";
    }
    if (oid_len == sizeof(ECMP_PBM_OID) - 1 &&
        memcmp(oid, ECMP_PBM_OID, oid_len) == 0) {
        return "passwordBasedMac";
    }

    oid_buf.tag = MBEDTLS_ASN1_OID;
    oid_buf.p = (unsigned char *) oid;
    oid_buf.len = oid_len;

    if (mbedtls_oid_get_sig_alg_desc(&oid_buf, &desc) == 0 && desc != NULL) {
        return desc;
    }
    if (mbedtls_oid_get_sig_alg(&oid_buf, &md_alg, &pk_alg) == 0) {
        (void) md_alg;
        (void) pk_alg;
        return "signature";
    }

    return "unknownProtectionAlg";
}

static int format_name_der(const unsigned char *der, size_t der_len,
                           char *out, size_t out_len)
{
    unsigned char *p;
    size_t len;
    mbedtls_x509_name head;
    int ret;
    int written;

    if (out == NULL || out_len == 0) {
        return ECMP_ERR_PARAM;
    }
    if (der == NULL && der_len != 0) {
        return ECMP_ERR_PARAM;
    }
    if (der == NULL || der_len == 0) {
        if (out_len < 5) {
            return ECMP_ERR_PARAM;
        }
        memcpy(out, "none", 5);
        return ECMP_OK;
    }

    memset(&head, 0, sizeof(head));
    p = (unsigned char *) der;
    ret = mbedtls_asn1_get_tag(&p, der + der_len, &len,
                               MBEDTLS_ASN1_CONSTRUCTED |
                               MBEDTLS_ASN1_SEQUENCE);
    if (ret != 0 || p + len != der + der_len) {
        return ECMP_ERR_ASN1;
    }

    ret = mbedtls_x509_get_name(&p, p + len, &head);
    if (ret != 0 || p != der + der_len) {
        mbedtls_asn1_free_named_data_list_shallow(head.next);
        return ECMP_ERR_ASN1;
    }

    written = mbedtls_x509_dn_gets(out, out_len, &head);
    mbedtls_asn1_free_named_data_list_shallow(head.next);
    if (written < 0) {
        return ECMP_ERR_ASN1;
    }

    return ECMP_OK;
}

static int write_debug_meta_file(const char *path, const ecmp_ir_result *result)
{
    FILE *f;
    char fail_info_buf[256];
    char oid_buf[128];
    char sender_buf[512];
    char recipient_buf[512];
    char sender_kid_buf[128];
    char txid_buf[128];
    char sender_nonce_buf[128];
    char recip_nonce_buf[128];
    int ret;

    if (path == NULL || result == NULL) {
        return ECMP_ERR_PARAM;
    }

    ret = ecmp_cmp_failinfo_to_string(result->cmp_fail_info, fail_info_buf,
                                      sizeof(fail_info_buf));
    if (ret != 0) {
        snprintf(fail_info_buf, sizeof(fail_info_buf), "0x%08x",
                 result->cmp_fail_info);
    }

    ret = format_hex(result->protection_alg_oid, result->protection_alg_oid_len,
                     oid_buf, sizeof(oid_buf));
    if (ret != 0) {
        snprintf(oid_buf, sizeof(oid_buf), "unavailable");
    }
    ret = format_name_der(result->sender_der, result->sender_der_len,
                          sender_buf, sizeof(sender_buf));
    if (ret != 0) {
        snprintf(sender_buf, sizeof(sender_buf), "unavailable");
    }
    ret = format_name_der(result->recipient_der, result->recipient_der_len,
                          recipient_buf, sizeof(recipient_buf));
    if (ret != 0) {
        snprintf(recipient_buf, sizeof(recipient_buf), "unavailable");
    }
    ret = format_hex(result->sender_kid, result->sender_kid_len,
                     sender_kid_buf, sizeof(sender_kid_buf));
    if (ret != 0) {
        snprintf(sender_kid_buf, sizeof(sender_kid_buf), "unavailable");
    }
    ret = format_hex(result->transaction_id, result->transaction_id_len,
                     txid_buf, sizeof(txid_buf));
    if (ret != 0) {
        snprintf(txid_buf, sizeof(txid_buf), "unavailable");
    }
    ret = format_hex(result->sender_nonce, result->sender_nonce_len,
                     sender_nonce_buf, sizeof(sender_nonce_buf));
    if (ret != 0) {
        snprintf(sender_nonce_buf, sizeof(sender_nonce_buf), "unavailable");
    }
    ret = format_hex(result->recip_nonce, result->recip_nonce_len,
                     recip_nonce_buf, sizeof(recip_nonce_buf));
    if (ret != 0) {
        snprintf(recip_nonce_buf, sizeof(recip_nonce_buf), "unavailable");
    }

    f = fopen(path, "wb");
    if (f == NULL) {
        return ECMP_ERR_IO;
    }

    fprintf(f, "responseBodyType: %s (%d)\n",
            ecmp_cmp_body_type_str(result->response_body_type),
            result->response_body_type);
    fprintf(f, "protectionAlg: %s\n",
            protection_alg_name(result->protection_alg_oid,
                                result->protection_alg_oid_len));
    fprintf(f, "protectionAlgOid: %s\n", oid_buf);
    fprintf(f, "sender: %s\n", sender_buf);
    fprintf(f, "recipient: %s\n", recipient_buf);
    fprintf(f, "senderKID: %s\n", sender_kid_buf);
    fprintf(f, "transactionID: %s\n", txid_buf);
    fprintf(f, "senderNonce: %s\n", sender_nonce_buf);
    fprintf(f, "recipNonce: %s\n", recip_nonce_buf);
    fprintf(f, "cmpStatus: %s (%d)\n",
            ecmp_cmp_status_str(result->cmp_status), result->cmp_status);
    fprintf(f, "cmpFailInfo: %s (0x%08x)\n",
            fail_info_buf, result->cmp_fail_info);
    fprintf(f, "implicitConfirmGranted: %s\n",
            result->implicit_confirm_granted ? "true" : "false");
    if (result->cmp_status_text[0] != '\0') {
        fprintf(f, "cmpStatusText: %s\n", result->cmp_status_text);
    }

    if (fclose(f) != 0) {
        return ECMP_ERR_IO;
    }
    return ECMP_OK;
}

static void usage(const char *argv0)
{
    fprintf(stderr,
            "Usage: %s -i [--implicit-confirm] [--output DIR]\n"
            "       [--host HOST] [--port PORT] [--path PATH]\n"
            "       [--sender DN] [--recipient DN] [--subject DN]\n"
            "       [--secret SECRET] [--kid KID] [--curve CURVE]\n"
            "       [--write-debug-meta]\n",
            argv0);
}

static int parse_args(int argc, char **argv, cli_config *cfg)
{
    int i;
    int run_ir = 0;

    cfg->host = "127.0.0.1";
    cfg->port = "5000";
    cfg->path = "issuing";
    cfg->sender = "CN=embeddedcmp-ir";
    cfg->recipient = "CN=recip";
    cfg->subject = "CN=embeddedcmp-ir";
    cfg->secret = "SiemensIT";
    cfg->kid = "embeddedcmp-ir";
    cfg->curve = "secp256r1";
    cfg->output_dir = "eCMP/out";
    cfg->implicit_confirm = 0;
    cfg->write_debug_meta = 0;

    for (i = 1; i < argc; ++i) {
        if (strcmp(argv[i], "-i") == 0) {
            run_ir = 1;
        } else if (strcmp(argv[i], "--implicit-confirm") == 0) {
            cfg->implicit_confirm = 1;
        } else if (strcmp(argv[i], "--write-debug-meta") == 0) {
            cfg->write_debug_meta = 1;
        } else if (strcmp(argv[i], "--host") == 0 && i + 1 < argc) {
            cfg->host = argv[++i];
        } else if (strcmp(argv[i], "--port") == 0 && i + 1 < argc) {
            cfg->port = argv[++i];
        } else if (strcmp(argv[i], "--path") == 0 && i + 1 < argc) {
            cfg->path = argv[++i];
        } else if (strcmp(argv[i], "--sender") == 0 && i + 1 < argc) {
            cfg->sender = argv[++i];
        } else if (strcmp(argv[i], "--recipient") == 0 && i + 1 < argc) {
            cfg->recipient = argv[++i];
        } else if (strcmp(argv[i], "--subject") == 0 && i + 1 < argc) {
            cfg->subject = argv[++i];
        } else if (strcmp(argv[i], "--secret") == 0 && i + 1 < argc) {
            cfg->secret = argv[++i];
        } else if (strcmp(argv[i], "--kid") == 0 && i + 1 < argc) {
            cfg->kid = argv[++i];
        } else if (strcmp(argv[i], "--curve") == 0 && i + 1 < argc) {
            cfg->curve = argv[++i];
        } else if (strcmp(argv[i], "--output") == 0 && i + 1 < argc) {
            cfg->output_dir = argv[++i];
        } else {
            return ECMP_ERR_PARAM;
        }
    }

    return run_ir ? ECMP_OK : ECMP_ERR_PARAM;
}

int main(int argc, char **argv)
{
    cli_config cfg;
    ecmp_crypto_provider crypto;
    ecmp_transport transport;
    ecmp_ir_request request;
    ecmp_ir_result result;
    unsigned char *cert_pem = NULL;
    unsigned char *chain_pem = NULL;
    size_t cert_pem_len = 0;
    size_t chain_pem_len = 0;
    char path[512];
    char fail_info_buf[256];
    int ret;

    if (parse_args(argc, argv, &cfg) != 0) {
        usage(argv[0]);
        return 2;
    }

    if (ensure_dir(cfg.output_dir) != 0) {
        fprintf(stderr, "failed to create output directory %s\n", cfg.output_dir);
        return 1;
    }

    memset(&crypto, 0, sizeof(crypto));
    memset(&transport, 0, sizeof(transport));
    memset(&result, 0, sizeof(result));

    ret = ecmp_crypto_mbedtls_init(&crypto);
    if (ret != 0) {
        fprintf(stderr, "crypto init failed: %d\n", ret);
        return 1;
    }

    ret = ecmp_http_transport_init(&transport, cfg.host, cfg.port, cfg.path);
    if (ret != 0) {
        fprintf(stderr, "transport init failed\n");
        ecmp_crypto_provider_free(&crypto);
        return 1;
    }

    request.sender_dn = cfg.sender;
    request.recipient_dn = cfg.recipient;
    request.subject_dn = cfg.subject;
    request.pbm_secret = cfg.secret;
    request.pbm_kid = cfg.kid;
    request.new_key_curve = cfg.curve;
    request.request_implicit_confirm = cfg.implicit_confirm;

    ret = ecmp_initial_registration(&crypto, &transport, &request, &result);
    if (ret != 0) {
        fprintf(stderr, "IR failed: %s (%d)\n", ecmp_strerror(ret), ret);
        if (ret == ECMP_ERR_SERVER_REJECTED) {
            if (ecmp_cmp_failinfo_to_string(result.cmp_fail_info, fail_info_buf,
                                            sizeof(fail_info_buf)) != 0) {
                snprintf(fail_info_buf, sizeof(fail_info_buf), "0x%08x",
                         result.cmp_fail_info);
            }
            fprintf(stderr, "CMP status: %s (%d)\n",
                    ecmp_cmp_status_str(result.cmp_status), result.cmp_status);
            fprintf(stderr, "CMP failInfo: %s (0x%08x)\n",
                    fail_info_buf, result.cmp_fail_info);
            if (result.cmp_status_text[0] != '\0') {
                fprintf(stderr, "CMP statusText: %s\n", result.cmp_status_text);
            }
        }
        if (cfg.write_debug_meta) {
            snprintf(path, sizeof(path), "%s/last_response.meta.txt", cfg.output_dir);
            if (write_debug_meta_file(path, &result) != 0) {
                fprintf(stderr, "debug meta write failed for %s\n", path);
            }
        }
        ecmp_transport_free(&transport);
        ecmp_crypto_provider_free(&crypto);
        return 1;
    }

    ret = crypto.write_certificate_pem(crypto.ctx, result.issued_cert_der,
                                       result.issued_cert_der_len,
                                       &cert_pem, &cert_pem_len);
    if (ret != 0) {
        fprintf(stderr, "certificate PEM conversion failed\n");
        ecmp_ir_result_free(&result);
        ecmp_transport_free(&transport);
        ecmp_crypto_provider_free(&crypto);
        return 1;
    }

    if (result.extra_certs_der != NULL && result.extra_certs_der_len > 0) {
        ret = crypto.write_certificate_sequence_pem(crypto.ctx,
                                                    result.extra_certs_der,
                                                    result.extra_certs_der_len,
                                                    &chain_pem, &chain_pem_len);
        if (ret != 0) {
            fprintf(stderr, "chain PEM conversion failed\n");
            free(cert_pem);
            ecmp_ir_result_free(&result);
            ecmp_transport_free(&transport);
            ecmp_crypto_provider_free(&crypto);
            return 1;
        }
    }

    snprintf(path, sizeof(path), "%s/last_request.der", cfg.output_dir);
    write_file(path, result.request_der, result.request_der_len);
    snprintf(path, sizeof(path), "%s/last_response.der", cfg.output_dir);
    write_file(path, result.response_der, result.response_der_len);
    snprintf(path, sizeof(path), "%s/new_key.pem", cfg.output_dir);
    write_file(path, result.private_key_pem, result.private_key_pem_len);
    snprintf(path, sizeof(path), "%s/new_cert.der", cfg.output_dir);
    write_file(path, result.issued_cert_der, result.issued_cert_der_len);
    snprintf(path, sizeof(path), "%s/new_cert.pem", cfg.output_dir);
    write_file(path, cert_pem, cert_pem_len);
    if (chain_pem != NULL) {
        snprintf(path, sizeof(path), "%s/extra_certs.der", cfg.output_dir);
        write_file(path, result.extra_certs_der, result.extra_certs_der_len);
        snprintf(path, sizeof(path), "%s/extra_certs.pem", cfg.output_dir);
        write_file(path, chain_pem, chain_pem_len);
    }
    if (cfg.write_debug_meta) {
        snprintf(path, sizeof(path), "%s/last_response.meta.txt", cfg.output_dir);
        ret = write_debug_meta_file(path, &result);
        if (ret != 0) {
            fprintf(stderr, "debug meta write failed: %s (%d)\n",
                    ecmp_strerror(ret), ret);
            free(cert_pem);
            free(chain_pem);
            ecmp_ir_result_free(&result);
            ecmp_transport_free(&transport);
            ecmp_crypto_provider_free(&crypto);
            return 1;
        }
    }

    fprintf(stdout,
            "IR completed. implicitConfirm=%s. Output written to %s\n",
            result.implicit_confirm_granted ? "granted" : "not granted",
            cfg.output_dir);

    free(cert_pem);
    free(chain_pem);
    ecmp_ir_result_free(&result);
    ecmp_transport_free(&transport);
    ecmp_crypto_provider_free(&crypto);
    return 0;
}
