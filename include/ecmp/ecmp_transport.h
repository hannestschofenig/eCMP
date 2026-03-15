#ifndef ECMP_TRANSPORT_H
#define ECMP_TRANSPORT_H

#include <stddef.h>

#ifdef __cplusplus
extern "C" {
#endif

typedef struct ecmp_transport {
    void *ctx;
    void (*free_ctx)(void *ctx);
    int (*send_receive)(void *ctx, const unsigned char *request,
                        size_t request_len, unsigned char **response,
                        size_t *response_len);
} ecmp_transport;

int ecmp_http_transport_init(ecmp_transport *transport, const char *host,
                             const char *port, const char *path);
void ecmp_transport_free(ecmp_transport *transport);

#ifdef __cplusplus
}
#endif

#endif
