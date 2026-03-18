/* NOLINTNEXTLINE(bugprone-reserved-identifier) */
#define _POSIX_C_SOURCE 200809L

#include "ecmp/ecmp_transport.h"
#include "ecmp/ecmp_error.h"

#include <errno.h>
#include <netdb.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/socket.h>
#include <sys/types.h>
#include <unistd.h>

/*
 * This file provides the current transport backend for eCMP.
 *
 * CMP itself is transport-agnostic. For now, eCMP uses the HTTP binding and
 * sends DER-encoded PKIMessage objects with:
 *
 *   Content-Type: application/pkixcmp
 *
 * The rest of the client only sees the transport abstraction and hands over
 * request/response byte strings.
 */

typedef struct ecmp_http_ctx {
    char *host;
    char *port;
    char *path;
} ecmp_http_ctx;

static char *ecmp_http_strdup(const char *src)
{
    size_t len;
    char *copy;

    len = strlen(src) + 1;
    copy = calloc(1, len);
    if (copy == NULL) {
        return NULL;
    }
    memcpy(copy, src, len);
    return copy;
}

static void ecmp_http_free_ctx(void *ctx)
{
    ecmp_http_ctx *http = (ecmp_http_ctx *) ctx;

    if (http == NULL) {
        return;
    }

    free(http->host);
    free(http->port);
    free(http->path);
    free(http);
}

static int ecmp_http_write_all(int fd, const unsigned char *buf, size_t len)
{
    /* send() may complete partially, so loop until the complete HTTP fragment is written. */
    while (len > 0) {
        ssize_t written = send(fd, buf, len, 0);
        if (written < 0) {
            if (errno == EINTR) {
                continue;
            }
            return ECMP_ERR_NETWORK;
        }
        buf += (size_t) written;
        len -= (size_t) written;
    }
    return 0;
}

static int ecmp_http_send_receive(void *ctx, const unsigned char *request,
                                  size_t request_len, unsigned char **response,
                                  size_t *response_len)
{
    ecmp_http_ctx *http = (ecmp_http_ctx *) ctx;
    struct addrinfo hints;
    struct addrinfo *ai = NULL;
    struct addrinfo *cur;
    int fd = -1;
    int ret;
    unsigned char *raw = NULL;
    size_t raw_len = 0;
    size_t raw_cap = 0;
    char header[512];
    const unsigned char *body;
    const unsigned char *hdr_end;

    /*
     * Minimal HTTP client for the CMP-over-HTTP binding:
     *   1. resolve host/port
     *   2. open a TCP connection
     *   3. POST the DER PKIMessage
     *   4. read the full HTTP response
     *   5. return only the CMP payload body
     */
    if (http == NULL || request == NULL || response == NULL || response_len == NULL) {
        return ECMP_ERR_PARAM;
    }

    memset(&hints, 0, sizeof(hints));
    hints.ai_socktype = SOCK_STREAM;
    hints.ai_family = AF_UNSPEC;

    ret = getaddrinfo(http->host, http->port, &hints, &ai);
    if (ret != 0) {
        return ECMP_ERR_NETWORK;
    }

    /* Try all resolved addresses until a TCP connection succeeds. */
    for (cur = ai; cur != NULL; cur = cur->ai_next) {
        fd = socket(cur->ai_family, cur->ai_socktype, cur->ai_protocol);
        if (fd < 0) {
            continue;
        }
        if (connect(fd, cur->ai_addr, cur->ai_addrlen) == 0) {
            break;
        }
        close(fd);
        fd = -1;
    }
    freeaddrinfo(ai);

    if (fd < 0) {
        return ECMP_ERR_NETWORK;
    }

    /* CMP payloads are carried verbatim as application/pkixcmp bodies. */
    snprintf(header, sizeof(header),
             "POST %s%s HTTP/1.1\r\n"
             "Host: %s\r\n"
             "Content-Type: application/pkixcmp\r\n"
             "Connection: close\r\n"
             "Content-Length: %zu\r\n\r\n",
             http->path[0] == '/' ? "" : "/",
             http->path, http->host, request_len);

    if (ecmp_http_write_all(fd, (const unsigned char *) header, strlen(header)) != 0 ||
        ecmp_http_write_all(fd, request, request_len) != 0) {
        close(fd);
        return ECMP_ERR_NETWORK;
    }

    /* Read the full HTTP response into a growable buffer before stripping headers. */
    for (;;) {
        unsigned char chunk[2048];
        ssize_t got = recv(fd, chunk, sizeof(chunk), 0);
        unsigned char *tmp;

        if (got < 0) {
            if (errno == EINTR) {
                continue;
            }
            free(raw);
            close(fd);
            return ECMP_ERR_NETWORK;
        }
        if (got == 0) {
            break;
        }
        if (raw_len + (size_t) got > raw_cap) {
            size_t new_cap = raw_cap == 0 ? 4096 : raw_cap * 2;
            while (new_cap < raw_len + (size_t) got) {
                new_cap *= 2;
            }
            tmp = realloc(raw, new_cap);
            if (tmp == NULL) {
                free(raw);
                close(fd);
                return ECMP_ERR_ALLOC;
            }
            raw = tmp;
            raw_cap = new_cap;
        }
        memcpy(raw + raw_len, chunk, (size_t) got);
        raw_len += (size_t) got;
    }
    close(fd);

    if (raw == NULL || raw_len < 4) {
        free(raw);
        return ECMP_ERR_HTTP;
    }

    {
        unsigned char *tmp = realloc(raw, raw_len + 1);
        if (tmp == NULL) {
            free(raw);
            return ECMP_ERR_ALLOC;
        }
        raw = tmp;
        raw[raw_len] = '\0';
    }

    /* The CMP payload starts after the HTTP header terminator. */
    hdr_end = (const unsigned char *) strstr((const char *) raw, "\r\n\r\n");
    if (hdr_end == NULL) {
        free(raw);
        return ECMP_ERR_HTTP;
    }
    body = hdr_end + 4;

    /* Keep the transport strict: reject HTTP responses that are not labeled as CMP. */
    if (strstr((const char *) raw, "\r\nContent-Type: application/pkixcmp\r\n") == NULL &&
        strstr((const char *) raw, "\r\ncontent-type: application/pkixcmp\r\n") == NULL) {
        free(raw);
        return ECMP_ERR_HTTP;
    }

    *response_len = raw_len - (size_t) (body - raw);
    *response = calloc(1, *response_len);
    if (*response == NULL) {
        free(raw);
        return ECMP_ERR_ALLOC;
    }
    memcpy(*response, body, *response_len);
    free(raw);
    return 0;
}

int ecmp_http_transport_init(ecmp_transport *transport, const char *host,
                             const char *port, const char *path)
{
    ecmp_http_ctx *ctx;

    /* Install the HTTP vtable so the CMP layer can remain transport-neutral. */
    if (transport == NULL || host == NULL || port == NULL || path == NULL) {
        return ECMP_ERR_PARAM;
    }

    memset(transport, 0, sizeof(*transport));
    ctx = calloc(1, sizeof(*ctx));
    if (ctx == NULL) {
        return ECMP_ERR_ALLOC;
    }

    ctx->host = ecmp_http_strdup(host);
    ctx->port = ecmp_http_strdup(port);
    ctx->path = ecmp_http_strdup(path);
    if (ctx->host == NULL || ctx->port == NULL || ctx->path == NULL) {
        ecmp_http_free_ctx(ctx);
        return ECMP_ERR_ALLOC;
    }

    transport->ctx = ctx;
    transport->free_ctx = ecmp_http_free_ctx;
    transport->send_receive = ecmp_http_send_receive;
    return 0;
}

void ecmp_transport_free(ecmp_transport *transport)
{
    if (transport == NULL) {
        return;
    }
    if (transport->free_ctx != NULL) {
        transport->free_ctx(transport->ctx);
    }
    memset(transport, 0, sizeof(*transport));
}
