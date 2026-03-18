#ifndef ECMP_ERROR_H
#define ECMP_ERROR_H

#ifdef __cplusplus
extern "C" {
#endif

#define ECMP_OK (0)

#define ECMP_ERR_PARAM (-0x1000)
#define ECMP_ERR_ALLOC (-0x1001)
#define ECMP_ERR_CRYPTO (-0x1002)
#define ECMP_ERR_ASN1 (-0x1003)
#define ECMP_ERR_PROTOCOL (-0x1004)
#define ECMP_ERR_TRANSPORT (-0x1005)
#define ECMP_ERR_SERVER_REJECTED (-0x1006)
#define ECMP_ERR_UNSUPPORTED (-0x1007)
#define ECMP_ERR_IO (-0x1008)
#define ECMP_ERR_HTTP (-0x1009)
#define ECMP_ERR_NETWORK (-0x100A)
#define ECMP_ERR_CRYPTO_BACKEND (-0x100B)

#ifdef __cplusplus
}
#endif

#endif
