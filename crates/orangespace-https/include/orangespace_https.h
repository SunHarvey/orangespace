#ifndef ORANGESPACE_HTTPS_V1_H
#define ORANGESPACE_HTTPS_V1_H
#include <stddef.h>
#include <stdint.h>
#ifdef __cplusplus
extern "C" {
#endif
#define OS_HTTPS_MAX_RESPONSE ((size_t)1048576)
#define OS_HTTPS_ERROR ((int32_t)-1)
/* Not NUL terminated; ptr may be NULL iff len is zero. Borrowed, never retained. */
typedef struct OsHttpsBytes { const uint8_t *ptr; size_t len; } OsHttpsBytes;
typedef struct OsHttpsRequest {
    OsHttpsBytes origin;  /* strict https://authority, no trailing /, userinfo/query/fragment */
    OsHttpsBytes ca_pem;  /* app-owned CA bytes only; no filename or system roots */
    OsHttpsBytes method;  /* GET, POST, DELETE only */
    OsHttpsBytes path;    /* / path; only canonical GET node-list pagination query allowed */
    OsHttpsBytes body;    /* opaque JSON bytes; <=16384; caller owns JSON/schema validation */
    OsHttpsBytes bearer;  /* empty or exactly 43 ASCII URL-safe token characters */
} OsHttpsRequest;
/*
 * One synchronous HTTPS request, global 5-second network deadline. No redirects,
 * retries, cookies, environment proxies, system roots, or verification bypass.
 * All pointers must be valid/aligned; buffers, scalars and inputs MUST NOT overlap.
 * out != NULL, outcap >= OS_HTTPS_MAX_RESPONSE; status/headerLen != NULL.
 * nodeHeader != NULL requires headercap >=64. Optional NULL/0 discards the header,
 * but still validates it and returns its byte length through headerLen.
 * No size-query mode. On success returns body length (including for 4xx/5xx),
 * writes status, body and an optional unique X-OrangeSpace-Node (0..64 ASCII
 * [A-Za-z0-9_.-] bytes). Missing node header is allowed for centre endpoints.
 * Outputs are raw bytes, NOT NUL terminated. Bytes beyond returned lengths remain
 * unchanged. On ANY error returns OS_HTTPS_ERROR and leaves ALL outputs unchanged.
 * Malformed pointers/overlaps are caller UB, not discoverable by this API.
 * Unwinding Rust panics are contained; no error text/body/token is returned/logged
 * by this crate. Allocation failure/abort is not recoverable.
 * Requests carry fixed X-OrangeSpace-Lease-Schema: 2 protocol metadata.
 * Except 204, replies must have one JSON Content-Type (same guard as WinHTTP).
 */
int32_t os_https_request_v1(const OsHttpsRequest *request, uint8_t *out, size_t outcap,
                          uint32_t *status, uint8_t *nodeHeader, size_t headercap,
                          uint32_t *headerLen);
#ifdef __cplusplus
}
#endif
#endif
