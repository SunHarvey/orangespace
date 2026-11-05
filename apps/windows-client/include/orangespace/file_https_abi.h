#ifndef ORANGESPACE_FILE_HTTPS_ABI_H
#define ORANGESPACE_FILE_HTTPS_ABI_H
#include <stddef.h>
#include <stdint.h>
#include "../../../../crates/orangespace-https/include/orangespace_https.h"
#ifdef __cplusplus
extern "C" {
#endif
typedef struct OsHttpsTransferRequest {
    OsHttpsBytes origin, ca_pem, method, path, bearer, expected_node;
    uint64_t upload_size;
    void *context;
    int64_t (*read)(void *, uint8_t *, size_t);
    int32_t (*write)(void *, const uint8_t *, size_t);
    int32_t (*cancelled)(void *);
} OsHttpsTransferRequest;
/* Synchronous, borrowed pointers; all input/output allocations disjoint and valid.
 * Callbacks run on calling thread, must not throw/unwind or block indefinitely.
 * read: 0 EOF, negative error, otherwise <=cap; write: 0 accepted, nonzero error;
 * cancelled: 0 continue, nonzero cancel. write/cancelled required; read required
 * for PUT/POST (including empty upload), NULL for GET; GET upload_size must be 0.
 * Callbacks receive at most 65536 bytes. Upload is exactly upload_size bytes;
 * one final read(cap=1) MUST return EOF (extra input rejects completion).
 * GET /v1/files[?path=<encoded-relative-path>] or /v1/files/<encoded-path>: 200.
 * PUT /v1/files/<encoded-path>[?overwrite=true|false]: raw body, 201.
 * POST /v1/directories: JSON body via read, 201 (caller validates schema).
 * Protected /nodes/<canonical expected_node> prefix is also supported exactly;
 * another node's prefix or an arbitrary mount prefix is rejected.
 * Path UTF-8 must be percent encoded; no dot segments, controls, backslash,
 * fragment, absolute path/query tricks; literal '/' separates path components.
 * Strict Rustls app-private ca_pem required, no system roots/proxy/redirect/retry.
 * Unique exact X-OrangeSpace-Node required on EVERY reply, including HTTP errors.
 * Successful replies require one Content-Type: octet-stream for file download;
 * application/json (optional exact charset=utf-8) for list/mkdir/upload commit.
 * Media-type rejection occurs before any response write callback.
 * status is initialized to 0, then exposes received HTTP status even on error.
 * total initialized UINT64_MAX, then response Content-Length (unknown if absent).
 * Return 0 ONLY for complete authenticated expected-status response; -1 for all
 * errors/cancellation, without delivering HTTP error bodies or raw error text.
 * Response bytes are provisional: caller MUST discard partial output on -1.
 * 30s maximum network stall, 1h overall budget; cancellation checked surrounding
 * each callback and before success. Cannot preempt a blocking caller callback.
 * Existing os_https_request_v1 ABI/behavior is unchanged.
 */
int32_t os_https_transfer_v1(const OsHttpsTransferRequest *, uint32_t *status, uint64_t *total);
#ifdef __cplusplus
}
#endif
#endif
