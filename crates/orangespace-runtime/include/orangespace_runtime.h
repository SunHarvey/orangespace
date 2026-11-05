#ifndef ORANGESPACE_RUNTIME_H
#define ORANGESPACE_RUNTIME_H
#include <stddef.h>
#include <stdint.h>
#ifdef __cplusplus
extern "C" {
#endif
#define OS_RUNTIME_BUFFER_CAPACITY 65536u
#define OS_RUNTIME_JSON_SCHEMA 2u
#define OS_RUNTIME_LOCAL_CHANNEL_CAPACITY 4096u
#define OS_RUNTIME_LOCAL_PROXY_SOCKS 0u
#define OS_RUNTIME_LOCAL_PROXY_AUTHENTICATED_MIXED 1u
#define OS_RUNTIME_ERROR_INVALID (-1)
#define OS_RUNTIME_ERROR_CAPACITY (-2)
#define OS_RUNTIME_ERROR_HANDLE (-3)
#define OS_RUNTIME_ERROR_FAILED_CLOSED (-4)
/* PRIVATE in-process SCM ABI, NOT public IPC. Service authenticates/authorizes
 * the complete binding and supplies only an authenticated node API lease.
 * BEFORE new: verify pinned helper hash, immutable protected executable,
 * ancestors/dependencies/trust roots for entire handle lifetime. This API does
 * not verify Windows ACLs. Never accept a caller-selected executable over IPC.
 * UTF-8 absolute path bytes, no terminator. timeout_ms in [1,30000].
 * Opaque token: never dereference; free is idempotent; tokens are never reused.
 * All operations on one runtime (including free) serialize internally; service
 * must also serialize authorization/start/close and fail closed on errors.
 * Caller owns all byte ranges and guarantees they are valid for each call.
 */
void* os_runtime_new(const uint8_t* path, size_t path_len, uint32_t timeout_ms);
/* Explicit private-CA variant: ca is 1..65536 UTF-8 PEM bytes, copied at
 * construction; only protected static catalog CA for the bound node is allowed.
 * No path/UI/lease/control-response trust; no insecure/system-trust fallback.
 * One runtime must remain confined to that catalog node for its lifetime.
 * Legacy os_runtime_new remains unchanged (normal default TLS verification).
 */
void* os_runtime_new_with_ca_v1(const uint8_t* path, size_t path_len,
    uint32_t timeout_ms, const uint8_t* ca, size_t ca_len);
/* Immutable trusted protocol selection: 0 SOCKS (legacy), 1 authenticated
 * HTTP/CONNECT + SOCKS on the SAME loopback port. Others reject with NULL.
 * ca=NULL,ca_len=0 uses normal TLS roots; otherwise same strict CA contract.
 * Selection is NOT accepted from lease/start JSON; set_system_proxy=false.
 * All legacy constructors/start wrappers remain SOCKS by default.
 */
void* os_runtime_new_with_local_proxy_v1(const uint8_t* path, size_t path_len,
    uint32_t start_timeout_ms, const uint8_t* ca, size_t ca_len, uint32_t protocol);
/* Dedicated Service-private credential handoff, NEVER general IPC/status.
 * Input is ONLY the five-field full tuple (no schema/wrapper/unknown fields).
 * Canonical nonzero UUID strings (unescaped), exact integer generation.
 * capacity >=4096 BEFORE work; input 1..4096; no partial output on any error.
 * Positive JSON byte count, no NUL; same negative error constants as call.
 * Full output and ownership contract: ../tests/local_channel_README.md.
 * Output: {schema:2,binding,host:"127.0.0.1",port,username,password,clock,
 *   request_started_ms,remaining_ttl_ms,deadline_ms,proof_observed_at_ms}.
 * The original start grant's clock/anchor/TTL/deadline NEVER reset or renew.
 * Requires exact live binding, live owned helper, unexpired original grant,
 * successful historical forwarding proof <3000ms old. A failed probe clears
 * proof eligibility. Only one successful take per binding; errors/short output
 * do not consume. Retains independent internal credentials for subsequent proof.
 * Complete guarded serialization and final liveness/deadline fence precede
 * one-time consumption/copy under the runtime lock. Caller owns successful
 * output, MUST scrub after delivery, and MUST independently authenticate the
 * Service, OS peer/root and complete instance-bound IPC authorization. This ABI
 * grants neither Node authentication nor browser/WFP authorization. No TUIC/CA
 * bytes appear here. No secret-bearing JSON DOM/heap output buffer is created.
 */
int32_t os_runtime_take_local_channel_v1(void* handle,
    const uint8_t* binding_json, size_t binding_len, uint8_t* out, size_t capacity);
/* capacity MUST be >= OS_RUNTIME_BUFFER_CAPACITY before ANY side effects.
 * Request max 65536 bytes. Return positive UTF-8 JSON length (no NUL), or a
 * negative generic error above; no partial output on error. No size-query call.
 * JSON dispatch schema 2 is mandatory on EVERY operation; old/missing schema
 * is rejected without work or fallback. C function signatures are unchanged.
 * start: {"schema":2,"op":"start","binding":<exact tuple>,
 *         "lease":<exact 17-field node lease_schema:2 lease>,"budget":<budget>}
 * close: {"schema":2,"op":"close","binding":<exact tuple>}
 * poll: {"schema":2,"op":"poll"}
 * tuple: {user_id,sandbox_id,node_id,generation,tunnel_id}.
 * budget (exactly four fields): {"clock":<platform clock name>,
 *   "request_started_ms":m0,"remaining_ttl_ms":ttl,"deadline_ms":D}.
 * Windows clock: "windows-gettickcount64-ms-v1" (GetTickCount64).
 * Linux clock: "linux-clock-monotonic-ms-v1" (CLOCK_MONOTONIC, floor ms).
 * Timing integers must be exact, nonnegative and <=9007199254740991;
 * ttl in [1,30000], D == checked(m0+ttl), m0<=now<D. Start's budget ttl
 * must equal lease.remaining_ttl_ms. Preserve the actual POST's m0 and D:
 * queueing, FFI, proof and active polls never restart the lease budget.
 * start response: {"ok":bool,"binding":{...},"process_started":bool,
 *   "tunnel_authenticated":bool,"forwarding_verified":bool,"running":bool,
 *   "pid":number|null,"socks_port":number|null}.
 * tunnel_authenticated requires authenticated node proof through actual TUIC;
 * a local SOCKS handshake alone never establishes it. Only verified forwarding
 * permits running=true. Proof failure kills/reaps before ok=false response.
 * close: {"ok":true,"binding":{...},"running":false}.
 * renew: {"schema":2,"op":"renew","binding":<exact tuple>,
 *         "expires_at":number,"budget":<original renewal budget>}.
 * Service must first obtain and validate a successful node API renewal. Only a
 * still-live exact binding whose OLD common-clock deadline is unexpired may
 * renew. Expiry regression is rejected. Effective D <= min(new D, old D +
 * checked((new server expiry - old server expiry)*1000)); equal expiry cannot
 * extend. Recheck after polling; no wall-derived lifetime or revival.
 * Returns {ok:true,binding,expires_at}, never a new proof.
 * poll: {"ok":true,"exited":[{"binding":{...},"pid":number}]}.
 * Poll periodically to reap exits/expire leases. Service must revoke on error
 * or returned exit, and must not treat any response as a browser permit.
 * Never return local SOCKS credentials or probe/TUIC/API secrets to UI/IPC.
 * Free waits for in-flight calls, invalidates token, drops supervisor/children.
 * No Rust unwind crosses these functions (allocation abort/invalid C memory
 * cannot be recovered). Input/output buffers must not overlap.
 */
int32_t os_runtime_call(void* handle, const uint8_t* request, size_t len,
                        uint8_t* out, size_t capacity);
void os_runtime_free(void* handle);
#ifdef __cplusplus
}
#endif
#endif
