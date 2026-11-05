/* Linux static-link ABI smoke; fixture only, not a production runtime CLI. */
#include "orangespace_runtime.h"
#include <assert.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

int main(int argc, char **argv) {
    assert(argc == 2); /* caller supplies the protected, verified fixture helper */
    void *handle = os_runtime_new((const uint8_t *)argv[1], strlen(argv[1]), 100);
    assert(handle != NULL);
    uint8_t *out = (uint8_t *)malloc(OS_RUNTIME_BUFFER_CAPACITY);
    assert(out != NULL);
    memset(out, 0x55, OS_RUNTIME_BUFFER_CAPACITY);
    const uint8_t request[] = "{\"schema\":2,\"op\":\"poll\"}";
    assert(OS_RUNTIME_JSON_SCHEMA == 2u);
    const uint8_t legacy[] = "{\"op\":\"poll\"}";
    const uint8_t old_schema[] = "{\"schema\":1,\"op\":\"poll\"}";
    assert(os_runtime_call(handle, legacy, sizeof(legacy)-1, out,
                           OS_RUNTIME_BUFFER_CAPACITY) == OS_RUNTIME_ERROR_INVALID);
    assert(out[0] == 0x55);
    assert(os_runtime_call(handle, old_schema, sizeof(old_schema)-1, out,
                           OS_RUNTIME_BUFFER_CAPACITY) == OS_RUNTIME_ERROR_INVALID);
    assert(out[0] == 0x55);
    assert(os_runtime_call(handle, request, sizeof(request)-1, out,
                           OS_RUNTIME_BUFFER_CAPACITY-1) == OS_RUNTIME_ERROR_CAPACITY);
    assert(out[0] == 0x55);
    int32_t size = os_runtime_call(handle, request, sizeof(request)-1, out,
                                   OS_RUNTIME_BUFFER_CAPACITY);
    const char expected[] = "{\"exited\":[],\"ok\":true}";
    assert(size == (int32_t)(sizeof(expected)-1));
    assert(memcmp(out, expected, (size_t)size) == 0);
    os_runtime_free(handle);
    os_runtime_free(handle);
    assert(os_runtime_call(handle, request, sizeof(request)-1, out,
                           OS_RUNTIME_BUFFER_CAPACITY) == OS_RUNTIME_ERROR_HANDLE);
    os_runtime_free(NULL);
    free(out);
    puts("C ABI static-link smoke passed: new/poll/preflight/free/stale handle");
    return 0;
}
