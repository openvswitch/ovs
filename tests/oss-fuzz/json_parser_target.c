#include <config.h>
#include "fuzzer.h"
#include "jsonrpc.h"
#include "openvswitch/json.h"
#include "ovsdb-error.h"
#include "ovsdb/table.h"
#include <assert.h>
#include <string.h>

int
LLVMFuzzerTestOneInput(const uint8_t *data, size_t size)
{
    if (!size || data[size - 1]) {
        return 0;
    }

    struct json *j1 = json_from_string((const char *)data);
    if (j1->type == JSON_STRING) {
        json_destroy(j1);
        return 0;
    }

    free(json_to_string(j1, JSSF_SORT | JSSF_PRETTY));

    struct jsonrpc_msg *msg;
    char *error = jsonrpc_msg_from_json(j1, &msg); /* Frees 'j1'. */
    if (error) {
        free(error);
        return 0;
    }

    struct json *j2 = jsonrpc_msg_to_json(msg); /* Frees 'msg'. */
    if (j2->type == JSON_STRING) {
        json_destroy(j2);
        return 0;
    }

    free(json_to_string(j2, JSSF_SORT | JSSF_PRETTY));
    json_destroy(j2);

    return 0;
}
