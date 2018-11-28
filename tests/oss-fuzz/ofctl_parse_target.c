#include <config.h>
#include "fuzzer.h"
#include "openvswitch/ofp-flow.h"
#include "ofp-version-opt.h"
#include "ofproto/ofproto.h"
#include "openflow/openflow.h"
#include "openvswitch/ofpbuf.h"
#include "openvswitch/vlog.h"
#include "util.h"

static void
ofctl_parse_flows__(struct ofputil_flow_mod *fms, size_t n_fms,
                    enum ofputil_protocol usable_protocols)
{
    enum ofputil_protocol protocol = 0;
    char *usable_s;
    size_t i;

    usable_s = ofputil_protocols_to_string(usable_protocols);
    printf("usable protocols: %s\n", usable_s);
    free(usable_s);

    if (!(usable_protocols & OFPUTIL_P_ANY)) {
        printf("no usable protocol\n");
        goto free;
    }
    for (i = 0; i < sizeof(enum ofputil_protocol) * CHAR_BIT; i++) {
        protocol = 1u << i;
        if (protocol & usable_protocols & OFPUTIL_P_ANY) {
            break;
        }
    }
    ovs_assert(is_pow2(protocol));

    printf("chosen protocol: %s\n", ofputil_protocol_to_string(protocol));

    for (i = 0; i < n_fms; i++) {
        struct ofputil_flow_mod *fm = &fms[i];
        struct ofpbuf *msg;

        msg = ofputil_encode_flow_mod(fm, protocol);
        ofpbuf_delete(msg);
    }

free:
    for (i = 0; i < n_fms; i++) {
        struct ofputil_flow_mod *fm = &fms[i];
        free(CONST_CAST(struct ofpact *, fm->ofpacts));
        minimatch_destroy(&fm->match);
    }
}

/* "parse-flow FLOW": parses the argument as a flow (like add-flow) and prints
 * it back to stdout.  */
static void
ofctl_parse_flow(const char *input, int command)
{
    enum ofputil_protocol usable_protocols;
    struct ofputil_flow_mod fm;
    char *error;

    error = parse_ofp_flow_mod_str(&fm, input, NULL, NULL,
                                   command, &usable_protocols);
    if (error) {
        printf("Error encountered: %s\n", error);
        free(error);
    } else {
        ofctl_parse_flows__(&fm, 1, usable_protocols);
    }
}

int
LLVMFuzzerTestOneInput(const uint8_t *data, size_t size)
{
    /* Bail out if we cannot construct at least a 1 char string.
     * Reserve 1 byte to decide flow mod command.
     *
     * Here's the structure of data we expect
     * |--Byte 1--|--Byte 2--|...|--Byte (size-1)--|
     *
     * where,
     *
     * Byte 1: Used to decide which ofp flow mod command to test
     * Bytes 2--(size-1): The C string that is actually passed to
     *                    ofctl_parse_flow() test API.
     *
     * This means that the fuzzed input is actually a C string of
     * length = (size -2) with the terminal byte being the NUL
     * character. Moreover, this string is expected to not contain
     * a new-line character.
     */
    const char *stream = (const char *) data;
    if (size < 3 || stream[size - 1] != '\0' || strchr(&stream[1], '\n') ||
        strlen(&stream[1]) != size - 2) {
        return 0;
    }

    /* Disable logging to avoid write to disk. */
    static bool isInit = false;
    if (!isInit) {
        vlog_set_verbosity("off");
        isInit = true;
    }

    /* Decide test parameters using first byte of fuzzed input. */
    int command = (stream[0] % OFPFC_DELETE_STRICT) + 1;

    /* Fuzz extended match parsing. */
    const char *input = &stream[1];
    ofctl_parse_flow(input, command);

    return 0;
}
