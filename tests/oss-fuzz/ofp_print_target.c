#include <config.h>
#include "fuzzer.h"
#include "dp-packet.h"
#include "openvswitch/ofp-print.h"
#include "openvswitch/ofpbuf.h"
#include "openvswitch/vlog.h"

int
LLVMFuzzerTestOneInput(const uint8_t *data, size_t size)
{
    if (size < sizeof(struct ofp_header)) {
        return 0;
    }

    static bool isInit = false;
    if (!isInit) {
        vlog_set_verbosity("off");
        isInit = true;
    }

    struct ofpbuf b;
    ofpbuf_use_const(&b, data, size);
    for (;;) {
        /* Check if ofpbuf contains ofp header. */
        struct ofp_header *oh = ofpbuf_at(&b, 0, sizeof *oh);
        if (!oh) {
            break;
        }

        /* Check if length is geq than lower bound. */
        size_t length = ntohs(oh->length);
        if (length < sizeof *oh) {
            break;
        }

        /* Check if ofpbuf contains payload. */
        size_t tail_len = length - sizeof *oh;
        void *tail = ofpbuf_at(&b, sizeof *oh, tail_len);
        if (!tail) {
            break;
        }

        ofp_print(stdout, ofpbuf_pull(&b, length), length, NULL, NULL, 2);
    }
    ofpbuf_uninit(&b);
    return 0;
}
