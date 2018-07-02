#include "flow.h"
#include "dp-packet.h"

int LLVMFuzzerTestOneInput(const uint8_t* data, size_t size)
{
    struct dp_packet packet;
    struct flow flow;

    dp_packet_use_const(&packet, data, size);
    flow_extract(&packet, &flow);
    return 0;
}
