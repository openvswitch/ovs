#ifndef OFP_VERSION_H
#define OFP_VERSION_H 1

#include <openflow/openflow-common.h>
#include "util.h"

#define OFP_VERSION_LONG_OPTIONS                                \
        {"version",     no_argument, NULL, 'V'},                \
        {"protocols", required_argument, NULL, 'O'}

#define OFP_VERSION_OPTION_HANDLERS                             \
        case 'V':                                               \
            ovs_print_version(OFP10_VERSION, OFP14_VERSION);    \
            exit(EXIT_SUCCESS);                                 \
                                                                \
        case 'O':                                               \
            set_allowed_ofp_versions(optarg);                   \
            break;

uint32_t get_allowed_ofp_versions(void);
void set_allowed_ofp_versions(const char *string);
void mask_allowed_ofp_versions(uint32_t);
void add_allowed_ofp_versions(uint32_t);
void ofp_version_usage(void);

#endif
