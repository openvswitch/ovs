#ifndef IP_H
#define IP_H 1

#define IP_FMT "%"PRIu8".%"PRIu8".%"PRIu8".%"PRIu8
#define IP_ARGS(ip)                             \
        ((uint8_t *) ip)[0],                    \
        ((uint8_t *) ip)[1],                    \
        ((uint8_t *) ip)[2],                    \
        ((uint8_t *) ip)[3]

#endif /* ip.h */
