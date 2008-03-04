#ifndef XTOXLL_H
#define XTOXLL_H 1

#include <arpa/inet.h>
#include <sys/types.h>

static inline uint64_t
htonll(uint64_t n)
{
    return htonl(1) == 1 ? n : ((uint64_t) htonl(n) << 32) | htonl(n >> 32);
}

static inline uint64_t
ntohll(uint64_t n)
{
    return htonl(1) == 1 ? n : ((uint64_t) ntohl(n) << 32) | ntohl(n >> 32);
}

#endif /* xtonll.h */
