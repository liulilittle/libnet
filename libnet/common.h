#pragma once

#include <stdint.h>

#pragma pack(push, 1)
typedef uint32_t                    __in4_addr__;
typedef struct {
    union {
        uint8_t                     byte_bin[16];
        uint16_t                    word_bin[8];
    } u;
}                                   __in6_addr__;
typedef struct {
    int                             bv6;
    __in4_addr__                    in4;
    __in6_addr__                    in6;
}                                   __in_addr__;
#pragma pack(pop)