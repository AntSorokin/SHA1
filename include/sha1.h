#include <stdint.h>

#ifndef SHA1_H
#define SHA1_H
/*
    Produces the SHA1 message digest of buf found using method 2 of RFC 3174 section 6
    @param H message diges of buf
    @param buf buffer to produce sha1 digest from
    @param length byte length of buffer
    @warning The length of buf should be at least 9 bytes smaller than the max of uint64_t
*/
void sha1_message_digest(uint32_t H[5], const uint8_t* buf, uint64_t length);
#endif 