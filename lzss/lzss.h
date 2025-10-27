#ifndef LZSS_H
#define LZSS_H

#include <stdint.h>

#ifdef __cplusplus
extern "C" {
#endif

// Decode LZSS-compressed data.
// dst: preallocated output buffer
// src: input buffer
// srclen: length of input data
// Returns: number of bytes written to dst, or -1 on failure
int lzss_decode(uint8_t *dst, const uint8_t *src, uint32_t srclen);

// Encode raw data into LZSS.
// dst: preallocated output buffer
// dstlen: maximum size of dst
// src: input buffer
// srclen: size of input data
// Returns: pointer to end of written data (dst + bytes_written), or NULL if failed
uint8_t *lzss_encode(uint8_t *dst, uint32_t dstlen, const uint8_t *src, uint32_t srclen);

#ifdef __cplusplus
}
#endif

#endif // LZSS_H
