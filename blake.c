#include <stdint.h>
#include <string.h>
#include <assert.h>
#include "blake.h"

static const uint32_t   blake2b_block_len = 128;
static const uint32_t   blake2b_rounds = 12;
static const uint64_t   blake2b_iv[8] =
{
    0x6a09e667f3bcc908ULL, 0xbb67ae8584caa73bULL,
    0x3c6ef372fe94f82bULL, 0xa54ff53a5f1d36f1ULL,
    0x510e527fade682d1ULL, 0x9b05688c2b3e6c1fULL,
    0x1f83d9abfb41bd6bULL, 0x5be0cd19137e2179ULL,
};
static const uint8_t    blake2b_sigma[12][16] =
{
      {  0,  1,  2,  3,  4,  5,  6,  7,  8,  9, 10, 11, 12, 13, 14, 15 },
      { 14, 10,  4,  8,  9, 15, 13,  6,  1, 12,  0,  2, 11,  7,  5,  3 },
      { 11,  8, 12,  0,  5,  2, 15, 13, 10, 14,  3,  6,  7,  1,  9,  4 },
      {  7,  9,  3,  1, 13, 12, 11, 14,  2,  6,  5, 10,  4,  0, 15,  8 },
      {  9,  0,  5,  7,  2,  4, 10, 15, 14,  1, 11, 12,  6,  8,  3, 13 },
      {  2, 12,  6, 10,  0, 11,  8,  3,  4, 13,  7,  5, 15, 14,  1,  9 },
      { 12,  5,  1, 15, 14, 13,  4, 10,  0,  7,  6,  3,  9,  2,  8, 11 },
      { 13, 11,  7, 14, 12,  1,  3,  9,  5,  0, 15,  4,  8,  6,  2, 10 },
      {  6, 15, 14,  9, 11,  3,  0,  8, 12,  2, 13,  7,  1,  4, 10,  5 },
      { 10,  2,  8,  4,  7,  6,  1,  5, 15, 11,  9, 14,  3, 12, 13,  0 },
      {  0,  1,  2,  3,  4,  5,  6,  7,  8,  9, 10, 11, 12, 13, 14, 15 },
      { 14, 10,  4,  8,  9, 15, 13,  6,  1, 12,  0,  2, 11,  7,  5,  3 },
};

/*
** Init the state according to Zcash parameters.
*/
void zcash_blake2b_init(blake2b_state_t *st, uint8_t hash_len,
	uint32_t n, uint32_t k)
{
    assert(n > k);
    assert(hash_len <= 64);
    st->h[0] = blake2b_iv[0] ^ (0x01010000 | hash_len);
        st->h[1] = blake2b_iv[1];
	st->h[2] = blake2b_iv[2];
	st->h[3] = blake2b_iv[3];
	st->h[4] = blake2b_iv[4];
	st->h[5] = blake2b_iv[5];
    st->h[6] = blake2b_iv[6] ^ *(uint64_t *)"ZcashPoW";
    st->h[7] = blake2b_iv[7] ^ (((uint64_t)k << 32) | n);
    st->bytes = 0;
}

static uint64_t rotr64(uint64_t a, uint8_t bits)
{
    return (a >> bits) | (a << (64 - bits));
}

static void mix(uint64_t *va, uint64_t *vb, uint64_t *vc, uint64_t *vd,
        uint64_t x, uint64_t y)
{
    *va = (*va + *vb + x);
    *vd = rotr64(*vd ^ *va, 32);
    *vc = (*vc + *vd);
    *vb = rotr64(*vb ^ *vc, 24);
    *va = (*va + *vb + y);
    *vd = rotr64(*vd ^ *va, 16);
    *vc = (*vc + *vd);
    *vb = rotr64(*vb ^ *vc, 63);
}

/*
** Process either a full message block or the final partial block.
** Note that v[13] is not XOR'd because st->bytes is assumed to never overflow.
**
** _msg         pointer to message (must be zero-padded to 128 bytes if final block)
** msg_len      must be 128 (<= 128 allowed only for final partial block)
** is_final     indicate if this is the final block
*/
void zcash_blake2b_update(blake2b_state_t *st, const uint8_t *_msg,
        uint32_t msg_len, uint32_t is_final)
{
    const uint64_t      *m = (const uint64_t *)_msg;
    uint64_t            v[16];
    assert(msg_len <= 128);
    assert(st->bytes <= UINT64_MAX - msg_len);
    memcpy(v + 0, st->h, 8 * sizeof (*v));
    memcpy(v + 8, blake2b_iv, 8 * sizeof (*v));
    v[12] ^= (st->bytes += msg_len);
    v[14] ^= is_final ? -1 : 0;

const uint8_t   *s0 = blake2b_sigma[0];
        mix(v + 0, v + 4, v + 8,  v + 12, m[s0[0]],  m[s0[1]]);
        mix(v + 1, v + 5, v + 9,  v + 13, m[s0[2]],  m[s0[3]]);
        mix(v + 2, v + 6, v + 10, v + 14, m[s0[4]],  m[s0[5]]);
        mix(v + 3, v + 7, v + 11, v + 15, m[s0[6]],  m[s0[7]]);
        mix(v + 0, v + 5, v + 10, v + 15, m[s0[8]],  m[s0[9]]);
        mix(v + 1, v + 6, v + 11, v + 12, m[s0[10]], m[s0[11]]);
        mix(v + 2, v + 7, v + 8,  v + 13, m[s0[12]], m[s0[13]]);
        mix(v + 3, v + 4, v + 9,  v + 14, m[s0[14]], m[s0[15]]);

const uint8_t   *s1 = blake2b_sigma[1];
        mix(v + 0, v + 4, v + 8,  v + 12, m[s1[0]],  m[s1[1]]);
        mix(v + 1, v + 5, v + 9,  v + 13, m[s1[2]],  m[s1[3]]);
        mix(v + 2, v + 6, v + 10, v + 14, m[s1[4]],  m[s1[5]]);
        mix(v + 3, v + 7, v + 11, v + 15, m[s1[6]],  m[s1[7]]);
        mix(v + 0, v + 5, v + 10, v + 15, m[s1[8]],  m[s1[9]]);
        mix(v + 1, v + 6, v + 11, v + 12, m[s1[10]], m[s1[11]]);
        mix(v + 2, v + 7, v + 8,  v + 13, m[s1[12]], m[s1[13]]);
        mix(v + 3, v + 4, v + 9,  v + 14, m[s1[14]], m[s1[15]]);

const uint8_t   *s2 = blake2b_sigma[2];
        mix(v + 0, v + 4, v + 8,  v + 12, m[s2[0]],  m[s2[1]]);
        mix(v + 1, v + 5, v + 9,  v + 13, m[s2[2]],  m[s2[3]]);
        mix(v + 2, v + 6, v + 10, v + 14, m[s2[4]],  m[s2[5]]);
        mix(v + 3, v + 7, v + 11, v + 15, m[s2[6]],  m[s2[7]]);
        mix(v + 0, v + 5, v + 10, v + 15, m[s2[8]],  m[s2[9]]);
        mix(v + 1, v + 6, v + 11, v + 12, m[s2[10]], m[s2[11]]);
        mix(v + 2, v + 7, v + 8,  v + 13, m[s2[12]], m[s2[13]]);
        mix(v + 3, v + 4, v + 9,  v + 14, m[s2[14]], m[s2[15]]);

const uint8_t   *s3 = blake2b_sigma[3];
        mix(v + 0, v + 4, v + 8,  v + 12, m[s3[0]],  m[s3[1]]);
        mix(v + 1, v + 5, v + 9,  v + 13, m[s3[2]],  m[s3[3]]);
        mix(v + 2, v + 6, v + 10, v + 14, m[s3[4]],  m[s3[5]]);
        mix(v + 3, v + 7, v + 11, v + 15, m[s3[6]],  m[s3[7]]);
        mix(v + 0, v + 5, v + 10, v + 15, m[s3[8]],  m[s3[9]]);
        mix(v + 1, v + 6, v + 11, v + 12, m[s3[10]], m[s3[11]]);
        mix(v + 2, v + 7, v + 8,  v + 13, m[s3[12]], m[s3[13]]);
        mix(v + 3, v + 4, v + 9,  v + 14, m[s3[14]], m[s3[15]]);

const uint8_t   *s4 = blake2b_sigma[4];
        mix(v + 0, v + 4, v + 8,  v + 12, m[s4[0]],  m[s4[1]]);
        mix(v + 1, v + 5, v + 9,  v + 13, m[s4[2]],  m[s4[3]]);
        mix(v + 2, v + 6, v + 10, v + 14, m[s4[4]],  m[s4[5]]);
        mix(v + 3, v + 7, v + 11, v + 15, m[s4[6]],  m[s4[7]]);
        mix(v + 0, v + 5, v + 10, v + 15, m[s4[8]],  m[s4[9]]);
        mix(v + 1, v + 6, v + 11, v + 12, m[s4[10]], m[s4[11]]);
        mix(v + 2, v + 7, v + 8,  v + 13, m[s4[12]], m[s4[13]]);
        mix(v + 3, v + 4, v + 9,  v + 14, m[s4[14]], m[s4[15]]);

const uint8_t   *s5 = blake2b_sigma[5];
        mix(v + 0, v + 4, v + 8,  v + 12, m[s5[0]],  m[s5[1]]);
        mix(v + 1, v + 5, v + 9,  v + 13, m[s5[2]],  m[s5[3]]);
        mix(v + 2, v + 6, v + 10, v + 14, m[s5[4]],  m[s5[5]]);
        mix(v + 3, v + 7, v + 11, v + 15, m[s5[6]],  m[s5[7]]);
        mix(v + 0, v + 5, v + 10, v + 15, m[s5[8]],  m[s5[9]]);
        mix(v + 1, v + 6, v + 11, v + 12, m[s5[10]], m[s5[11]]);
        mix(v + 2, v + 7, v + 8,  v + 13, m[s5[12]], m[s5[13]]);
        mix(v + 3, v + 4, v + 9,  v + 14, m[s5[14]], m[s5[15]]);

const uint8_t   *s6 = blake2b_sigma[6];
        mix(v + 0, v + 4, v + 8,  v + 12, m[s6[0]],  m[s6[1]]);
        mix(v + 1, v + 5, v + 9,  v + 13, m[s6[2]],  m[s6[3]]);
        mix(v + 2, v + 6, v + 10, v + 14, m[s6[4]],  m[s6[5]]);
        mix(v + 3, v + 7, v + 11, v + 15, m[s6[6]],  m[s6[7]]);
        mix(v + 0, v + 5, v + 10, v + 15, m[s6[8]],  m[s6[9]]);
        mix(v + 1, v + 6, v + 11, v + 12, m[s6[10]], m[s6[11]]);
        mix(v + 2, v + 7, v + 8,  v + 13, m[s6[12]], m[s6[13]]);
        mix(v + 3, v + 4, v + 9,  v + 14, m[s6[14]], m[s6[15]]);

const uint8_t   *s7 = blake2b_sigma[7];
        mix(v + 0, v + 4, v + 8,  v + 12, m[s7[0]],  m[s7[1]]);
        mix(v + 1, v + 5, v + 9,  v + 13, m[s7[2]],  m[s7[3]]);
        mix(v + 2, v + 6, v + 10, v + 14, m[s7[4]],  m[s7[5]]);
        mix(v + 3, v + 7, v + 11, v + 15, m[s7[6]],  m[s7[7]]);
        mix(v + 0, v + 5, v + 10, v + 15, m[s7[8]],  m[s7[9]]);
        mix(v + 1, v + 6, v + 11, v + 12, m[s7[10]], m[s7[11]]);
        mix(v + 2, v + 7, v + 8,  v + 13, m[s7[12]], m[s7[13]]);
        mix(v + 3, v + 4, v + 9,  v + 14, m[s7[14]], m[s7[15]]);

const uint8_t   *s8 = blake2b_sigma[8];
        mix(v + 0, v + 4, v + 8,  v + 12, m[s8[0]],  m[s8[1]]);
        mix(v + 1, v + 5, v + 9,  v + 13, m[s8[2]],  m[s8[3]]);
        mix(v + 2, v + 6, v + 10, v + 14, m[s8[4]],  m[s8[5]]);
        mix(v + 3, v + 7, v + 11, v + 15, m[s8[6]],  m[s8[7]]);
        mix(v + 0, v + 5, v + 10, v + 15, m[s8[8]],  m[s8[9]]);
        mix(v + 1, v + 6, v + 11, v + 12, m[s8[10]], m[s8[11]]);
        mix(v + 2, v + 7, v + 8,  v + 13, m[s8[12]], m[s8[13]]);
        mix(v + 3, v + 4, v + 9,  v + 14, m[s8[14]], m[s8[15]]);

const uint8_t   *s9 = blake2b_sigma[9];
        mix(v + 0, v + 4, v + 8,  v + 12, m[s9[0]],  m[s9[1]]);
        mix(v + 1, v + 5, v + 9,  v + 13, m[s9[2]],  m[s9[3]]);
        mix(v + 2, v + 6, v + 10, v + 14, m[s9[4]],  m[s9[5]]);
        mix(v + 3, v + 7, v + 11, v + 15, m[s9[6]],  m[s9[7]]);
        mix(v + 0, v + 5, v + 10, v + 15, m[s9[8]],  m[s9[9]]);
        mix(v + 1, v + 6, v + 11, v + 12, m[s9[10]], m[s9[11]]);
        mix(v + 2, v + 7, v + 8,  v + 13, m[s9[12]], m[s9[13]]);
        mix(v + 3, v + 4, v + 9,  v + 14, m[s9[14]], m[s9[15]]);

const uint8_t   *s10 = blake2b_sigma[10];
        mix(v + 0, v + 4, v + 8,  v + 12, m[s10[0]],  m[s10[1]]);
        mix(v + 1, v + 5, v + 9,  v + 13, m[s10[2]],  m[s10[3]]);
        mix(v + 2, v + 6, v + 10, v + 14, m[s10[4]],  m[s10[5]]);
        mix(v + 3, v + 7, v + 11, v + 15, m[s10[6]],  m[s10[7]]);
        mix(v + 0, v + 5, v + 10, v + 15, m[s10[8]],  m[s10[9]]);
        mix(v + 1, v + 6, v + 11, v + 12, m[s10[10]], m[s10[11]]);
        mix(v + 2, v + 7, v + 8,  v + 13, m[s10[12]], m[s10[13]]);
        mix(v + 3, v + 4, v + 9,  v + 14, m[s10[14]], m[s10[15]]);

const uint8_t   *s11 = blake2b_sigma[11];
        mix(v + 0, v + 4, v + 8,  v + 12, m[s11[0]],  m[s11[1]]);
        mix(v + 1, v + 5, v + 9,  v + 13, m[s11[2]],  m[s11[3]]);
        mix(v + 2, v + 6, v + 10, v + 14, m[s11[4]],  m[s11[5]]);
        mix(v + 3, v + 7, v + 11, v + 15, m[s11[6]],  m[s11[7]]);
        mix(v + 0, v + 5, v + 10, v + 15, m[s11[8]],  m[s11[9]]);
        mix(v + 1, v + 6, v + 11, v + 12, m[s11[10]], m[s11[11]]);
        mix(v + 2, v + 7, v + 8,  v + 13, m[s11[12]], m[s11[13]]);
        mix(v + 3, v + 4, v + 9,  v + 14, m[s11[14]], m[s11[15]]);

        st->h[0] ^= v[0] ^ v[8];
	st->h[1] ^= v[1] ^ v[9];
	st->h[2] ^= v[2] ^ v[10];
	st->h[3] ^= v[3] ^ v[11];
	st->h[4] ^= v[4] ^ v[12];
	st->h[5] ^= v[5] ^ v[13];
	st->h[6] ^= v[6] ^ v[14];
	st->h[7] ^= v[7] ^ v[15];
}

void zcash_blake2b_final(blake2b_state_t *st, uint8_t *out, uint8_t outlen)
{
    assert(outlen <= 64);
    memcpy(out, st->h, outlen);
}
