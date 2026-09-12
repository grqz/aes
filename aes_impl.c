#ifndef AES_IMPL_C_
#define AES_IMPL_C_

#define AES128_NR 10
#define AES128_NK 4

#define AES192_NR 12
#define AES192_NK 6

#define AES256_NR 14
#define AES256_NK 8

#include <stdint.h>
typedef uint8_t u8;
typedef u8 aes_state[16];
typedef u8 aes_word[4];
#ifndef GF_API
#define GF_API static inline
#endif
#ifndef AES_CORE_API
#define AES_CORE_API static inline
#endif
#define AES_IDX(r,c) ((r)+((c)<<2))

GF_API
u8 gf_2x(u8 b) {
    return b << 1 ^ (0x1b & -(b >> 7));
}

GF_API
u8 gf_mul(u8 b, u8 c) {
    u8 tbl[7];
    tbl[0] = gf_2x(b);
    tbl[1] = gf_2x(tbl[0]);
    tbl[2] = gf_2x(tbl[1]);
    tbl[3] = gf_2x(tbl[2]);
    tbl[4] = gf_2x(tbl[3]);
    tbl[5] = gf_2x(tbl[4]);
    tbl[6] = gf_2x(tbl[5]);

    return (-(c & 1) & b)
        ^ (-(c >> 1 & 1) & tbl[0])
        ^ (-(c >> 2 & 1) & tbl[1])
        ^ (-(c >> 3 & 1) & tbl[2])
        ^ (-(c >> 4 & 1) & tbl[3])
        ^ (-(c >> 5 & 1) & tbl[4])
        ^ (-(c >> 6 & 1) & tbl[5])
        ^ (-(c >> 7 & 1) & tbl[6]);
}

GF_API
u8 gf_tilde(u8 b) {
    /* shortest addition chain, see tmp/tape.py */
    u8 s[10];
    s[0] = gf_mul(b, b);  // 2
    s[1] = gf_mul(s[0], s[0]);  // 4
    s[2] = gf_mul(s[1], s[1]);  // 8
    s[3] = gf_mul(s[2], s[2]);  // 16
    s[4] = gf_mul(s[3], s[3]);  // 32
    s[5] = gf_mul(s[4], s[4]);  // 64
    s[6] = gf_mul(s[5], s[3]);  // 80
    s[7] = gf_mul(s[6], s[1]);  // 84
    s[8] = gf_mul(s[7], s[7]);  // 168
    s[9] = gf_mul(s[8], s[0]);  // 170
    return gf_mul(s[9], s[7]);  // 254
}

AES_CORE_API
u8 aes_sbox(u8 b) {
    b = gf_tilde(b);
    u8 b0 = b & 1,
       b1 = b >> 1 & 1,
       b2 = b >> 2 & 1,
       b3 = b >> 3 & 1,
       b4 = b >> 4 & 1,
       b5 = b >> 5 & 1,
       b6 = b >> 6 & 1,
       b7 = b >> 7 & 1;
    return (
        (b0 ^ b4 ^ b5 ^ b6 ^ b7)
        | (b0 ^ b1 ^ b5 ^ b6 ^ b7) << 1
        | (b0 ^ b1 ^ b2 ^ b6 ^ b7) << 2
        | (b0 ^ b1 ^ b2 ^ b3 ^ b7) << 3
        | (b0 ^ b1 ^ b2 ^ b3 ^ b4) << 4
        | (b1 ^ b2 ^ b3 ^ b4 ^ b5) << 5
        | (b2 ^ b3 ^ b4 ^ b5 ^ b6) << 6
        | (b3 ^ b4 ^ b5 ^ b6 ^ b7) << 7) ^ 0x63;
}

/*
 * The standard did not mathematically define invsbox.
 * ** b0 b1 b2 b3 b4 b5 b6 b7
 * B0  1  0  0  0  1  1  1  1
 * B1  1  1  0  0  0  1  1  1
 * B2  1  1  1  0  0  0  1  1
 * B3  1  1  1  1  0  0  0  1
 * B4  1  1  1  1  1  0  0  0
 * B5  0  1  1  1  1  1  0  0
 * B6  0  0  1  1  1  1  1  0
 * B7  0  0  0  1  1  1  1  1
 *
 * see tmp/invsbox.c
 * B6 B4 B1 = b7
 * B5 B3 B0 = b6
 * B7 B4 B2 = b5
 * B6 B3 B1 = b4
 * B5 B2 B0 = b3
 * B7 B4 B1 = b2
 * B6 B3 B0 = b1
 * B7 B5 B2 = b0
 */
AES_CORE_API
u8 aes_invsbox(u8 b) {
    b ^= 0x63;
    u8 b0 = b & 1,
       b1 = b >> 1 & 1,
       b2 = b >> 2 & 1,
       b3 = b >> 3 & 1,
       b4 = b >> 4 & 1,
       b5 = b >> 5 & 1,
       b6 = b >> 6 & 1,
       b7 = b >> 7 & 1;
    return gf_tilde(
        (b2 ^ b5 ^ b7)
        | (b0 ^ b3 ^ b6) << 1
        | (b1 ^ b4 ^ b7) << 2
        | (b0 ^ b2 ^ b5) << 3
        | (b1 ^ b3 ^ b6) << 4
        | (b2 ^ b4 ^ b7) << 5
        | (b0 ^ b3 ^ b5) << 6
        | (b1 ^ b4 ^ b6) << 7);
}

AES_CORE_API
void aes_rotword(aes_word *w) {
    u8 tmp = (*w)[0];

    (*w)[0] = (*w)[1];
    (*w)[1] = (*w)[2];
    (*w)[2] = (*w)[3];
    (*w)[3] = tmp;
}

AES_CORE_API
void aes_subword(aes_word *w) {
    (*w)[0x0] = aes_sbox((*w)[0x0]);
    (*w)[0x1] = aes_sbox((*w)[0x1]);
    (*w)[0x2] = aes_sbox((*w)[0x2]);
    (*w)[0x3] = aes_sbox((*w)[0x3]);
}

AES_CORE_API
void aes_subbytes(aes_state *s) {
    (*s)[0x0] = aes_sbox((*s)[0x0]);
    (*s)[0x1] = aes_sbox((*s)[0x1]);
    (*s)[0x2] = aes_sbox((*s)[0x2]);
    (*s)[0x3] = aes_sbox((*s)[0x3]);
    (*s)[0x4] = aes_sbox((*s)[0x4]);
    (*s)[0x5] = aes_sbox((*s)[0x5]);
    (*s)[0x6] = aes_sbox((*s)[0x6]);
    (*s)[0x7] = aes_sbox((*s)[0x7]);
    (*s)[0x8] = aes_sbox((*s)[0x8]);
    (*s)[0x9] = aes_sbox((*s)[0x9]);
    (*s)[0xa] = aes_sbox((*s)[0xa]);
    (*s)[0xb] = aes_sbox((*s)[0xb]);
    (*s)[0xc] = aes_sbox((*s)[0xc]);
    (*s)[0xd] = aes_sbox((*s)[0xd]);
    (*s)[0xe] = aes_sbox((*s)[0xe]);
    (*s)[0xf] = aes_sbox((*s)[0xf]);
}

AES_CORE_API
void aes_invsubbytes(aes_state *s) {
    (*s)[0x0] = aes_invsbox((*s)[0x0]);
    (*s)[0x1] = aes_invsbox((*s)[0x1]);
    (*s)[0x2] = aes_invsbox((*s)[0x2]);
    (*s)[0x3] = aes_invsbox((*s)[0x3]);
    (*s)[0x4] = aes_invsbox((*s)[0x4]);
    (*s)[0x5] = aes_invsbox((*s)[0x5]);
    (*s)[0x6] = aes_invsbox((*s)[0x6]);
    (*s)[0x7] = aes_invsbox((*s)[0x7]);
    (*s)[0x8] = aes_invsbox((*s)[0x8]);
    (*s)[0x9] = aes_invsbox((*s)[0x9]);
    (*s)[0xa] = aes_invsbox((*s)[0xa]);
    (*s)[0xb] = aes_invsbox((*s)[0xb]);
    (*s)[0xc] = aes_invsbox((*s)[0xc]);
    (*s)[0xd] = aes_invsbox((*s)[0xd]);
    (*s)[0xe] = aes_invsbox((*s)[0xe]);
    (*s)[0xf] = aes_invsbox((*s)[0xf]);
}

AES_CORE_API
void aes_shiftrows(aes_state *s) {
    u8 tmp0, tmp1;
    /* iteration r=0 modifies nothing */

    /* iteration r=1 */
    tmp0 = (*s)[AES_IDX(1, 0)];

    (*s)[AES_IDX(1, 0)] = (*s)[AES_IDX(1, 1)];
    (*s)[AES_IDX(1, 1)] = (*s)[AES_IDX(1, 2)];
    (*s)[AES_IDX(1, 2)] = (*s)[AES_IDX(1, 3)];
    (*s)[AES_IDX(1, 3)] = tmp0;

    /* iteration r=2 */
    tmp0 = (*s)[AES_IDX(2, 0)];
    tmp1 = (*s)[AES_IDX(2, 1)];

    (*s)[AES_IDX(2, 0)] = (*s)[AES_IDX(2, 2)];
    (*s)[AES_IDX(2, 1)] = (*s)[AES_IDX(2, 3)];
    (*s)[AES_IDX(2, 2)] = tmp0;
    (*s)[AES_IDX(2, 3)] = tmp1;

    /* iteration r=3 */
    tmp0 = (*s)[AES_IDX(3, 3)];

    (*s)[AES_IDX(3, 3)] = (*s)[AES_IDX(3, 2)];
    (*s)[AES_IDX(3, 2)] = (*s)[AES_IDX(3, 1)];
    (*s)[AES_IDX(3, 1)] = (*s)[AES_IDX(3, 0)];
    (*s)[AES_IDX(3, 0)] = tmp0;
}

AES_CORE_API
void aes_invshiftrows(aes_state *s) {
    u8 tmp0, tmp1;
    /* iteration r=0 modifies nothing */

    /* iteration r=1 */
    tmp0 = (*s)[AES_IDX(1, 3)];

    (*s)[AES_IDX(1, 3)] = (*s)[AES_IDX(1, 2)];
    (*s)[AES_IDX(1, 2)] = (*s)[AES_IDX(1, 1)];
    (*s)[AES_IDX(1, 1)] = (*s)[AES_IDX(1, 0)];
    (*s)[AES_IDX(1, 0)] = tmp0;

    /* iteration r=2 */
    tmp0 = (*s)[AES_IDX(2, 0)];
    tmp1 = (*s)[AES_IDX(2, 1)];

    (*s)[AES_IDX(2, 0)] = (*s)[AES_IDX(2, 2)];
    (*s)[AES_IDX(2, 1)] = (*s)[AES_IDX(2, 3)];
    (*s)[AES_IDX(2, 2)] = tmp0;
    (*s)[AES_IDX(2, 3)] = tmp1;

    /* iteration r=3 */
    tmp0 = (*s)[AES_IDX(3, 0)];

    (*s)[AES_IDX(3, 0)] = (*s)[AES_IDX(3, 1)];
    (*s)[AES_IDX(3, 1)] = (*s)[AES_IDX(3, 2)];
    (*s)[AES_IDX(3, 2)] = (*s)[AES_IDX(3, 3)];
    (*s)[AES_IDX(3, 3)] = tmp0;
}

AES_CORE_API
void aes_mixcolumns(aes_state *s) {
    u8 b0, b1, b2, b3, s2b0, s2b1, s2b2, s2b3;
#define MC0(c)                                         \
    b0 = (*s)[AES_IDX(0, c)];                          \
    b1 = (*s)[AES_IDX(1, c)];                          \
    b2 = (*s)[AES_IDX(2, c)];                          \
    b3 = (*s)[AES_IDX(3, c)];                          \
                                                       \
    s2b0 = gf_2x(b0);                                  \
    s2b1 = gf_2x(b1);                                  \
    s2b2 = gf_2x(b2);                                  \
    s2b3 = gf_2x(b3);                                  \
                                                       \
    (*s)[AES_IDX(0, c)] = b1 ^ b2 ^ b3 ^ s2b0 ^ s2b1;  \
    (*s)[AES_IDX(1, c)] = b0 ^ b2 ^ b3 ^ s2b1 ^ s2b2;  \
    (*s)[AES_IDX(2, c)] = b0 ^ b1 ^ b3 ^ s2b2 ^ s2b3;  \
    (*s)[AES_IDX(3, c)] = b0 ^ b1 ^ b2 ^ s2b0 ^ s2b3;

    MC0(0)
    MC0(1)
    MC0(2)
    MC0(3)
}

AES_CORE_API
void aes_invmixcolumns(aes_state *s) {
    u8 b0, b1, b2, b3,
       b0x2, b1x2, b2x2, b3x2,
       b0x4, b1x4, b2x4, b3x4,
       b0x8, b1x8, b2x8, b3x8,
       base;
#define IMC(c)                                                             \
    b0 = (*s)[AES_IDX(0, c)];                                              \
    b1 = (*s)[AES_IDX(1, c)];                                              \
    b2 = (*s)[AES_IDX(2, c)];                                              \
    b3 = (*s)[AES_IDX(3, c)];                                              \
                                                                           \
    b0x2 = gf_2x(b0);                                                      \
    b1x2 = gf_2x(b1);                                                      \
    b2x2 = gf_2x(b2);                                                      \
    b3x2 = gf_2x(b3);                                                      \
                                                                           \
    b0x4 = gf_2x(b0x2);                                                    \
    b1x4 = gf_2x(b1x2);                                                    \
    b2x4 = gf_2x(b2x2);                                                    \
    b3x4 = gf_2x(b3x2);                                                    \
                                                                           \
    b0x8 = gf_2x(b0x4);                                                    \
    b1x8 = gf_2x(b1x4);                                                    \
    b2x8 = gf_2x(b2x4);                                                    \
    b3x8 = gf_2x(b3x4);                                                    \
                                                                           \
    base = b0x8 ^ b1x8 ^ b2x8 ^ b3x8;                                      \
    (*s)[AES_IDX(0, c)] = b1 ^ b2 ^ b3 ^ b0x2 ^ b1x2 ^ b0x4 ^ b2x4 ^ base; \
    (*s)[AES_IDX(1, c)] = b0 ^ b2 ^ b3 ^ b1x2 ^ b2x2 ^ b1x4 ^ b3x4 ^ base; \
    (*s)[AES_IDX(2, c)] = b0 ^ b1 ^ b3 ^ b2x2 ^ b3x2 ^ b0x4 ^ b2x4 ^ base; \
    (*s)[AES_IDX(3, c)] = b0 ^ b1 ^ b2 ^ b0x2 ^ b3x2 ^ b1x4 ^ b3x4 ^ base;
    IMC(0)
    IMC(1)
    IMC(2)
    IMC(3)
}

AES_CORE_API
void aes_addroundkey(aes_state *s, const u8 * restrict pw, u8 r) {
    /* iteration c=0 */
    (*s)[AES_IDX(0, 0)] ^= pw[r << 4];
    (*s)[AES_IDX(1, 0)] ^= pw[r << 4 | 0x1];
    (*s)[AES_IDX(2, 0)] ^= pw[r << 4 | 0x2];
    (*s)[AES_IDX(3, 0)] ^= pw[r << 4 | 0x3];

    /* iteration c=1 */
    (*s)[AES_IDX(0, 1)] ^= pw[r << 4 | 0x4];
    (*s)[AES_IDX(1, 1)] ^= pw[r << 4 | 0x5];
    (*s)[AES_IDX(2, 1)] ^= pw[r << 4 | 0x6];
    (*s)[AES_IDX(3, 1)] ^= pw[r << 4 | 0x7];

    /* iteration c=2 */
    (*s)[AES_IDX(0, 2)] ^= pw[r << 4 | 0x8];
    (*s)[AES_IDX(1, 2)] ^= pw[r << 4 | 0x9];
    (*s)[AES_IDX(2, 2)] ^= pw[r << 4 | 0xa];
    (*s)[AES_IDX(3, 2)] ^= pw[r << 4 | 0xb];

    /* iteration c=3 */
    (*s)[AES_IDX(0, 3)] ^= pw[r << 4 | 0xc];
    (*s)[AES_IDX(1, 3)] ^= pw[r << 4 | 0xd];
    (*s)[AES_IDX(2, 3)] ^= pw[r << 4 | 0xe];
    (*s)[AES_IDX(3, 3)] ^= pw[r << 4 | 0xf];
}
#endif

#ifdef AES_IMPL
#define AES_DECL AES_IMPL
#endif

#ifdef AES_DECL
#ifdef AES_API
#define AES_API_ AES_API
#else
#define AES_API_
#endif

#define CAT4_(a,b,c,d) a##b##c##d
#define CAT4(a,b,c,d) CAT4_(a,b,c,d)
#define AES_NR CAT4(AES,AES_DECL,_NR,)
#define AES_NK CAT4(AES,AES_DECL,_NK,)
#define AES_ID(fn) CAT4(aes,AES_DECL,_,fn)
typedef u8 AES_ID(exkey)[(AES_NR + 1) << 4];
typedef u8 AES_ID(key)[AES_NK << 2];
AES_API_
void AES_ID(keyexpansion)(AES_ID(exkey) * restrict w, AES_ID(key) const * restrict k);
AES_API_
void AES_ID(cipher)(aes_state * restrict state, AES_ID(exkey) const * restrict w);
AES_API_
void AES_ID(invcipher)(aes_state * restrict state, AES_ID(exkey) const * restrict w);
#undef CAT4_
#undef CAT4
#undef AES_NR
#undef AES_NK
#undef AES_ID
#undef AES_API_
#endif

#ifdef AES_IMPL

#ifdef AES_API
#define AES_API_ AES_API
#else
#define AES_API_
#endif

#define CAT4_(a,b,c,d) a##b##c##d
#define CAT4(a,b,c,d) CAT4_(a,b,c,d)
#define AES_NR CAT4(AES,AES_IMPL,_NR,)
#define AES_NK CAT4(AES,AES_IMPL,_NK,)
#define AES_ID(fn) CAT4(aes,AES_IMPL,_,fn)
#if (((AES_NR + 1) << 2) / AES_NK) > 8
#define AES_RCON
#endif

AES_API_
void AES_ID(keyexpansion)(AES_ID(exkey) * restrict w, AES_ID(key) const * restrict k) {
    u8 i;
    aes_word temp;
#ifdef AES_RCON
    u8 rcon[10] = {1,2,4,8,16,32,64,128,0x1b,0x36};
#endif
    for (i = 0; i < AES_NK; ++i) {
        (*w)[i << 2] = (*k)[i << 2];
        (*w)[i << 2 | 1] = (*k)[i << 2 | 1];
        (*w)[i << 2 | 2] = (*k)[i << 2 | 2];
        (*w)[i << 2 | 3] = (*k)[i << 2 | 3];
    }

    temp[0] = (*w)[(i - 1) << 2];
    temp[1] = (*w)[(i - 1) << 2 | 1];
    temp[2] = (*w)[(i - 1) << 2 | 2];
    temp[3] = (*w)[(i - 1) << 2 | 3];

    for (; i < (AES_NR + 1) << 2; ++i) {
        u8 divi;
        u8 modi;

        divi = i / AES_NK;
        modi = i % AES_NK;
        if (!modi) {
            aes_rotword(&temp);
            aes_subword(&temp);
            temp[0] ^= (
#ifdef AES_RCON
                rcon[divi - 1]);
#else
                1 << (divi - 1));
#endif
        }
#if AES_NK > 6
        else if (modi == 4) {
            aes_subword(&temp);
        }
#endif
        temp[0] ^= (*w)[(i - AES_NK) << 2];
        temp[1] ^= (*w)[(i - AES_NK) << 2 | 1];
        temp[2] ^= (*w)[(i - AES_NK) << 2 | 2];
        temp[3] ^= (*w)[(i - AES_NK) << 2 | 3];

        (*w)[i << 2] = temp[0];
        (*w)[i << 2 | 1] = temp[1];
        (*w)[i << 2 | 2] = temp[2];
        (*w)[i << 2 | 3] = temp[3];
    }
}

AES_API_
void AES_ID(cipher)(aes_state * restrict state, AES_ID(exkey) const * restrict w) {
    u8 round;
    u8 const *xk = *w;
    aes_addroundkey(state, xk, 0);
    for (round = 1; round < AES_NR; ++round) {
        aes_subbytes(state);
        aes_shiftrows(state);
        aes_mixcolumns(state);
        aes_addroundkey(state, xk, round);
    }

    aes_subbytes(state);
    aes_shiftrows(state);
    aes_addroundkey(state, xk, AES_NR);
}

AES_API_
void AES_ID(invcipher)(aes_state * restrict state, AES_ID(exkey) const * restrict w) {
    u8 round = AES_NR;
    u8 const *xk = *w;
    aes_addroundkey(state, xk, round--);
    while (round) {
        aes_invshiftrows(state);
        aes_invsubbytes(state);
        aes_addroundkey(state, xk, round--);
        aes_invmixcolumns(state);
    }
    aes_invshiftrows(state);
    aes_invsubbytes(state);
    aes_addroundkey(state, xk, round);
}

#undef CAT4_
#undef CAT4
#undef AES_NR
#undef AES_NK
#undef AES_ID
#undef AES_IMPL
#undef AES_RCON
#undef AES_API_
#endif
