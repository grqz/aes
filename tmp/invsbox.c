#include <stdio.h>
#include <stdint.h>
typedef uint8_t u8;
u8 f_2x(u8 b) {
    return b << 1 | b >> 7;
}

u8 f_mul(u8 b, u8 c) {
    u8 tbl[7];
    tbl[0] = f_2x(b);
    tbl[1] = f_2x(tbl[0]);
    tbl[2] = f_2x(tbl[1]);
    tbl[3] = f_2x(tbl[2]);
    tbl[4] = f_2x(tbl[3]);
    tbl[5] = f_2x(tbl[4]);
    tbl[6] = f_2x(tbl[5]);

    b = c & 0x01 ? b : 0;
    if (c & 0x2)
        b ^= tbl[0];
    if (c & 0x4)
        b ^= tbl[1];
    if (c & 0x8)
        b ^= tbl[2];
    if (c & 0x10)
        b ^= tbl[3];
    if (c & 0x20)
        b ^= tbl[4];
    if (c & 0x40)
        b ^= tbl[5];
    if (c & 0x80)
        b ^= tbl[6];
    return b;
}

u8 f_recip(u8 b) {
    u8 s[3];
    s[0] = f_mul(b, b);  // 2
    s[1] = f_mul(s[0], s[0]);  // 4
    s[2] = f_mul(s[0], s[1]);  // 6
    return f_mul(s[2], b);  // 7
}

int main(void) {
    u8 res = f_recip(31);
    int i, j;
    for (i = 0; i < 8; i++, res = f_2x(res)) {
        for (j = 0; j < 8; j++) {
            if (res >> j & 1) {
                printf("B%d ", 7-j);
            }
        }
        printf("= b%d\n", 7-i);
    }
}
