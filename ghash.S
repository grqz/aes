BITS 64
section .text

global aes_ghash
global aes256_keyexpansion_aesni
global aes256_keyexpansion_aesni_32
global aes256_cipher_aesni
global aes256_ctr_vy
global aes256_ctr_vy128

%macro Trap 0
%ifndef NDEBUG
    int3
%endif
%endmacro

%ifdef WIN64
%macro WIN_SAVEX 2
    movdqa [rsp + (%1)], %2
%endmacro
%macro WIN_LOADX 2
    movdqa %2, [rsp + (%1)]
%endmacro
%macro WIN_PROLOGUE 1
    sub rsp, %1
%endmacro
%macro WIN_EPILOGUE 1
    add rsp, %1
%endmacro
%define P0 rcx
%define P1 rdx
%define P2 r8
%define P3 r9
%else
%macro WIN_SAVEX 2
%endmacro
%macro WIN_LOADX 2
%endmacro
%macro WIN_PROLOGUE 1
%endmacro
%macro WIN_EPILOGUE 1
%endmacro
%define P0 rdi
%define P1 rsi
%define P2 rdx
%define P3 rcx
%endif

; P0 *subkey R:16B align 16
; P1 *data W:16B R:<16*len>B align 16
; P2 r64 len
; @func r64 (r64 r64 r64)
; calling convention: win x64-ish
; return rax
; scratch
;     xmm0 xmm1 xmm2 xmm3
;     xmm4 xmm5 xmm6
;     rax r10 r11
; no shadow space/redzone/stack alignment
; benchmark (7 blocks):
; P-core: 37.402ns
; E-core: 52.722ns
aes_ghash:
    xor eax, eax
    test P2, P2
    jz .errout
    movdqa xmm6, [rel affine_mat]

    WIN_SAVEX 8, xmm6
    movdqa xmm1, [P0]
    mov P3, 0x87
    xorps xmm0, xmm0
    gf2p8affineqb xmm1, xmm6, 0
    movq xmm5, P3

    ; we may use:
    ; xmm0..xmm6 incl
    ; rax P0..3
    mov P3, P1

.loophead:
    movdqa xmm2, [P1]
    gf2p8affineqb xmm2, xmm6, 0
        add P1, 0x10
    xorps xmm2, xmm0

    ; perform xmm0 = blockproduct(xmm1, xmm2)
    ; reduction constant 0xe1 in xmm5

    vpclmullqlqdq xmm0, xmm1, xmm2

    ; for some reason we have both lqhq and hqlq
    vpclmullqhqdq xmm3, xmm1, xmm2
        vpclmulhqlqdq xmm4, xmm1, xmm2
            pclmulhqhqdq xmm2, xmm1
        xorps xmm3, xmm4

    vpslldq xmm4, xmm3, 8
        psrldq xmm3, 8
    xorps xmm0, xmm4
            xorps xmm2, xmm3

    ; now we have:
    ; xmm0 = lower half to be combined with xmm2 reduced
    ; xmm1 = subkey, dont touch
    ; xmm2 = higher half to be reduced
    ; xmm5 = reduction constant, only has lq

    vpclmullqlqdq xmm3, xmm2, xmm5  ; TODO: reduce only once
        pclmulhqlqdq xmm2, xmm5
                xorps xmm0, xmm3
            vpslldq xmm4, xmm2, 8
                xorps xmm0, xmm4
        pclmulhqlqdq xmm2, xmm5
    ; just a 8bx8b, xmm2 should be 16b or less

    inc rax
    dec P2
        xorps xmm0, xmm2
    test P2, P2
    jnz .loophead

    gf2p8affineqb xmm0, xmm6, 0
    movdqa [P3], xmm0
    WIN_LOADX 8, xmm6
.errout:
    ret

; P0 *kexp RW:240B align 16
; P1 *key R:32B align 16
; @func void (r64 r64)
; calling convention: win x64-ish
; scratch
;     xmm0 xmm1 xmm2 xmm3
;     xmm4 xmm5
;     rax r10 r11
; no shadow space/redzone/stack alignment
; benchmark: (for some reason the E-core is faster)
; P-core: 47.552ns
; E-core: 21.263ns
aes256_keyexpansion_aesni:
                movdqa xmm0, [P1 + 0x10]
            movdqa xmm1, [P1]
                movdqa [P0 + 0x10], xmm0
            movdqa [P0], xmm1
%define OFFSET 0x20
%define RCON 1
%rep 7
    vpslldq xmm2, xmm1, 4
        vpslldq xmm3, xmm1, 8
            vpslldq xmm4, xmm1, 0xc
    pxor xmm2, xmm1
        pxor xmm3, xmm4
        pxor xmm2, xmm3
                    aeskeygenassist xmm1, xmm0, RCON
                    pshufd xmm1, xmm1, 0b11111111  ; X3 rotsubxor
                    pxor xmm1, xmm2
                        movdqa [P0 + OFFSET], xmm1

    %assign OFFSET OFFSET + 0x10
    %assign RCON RCON << 1
    %if OFFSET >= 0xf0 || RCON & 0x80
        %exitrep
    %endif

    vpslldq xmm2, xmm0, 4
        vpslldq xmm3, xmm0, 8
            vpslldq xmm4, xmm0, 0xc
    pxor xmm2, xmm0
        pxor xmm3, xmm4
        pxor xmm2, xmm3
                    aeskeygenassist xmm0, xmm1, 0  ; X3 sub
                    pshufd xmm0, xmm0, 0b10101010
                    pxor xmm0, xmm2
                    movdqa [P0 + OFFSET], xmm0

    %assign OFFSET OFFSET + 0x10
    %if OFFSET >= 0xf0
        %exitrep
    %endif
%endrep
%undef OFFSET
%undef RCON
    ret

; P0 *exk RW:480B align 32
; P1 *key R:32B align 16
; @func void (r64 r64)
; calling convention: win x64-ish
; scratch
;     xmm0 xmm1 xmm2 xmm3
;     xmm4 xmm5
;     rax r10 r11
; no shadow space/redzone/stack alignment
aes256_keyexpansion_aesni_32:
                movdqa xmm0, [P1 + 0x10]
            movdqa xmm1, [P1]
                movdqa [P0 + 0x20], xmm0
                movdqa [P0 + 0x30], xmm0
            movdqa [P0], xmm1
            movdqa [P0 + 0x10], xmm1
%define OFFSET 0x40
%define RCON 1
%rep 7
    vpslldq xmm2, xmm1, 4
        vpslldq xmm3, xmm1, 8
            vpslldq xmm4, xmm1, 0xc
    pxor xmm2, xmm1
        pxor xmm3, xmm4
        pxor xmm2, xmm3
                    aeskeygenassist xmm1, xmm0, RCON
                    pshufd xmm1, xmm1, 0b11111111  ; X3 rotsubxor
                    pxor xmm1, xmm2
                        movdqa [P0 + OFFSET], xmm1
                        movdqa [P0 + OFFSET + 0x10], xmm1

    %assign OFFSET OFFSET + 0x20
    %assign RCON RCON << 1
    %if OFFSET >= 0x1e0 || RCON & 0x80
        %exitrep
    %endif

    vpslldq xmm2, xmm0, 4
        vpslldq xmm3, xmm0, 8
            vpslldq xmm4, xmm0, 0xc
    pxor xmm2, xmm0
        pxor xmm3, xmm4
        pxor xmm2, xmm3
                    aeskeygenassist xmm0, xmm1, 0  ; X3 sub
                    pshufd xmm0, xmm0, 0b10101010
                    pxor xmm0, xmm2
                    movdqa [P0 + OFFSET], xmm0
                    movdqa [P0 + OFFSET + 0x10], xmm0

    %assign OFFSET OFFSET + 0x20
    %if OFFSET >= 0x1e0
        %exitrep
    %endif
%endrep
%undef OFFSET
%undef RCON
    ret


; P0 *state RW:16B align 16
; P1 *exk R:240B align 16
; @func void (r64 r64)
; calling convention: win x64-ish
; scratch
;     xmm0 xmm1 xmm2 xmm3
;     xmm4 xmm5
;     rax r10 r11
; no shadow space/redzone/stack alignment
aes256_cipher_aesni:
    movdqa xmm0, [P0]
    xorps xmm0, [P1]
%define OFFSET 0x10
%rep 13
    vaesenc xmm0, [P1 + OFFSET]
%assign OFFSET OFFSET+0x10
%endrep
    vaesenclast xmm0, [P1 + OFFSET]
%undef OFFSET
    movdqa [P0], xmm0
    ret

; P0 *exk R:480B align 16
; P1 *iv R:16B RW:32B align 32
; P2 *data RW:<32*len>B align 32
; P3 r64 len of data in 32B chunks
; Basic version, don't use.
; @func void (r64 r64 r64 r64)
; calling convention: win x64-ish
; scratch
;     ymm0 ymm1 ymm2 ymm3
;     ymm4 ymm5
;     rax r10 r11
; no shadow space/redzone/stack alignment
aes256_ctr_vy:
    vmovdqa xmm5, [rel beshufb]
    vinserti128 ymm5, ymm5, xmm5, 1
    vmovdqa xmm0, [P1]
    ; "expand" IV for vecorised AES

    ; calculate carry. this is simple because we are adding one
            pcmpeqw xmm2, xmm2
            vpcmpeqq xmm2, xmm2, xmm0
    pshufb xmm0, xmm5
        mov eax, 1
        mov r10, 2
            pslldq xmm2, 8
        movd xmm1, eax
        paddq xmm1, xmm0
        ; subtract mask = add carry
        psubq xmm1, xmm2
        vinserti128 ymm0, ymm0, xmm1, 1
        vmovdqa [P1], ymm0
        vpshufb ymm0, ymm0, ymm5
.back:
    vmovaps ymm1, [P0]
    vxorps ymm1, ymm1, ymm0
%define OFFSET 0x20
%rep 13
    vmovaps ymm0, [P0 + OFFSET]
    vaesenc ymm1, ymm0
%assign OFFSET OFFSET+0x20
%endrep
    vmovaps ymm0, [P0 + OFFSET]
    vaesenclast ymm1, ymm0
%undef OFFSET

    vxorps ymm1, [P2]
    vmovaps [P2], ymm1
    ; inc IV
        movq xmm1, r10
        vinserti128 ymm1, ymm1, xmm1, 1
    vmovdqa ymm0, [P1]
    vpaddq ymm0, ymm1
    ; carry when the low qword equals zero or one
    vpxor ymm1, ymm1, ymm1
        vpcmpeqw ymm2, ymm2, ymm2
        vpsrlq ymm2, 63
    vpcmpeqq ymm1, ymm1, ymm0
        vpcmpeqq ymm2, ymm2, ymm0
    vpor ymm1, ymm2
    vpslldq ymm1, ymm1, 8  ; discard carry from high q

    ; masks can be subtracted because x - (-1) = x + 1
    vpsubq ymm0, ymm1
    vmovdqa [P1], ymm0
    vpshufb ymm0, ymm5
    add P2, 0x20
    dec P3
    test P3, P3
    jnz .back

    vzeroupper
    ret

; AES-256-CTR crypt function operating in 128-byte blocks
; Slightly optimised.
; P0 *exk R:480B align 32
; P1 *iv R:16B RW:128B align 32
; P2 *data RW:<128*len>B align 32
; P3 r64 len
; @func void (r64 r64 r64 r64)
; calling convention: win x64-ish
; scratch
;     ymm0 ymm1 ymm2 ymm3
;     ymm4 ymm5 ymm6 ymm7
;     ymm8 ymm9 ymm10 ymm11
;     ymm12 ymm13 ymm14 ymm15
;     rax r10 r11
; no shadow space/redzone/stack alignment
; RegAlloc: (legacy -8 parallel 4 no spill volatile 0..10)
;     ymm0: RoundKey
;     ymm1..4: State & Temp
;     ymm5: dq -8, 0, -8, 0
;     ymm6..9: IV
;     ymm10: Shuffle mask
aes256_ctr_vy128:
    ; TODO: experiment with spilled IV 8 and vpcmpgtq
    vmovdqa xmm10, [rel beshufb]
    vinserti128 ymm10, ymm10, xmm10, 1
    vmovdqa xmm0, [P1]
    ; "expand" IV for vecorised AES

    ; calculate carry. this is simple because we are adding one
            vpcmpeqw ymm1, ymm1, ymm1  ; -1
            vpsrldq ymm1, ymm1, 8
            vpsllq ymm5, ymm1, 1  ; -2
    pshufb xmm0, xmm10
            vpcmpeqq xmm2, xmm0, xmm1
            pslldq xmm2, 8
        vpsubq xmm1, xmm0, xmm1
        ; subtract mask = add carry
        psubq xmm1, xmm2
        ; inserts are limited to pre-loop
        vinserti128 ymm6, ymm0, xmm1, 1
        vpshufb ymm1, ymm6, ymm10

    ; BEGIN: ymm1 = ymm0 + 2
        vpand ymm2, ymm6, ymm5
    vpsubq ymm7, ymm6, ymm5
        vpcmpeqq ymm2, ymm2, ymm5
        vpslldq ymm2, ymm2, 8  ; discard carry from high q
    vpsllq ymm5, ymm5, 1  ; -4
        ; masks can be subtracted because x - (-1) = x + 1
        vpsubq ymm7, ymm7, ymm2
    ; start +4
    vpand ymm3, ymm6, ymm5
        vpand ymm4, ymm7, ymm5
            vpsubq ymm8, ymm6, ymm5
                vpsubq ymm9, ymm7, ymm5
        ; don't shuffle in place, so that the value is ready for increment at
        ; the end of the loop
        vpshufb ymm2, ymm7, ymm10

    vpcmpeqq ymm3, ymm3, ymm5
        vpcmpeqq ymm4, ymm4, ymm5
    vpslldq ymm3, ymm3, 8
        vpslldq ymm4, ymm4, 8
            vpsllq ymm5, ymm5, 1  ; -8
    vpsubq ymm8, ymm8, ymm3
        vpsubq ymm9, ymm9, ymm4
    vpshufb ymm3, ymm8, ymm10
        vpshufb ymm4, ymm9, ymm10

.back:
    vmovaps ymm0, [P0]  ; load first round key
    vxorps ymm1, ymm1, ymm0
        vxorps ymm2, ymm2, ymm0
            vxorps ymm3, ymm3, ymm0
                vxorps ymm4, ymm4, ymm0
%define OFFSET 0x20
%rep 13
    vmovaps ymm0, [P0 + OFFSET]
    vaesenc ymm1, ymm1, ymm0
        vaesenc ymm2, ymm2, ymm0
            vaesenc ymm3, ymm3, ymm0
                vaesenc ymm4, ymm4, ymm0
%assign OFFSET OFFSET+0x20
%endrep
    vmovaps ymm0, [P0 + OFFSET]
    vaesenclast ymm1, ymm1, ymm0
        vaesenclast ymm2, ymm2, ymm0
            vaesenclast ymm3, ymm3, ymm0
                vaesenclast ymm4, ymm4, ymm0
%undef OFFSET

    vxorps ymm1, [P2]
        vxorps ymm2, [P2 + 0x20]
            vxorps ymm3, [P2 + 0x40]
                vxorps ymm4, [P2 + 0x60]
    vmovaps [P2], ymm1
        vmovaps [P2 + 0x20], ymm2
            vmovaps [P2 + 0x40], ymm3
                vmovaps [P2 + 0x60], ymm4

    ; inc IV
    ; BEGIN: ymm6..9 += ymm5 clobber 1..4
                    vpand ymm1, ymm6, ymm5
                        vpand ymm2, ymm7, ymm5
                            vpand ymm3, ymm8, ymm5
                                vpand ymm4, ymm9, ymm5
    vpsubq ymm6, ymm6, ymm5
        vpsubq ymm7, ymm7, ymm5
            vpsubq ymm8, ymm8, ymm5
                vpsubq ymm9, ymm9, ymm5
                    vpcmpeqq ymm1, ymm1, ymm5
                        vpcmpeqq ymm2, ymm2, ymm5
                            vpcmpeqq ymm3, ymm3, ymm5
                                vpcmpeqq ymm4, ymm4, ymm5
                    vpslldq ymm1, ymm1, 8
                        vpslldq ymm2, ymm2, 8
                            vpslldq ymm3, ymm3, 8
                                vpslldq ymm4, ymm4, 8
                    vpsubq ymm6, ymm6, ymm1
                        vpsubq ymm7, ymm7, ymm2
                            vpsubq ymm8, ymm8, ymm3
                                vpsubq ymm9, ymm9, ymm4
    ; END: ymm6..9 += ymm5

                    vpshufb ymm1, ymm6, ymm10
                        vpshufb ymm2, ymm7, ymm10
                            vpshufb ymm3, ymm8, ymm10
                                vpshufb ymm4, ymm9, ymm10

    add P2, 0x80
    dec P3
    test P3, P3

    jnz .back

    vmovaps [P1], ymm6
        vmovaps [P1 + 0x20], ymm7
            vmovaps [P1 + 0x40], ymm8
                vmovaps [P1 + 0x60], ymm9
    vzeroupper  ; for performance
    ret

section .data
align 16
affine_mat:
    db 2 dup (1, 2, 4, 8, 0x10, 0x20, 0x40, 0x80)
beshufb:
    db 0xf, 0xe, 0xd, 0xc, 0xb, 0xa, 9, 8, 7, 6, 5, 4, 3, 2, 1, 0
