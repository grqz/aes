BITS 64
section .text

global aes_ghash_win
global aes_ghash_sv
global aes_ghash
global aes256_keyexpansion_aesni_sv
global aes256_keyexpansion_aesni
global aes256_keyexpansion_aesni_32_sv
global aes256_keyexpansion_aesni_32
global aes256_cipher_aesni_sv
global aes256_cipher_aesni
global aes256_invcipher_aesni_sv
global aes256_invcipher_aesni
global aes256_ctr_vy_sv
global aes256_ctr_vy
global aes256_ctr_vy64_sv

%macro __trap 0
%ifndef NDEBUG
    int3
%endif
%endmacro

aes_ghash_win:
    movdqa [rsp + 8], xmm6
    call aes_ghash
    movdqa xmm6, [rsp + 8]
    ret

aes_ghash_sv:
    mov r8, rdx  ; r64 len
    mov rdx, rsi ; *data W:16B R:<16*len>B align 16
    mov rcx, rdi ; *subkey R:16B align 16

; @func r64 (r64 r64 r64)
; calling convention: win x64-ish
; params rcx rdx r8
; return rax
; scratch
;     xmm0 xmm1 xmm2 xmm3
;     xmm4 xmm5 xmm6
;     rax rcx rdx r8 r9 r10 r11
; no shadow space/redzone/stack alignment
; benchmark (7 blocks):
; P-core: 37.402ns
; E-core: 52.722ns
aes_ghash:
    xor eax, eax
    test r8, r8
    jz .errout
    movdqa xmm6, [rel affine_mat]

    movdqa xmm1, [rcx]
    mov r9, 0x87
    xorps xmm0, xmm0
    gf2p8affineqb xmm1, xmm6, 0
    movq xmm5, r9

    ; we may use:
    ; xmm0..xmm6 incl
    ; r9 rcx rax
    mov r9, rdx

.loophead:
    movdqa xmm2, [rdx]
    gf2p8affineqb xmm2, xmm6, 0
        add rdx, 0x10
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

    vpclmullqlqdq xmm3, xmm2, xmm5
        pclmulhqlqdq xmm2, xmm5
                xorps xmm0, xmm3
            vpslldq xmm4, xmm2, 8
                xorps xmm0, xmm4
        pclmulhqlqdq xmm2, xmm5
    ; just a 8bx8b, xmm2 should be 16b or less

    inc rax
    dec r8
        xorps xmm0, xmm2
    test r8, r8
    jnz .loophead

    gf2p8affineqb xmm0, xmm6, 0
    movdqa [r9], xmm0
.errout:
    ret

aes256_keyexpansion_aesni_sv:
    mov rdx, rsi ; *key R:32B align 16
    mov rcx, rdi ; *kexp RW:240B align 16
; @func void (r64 r64)
; calling convention: win x64-ish
; params rcx rdx
; scratch
;     xmm0 xmm1 xmm2 xmm3
;     xmm4 xmm5
;     rax rcx rdx r8 r9 r10 r11
; no shadow space/redzone/stack alignment
; benchmark: (for some reason the E-core is faster)
; P-core: 47.552ns
; E-core: 21.263ns
aes256_keyexpansion_aesni:
                movdqa xmm0, [rdx + 0x10]
            movdqa xmm1, [rdx]
                movdqa [rcx + 0x10], xmm0
            movdqa [rcx], xmm1
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
                        movdqa [rcx + OFFSET], xmm1

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
                    movdqa [rcx + OFFSET], xmm0

    %assign OFFSET OFFSET + 0x10
    %if OFFSET >= 0xf0
        %exitrep
    %endif
%endrep
%undef OFFSET
%undef RCON
    ret

aes256_keyexpansion_aesni_32_sv:
    mov rdx, rsi ; *key R:32B align 16
    mov rcx, rdi ; *exk RW:480B align 32
; @func void (r64 r64)
; calling convention: win x64-ish
; params rcx rdx
; scratch
;     xmm0 xmm1 xmm2 xmm3
;     xmm4 xmm5
;     rax rcx rdx r8 r9 r10 r11
; no shadow space/redzone/stack alignment
aes256_keyexpansion_aesni_32:
                movdqa xmm0, [rdx + 0x10]
            movdqa xmm1, [rdx]
                movdqa [rcx + 0x20], xmm0
                movdqa [rcx + 0x30], xmm0
            movdqa [rcx], xmm1
            movdqa [rcx + 0x10], xmm1
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
                        movdqa [rcx + OFFSET], xmm1
                        movdqa [rcx + OFFSET + 0x10], xmm1

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
                    movdqa [rcx + OFFSET], xmm0
                    movdqa [rcx + OFFSET + 0x10], xmm0

    %assign OFFSET OFFSET + 0x20
    %if OFFSET >= 0x1e0
        %exitrep
    %endif
%endrep
%undef OFFSET
%undef RCON
    ret


aes256_cipher_aesni_sv:
    mov rdx, rsi ; *exk R:240B align 16
    mov rcx, rdi ; *state RW:16B align 16
; @func void (r64 r64)
; calling convention: win x64-ish
; params rcx rdx
; scratch
;     xmm0 xmm1 xmm2 xmm3
;     xmm4 xmm5
;     rax rcx rdx r8 r9 r10 r11
; no shadow space/redzone/stack alignment
aes256_cipher_aesni:
    movdqa xmm0, [rcx]
    xorps xmm0, [rdx]
%define OFFSET 0x10
%rep 13
    vaesenc xmm0, [rdx + OFFSET]
%assign OFFSET OFFSET+0x10
%endrep
    vaesenclast xmm0, [rdx + OFFSET]
%undef OFFSET
    movdqa [rcx], xmm0
    ret

aes256_ctr_vy_sv:
    mov r9, rcx  ; r64 len of data in 32B chunks
    mov r8, rdx  ; *data RW:<32*len>B align 32
    mov rdx, rsi ; *iv R:16B RW:32B align 32
    mov rcx, rdi ; *exk R:240B align 16
; Basic version, don't use.
; @func void (r64 r64 r64 r64)
; calling convention: win x64-ish
; params rcx rdx r8 r9
; scratch
;     ymm0 ymm1 ymm2 ymm3
;     ymm4 ymm5
;     rax rcx rdx r8 r9 r10 r11
; no shadow space/redzone/stack alignment
aes256_ctr_vy:
    vmovdqa xmm5, [rel beshufb]
    vinserti128 ymm5, ymm5, xmm5, 1
    vmovdqa xmm0, [rdx]
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
        vmovdqa [rdx], ymm0
        vpshufb ymm0, ymm0, ymm5
.back:
    vmovaps ymm1, [rcx]
    vxorps ymm1, ymm1, ymm0
%define OFFSET 0x20
%rep 13
    vmovaps ymm0, [rcx + OFFSET]
    vaesenc ymm1, ymm0
%assign OFFSET OFFSET+0x20
%endrep
    vmovaps ymm0, [rcx + OFFSET]
    vaesenclast ymm1, ymm0
%undef OFFSET

    vxorps ymm1, [r8]
    vmovaps [r8], ymm1
    ; inc IV
        movq xmm1, r10
        vinserti128 ymm1, ymm1, xmm1, 1
    vmovdqa ymm0, [rdx]
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
    vmovdqa [rdx], ymm0
    vpshufb ymm0, ymm5
    add r8, 0x20
    dec r9
    test r9, r9
    jnz .back
    vzeroupper
    ret

; TODO: win64 wrapper as ymm6+ are volatile there
aes256_ctr_vy64_sv:
    mov r9, rcx  ; r64 len of data in 32B chunks
    mov r8, rdx  ; *data RW:<32*len>B align 32
    mov rdx, rsi ; *iv R:16B RW:64B align 32
    mov rcx, rdi ; *exk R:240B align 32
; AES-256-CTR crypt function operating in 64-byte blocks
; Slightly optimised.
; @func void (r64 r64 r64 r64)
; calling convention: win x64-ish
; params rcx rdx r8 r9
; scratch
;     ymm0 ymm1 ymm2 ymm3
;     ymm4 ymm5 ymm6 ymm7
;     ymm8 ymm9 ymm10 ymm11
;     ymm12 ymm13 ymm14 ymm15
;     rax rcx rdx r8 r9 r10 r11
; no shadow space/redzone/stack alignment
.aes256_ctr_vy64:
    ; TODO: this may be optimised to read 128/256 bytes at a time
    vmovdqa xmm5, [rel beshufb]
    vinserti128 ymm5, ymm5, xmm5, 1
    vmovdqa xmm0, [rdx]
    ; "expand" IV for vecorised AES

    ; calculate carry. this is simple because we are adding one
            pcmpeqw xmm2, xmm2
            vpcmpeqq xmm2, xmm2, xmm0
    pshufb xmm0, xmm5
        mov eax, 1
    mov r10, 2
    movq xmm6, r10
    ; inserts are limited to pre-loop
    vinserti128 ymm6, ymm6, xmm6, 1
            pslldq xmm2, 8
        movd xmm1, eax
        paddq xmm1, xmm0
        ; subtract mask = add carry
        psubq xmm1, xmm2
        vinserti128 ymm0, ymm0, xmm1, 1
        vmovdqa [rdx], ymm0
        vpshufb ymm0, ymm0, ymm5

    ; BEGIN: ymm1 = ymm0 + 2
        vpsrlq ymm3, ymm6, 1   ; 2 1s, one in each lane
    vpaddq ymm1, ymm0, ymm6
            vpsllq ymm6, ymm6, 1   ; ymm6 contains 2 4s one in each lane
    ; carry when the (X & 1) == X (see NOTE section below)
        vpand ymm3, ymm3, ymm1
        vpcmpeqq ymm3, ymm3, ymm1
        vpslldq ymm3, ymm3, 8  ; discard carry from high q
        ; masks can be subtracted because x - (-1) = x + 1
        vpsubq ymm1, ymm3

        vmovdqa [rdx + 0x20], ymm1
        ; shuffle back AFTER store, so that the value is ready for increment
        ; once its loaded, this minimises shuffles
        ; TODO: maybe we shouldn't store back to memory at all?
        vpshufb ymm1, ymm1, ymm5

.back:
    ; now: ymm0 = IV 0,1, ymm1 = IV 2,3 (both mod 4)
    vmovaps ymm2, [rcx]  ; load first round key
    vxorps ymm0, ymm0, ymm2
        vxorps ymm1, ymm1, ymm2
%define OFFSET 0x20
%rep 13
    vmovaps ymm2, [rcx + OFFSET]
    vaesenc ymm0, ymm0, ymm2
        vaesenc ymm1, ymm1, ymm2
%assign OFFSET OFFSET+0x20
%endrep
    vmovaps ymm2, [rcx + OFFSET]
    vaesenclast ymm0, ymm0, ymm2
        vaesenclast ymm1, ymm1, ymm2
%undef OFFSET

    vxorps ymm0, [r8]
        vxorps ymm1, [r8 + 0x20]
    vmovaps [r8], ymm0
        vmovaps [r8 + 0x20], ymm1

    ; load and inc IV
    vmovdqa ymm0, [rdx]
        vmovdqa ymm1, [rdx + 0x20]

    ; BEGIN: ymm0 += 4, ymm1 += 4 clobber 3 4
    vpaddq ymm0, ymm0, ymm6
        vpaddq ymm1, ymm1, ymm6
    ; NOTE on testing carry with unroll factor 4:
    ; In general, addition carry is performed when A + B < A where < denotes
    ; unsigned less/below. In this case, we want to test for each ymm, whether
    ; the lower qwords are within the range [0, 3]. We should not use VPCMPGTQ
    ; as that gives us signed comparison. Instead, we rely on the fact that 4
    ; is a power of two, and when (X & 3) == X, X must be one of 0, 1, 2, 3.
    vpcmpeqw ymm3, ymm3, ymm3
    vpsrlq ymm3, ymm3, 62      ; ymm3 is 3(s)
        vpand ymm4, ymm3, ymm1
    vpand ymm3, ymm3, ymm0
        vpcmpeqq ymm4, ymm4, ymm1
    vpcmpeqq ymm3, ymm3, ymm0
        vpslldq ymm4, ymm4, 8
    vpslldq ymm3, ymm3, 8  ; discard carry from high q
        vpsubq ymm1, ymm1, ymm4
    vpsubq ymm0, ymm0, ymm3
    ; END: ymm0 += 4, ymm1 += 4

        vmovdqa [rdx + 0x20], ymm1
    vmovdqa [rdx], ymm0
        vpshufb ymm1, ymm1, ymm5
    vpshufb ymm0, ymm0, ymm5

    add r8, 0x40
    dec r9
    test r9, r9

    jnz .back

    vzeroupper  ; for performance
    ret

section .data
align 16
affine_mat:
    db 2 dup (1, 2, 4, 8, 0x10, 0x20, 0x40, 0x80)
beshufb:
    db 0xf, 0xe, 0xd, 0xc, 0xb, 0xa, 9, 8, 7, 6, 5, 4, 3, 2, 1, 0
