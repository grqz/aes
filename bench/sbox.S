BITS 64
section .text

extern bench_priu64
extern bench_end

extern aes_sbox

global bench_setup
global bench_loop
global bench_cleanup

bench_setup:
    mov r14, 0xff_ffff
    ret

bench_loop:
    call aes_sbox
    inc rdi
    dec r14
    test r14, r14  ; dec + test is faster
    jnz bench_loop
    jmp bench_end

bench_cleanup:
    jmp bench_priu64
