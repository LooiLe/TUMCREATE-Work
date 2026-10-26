.section .text.init
.global _start

_start:
    la sp, _stack_top

    /* Clear BSS */
    la t0, __bss_start
    la t1, __bss_end

clear_bss:
    bgeu t0, t1, bss_done
    sb zero, 0(t0)
    addi t0, t0, 1
    j clear_bss

bss_done:
    call main

finish:
    j finish