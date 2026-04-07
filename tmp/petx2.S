/*
 * petx2.S - Discover PE session MAC offsets (SAFE version)
 *
 * Minimal: get mac_ctx, get session, print session ptr,
 * then search for our MAC address byte by byte (safely).
 *
 * Build: as -o petx2.o petx2.S && ld -r -o petx2.ko petx2.o
 */

.section .gnu.linkonce.this_module, "aw"
.balign 256
__this_module:
    .fill 24, 1, 0
    .asciz "kfind"
    .fill 50, 1, 0
    .fill 256, 1, 0
    .quad init_module
    .fill 440, 1, 0
    .quad cleanup_module
    .fill 40, 1, 0

.section .modinfo, "a"
    .asciz "vermagic=4.19.81-perf+ SMP preempt mod_unload modversions aarch64"
    .asciz "name=kfind"
    .asciz "license=GPL"

.section __versions, "a"
    .quad 0
    .asciz "module_layout"
    .balign 64, 0
    .quad 0
    .asciz "printk"
    .balign 64, 0
    .quad 0
    .asciz "kallsyms_lookup_name"
    .balign 64, 0

.section .rodata, "a"
str_cds:        .asciz "cds_get_context"
str_pe_find:    .asciz "pe_find_session_by_session_id"

fmt_init:    .asciz "petx2: starting PE session scan\n"
fmt_sym:     .asciz "petx2: cds=%px pe_find=%px\n"
fmt_ctx:     .asciz "petx2: mac_ctx=%px\n"
fmt_sess:    .asciz "petx2: session=%px\n"
fmt_mac:     .asciz "petx2: MAC found at offset 0x%x\n"
fmt_hex:     .asciz "petx2: [0x%04x] %02x %02x %02x %02x %02x %02x\n"
fmt_nosess:  .asciz "petx2: no session for id %d\n"
fmt_err:     .asciz "petx2: symbol error\n"
fmt_done:    .asciz "petx2: scan complete\n"

/* 6-byte MAC to search for: 5c:17:cf:bc:a4:e3 */
.balign 8
our_mac:
    .byte 0x5c,0x17,0xcf,0xbc,0xa4,0xe3
    .byte 0,0  /* padding */

/* Home AP BSSID: 8c:de:f9:b3:9e:20 */
.balign 8
home_bssid:
    .byte 0x8c,0xde,0xf9,0xb3,0x9e,0x20
    .byte 0,0

.section .init.text, "ax"
.globl init_module
.type init_module, %function
init_module:
    stp x29, x30, [sp, #-96]!
    mov x29, sp
    stp x19, x20, [sp, #16]
    stp x21, x22, [sp, #32]
    stp x23, x24, [sp, #48]
    stp x25, x26, [sp, #64]

    adrp x0, fmt_init
    add x0, x0, :lo12:fmt_init
    bl printk

    /* Resolve symbols */
    adrp x0, str_cds
    add x0, x0, :lo12:str_cds
    bl kallsyms_lookup_name
    cbz x0, .Lerr
    mov x19, x0

    adrp x0, str_pe_find
    add x0, x0, :lo12:str_pe_find
    bl kallsyms_lookup_name
    cbz x0, .Lerr
    mov x20, x0

    adrp x0, fmt_sym
    add x0, x0, :lo12:fmt_sym
    mov x1, x19
    mov x2, x20
    bl printk

    /* Get mac_ctx = cds_get_context(53) */
    mov w0, #53
    blr x19
    cbz x0, .Lerr
    mov x21, x0

    adrp x0, fmt_ctx
    add x0, x0, :lo12:fmt_ctx
    mov x1, x21
    bl printk

    /* Try session IDs 0-3 */
    mov w22, #0

.Ltry_session:
    cmp w22, #4
    b.ge .Lscan_done

    mov x0, x21            /* mac_ctx */
    mov w1, w22            /* session_id */
    blr x20                /* pe_find_session_by_session_id */

    cbz x0, .Lno_session
    mov x23, x0            /* x23 = session */

    adrp x0, fmt_sess
    add x0, x0, :lo12:fmt_sess
    mov x1, x23
    bl printk

    /* Load our MAC bytes for comparison */
    adrp x8, our_mac
    add x8, x8, :lo12:our_mac
    ldrb w24, [x8, #0]     /* 0x5c */

    /* Search session memory for first byte of our MAC */
    mov w25, #0             /* offset */

.Lsearch:
    cmp w25, #2048          /* only scan 2KB */
    b.ge .Lsearch_bssid

    ldrb w9, [x23, x25]
    cmp w9, w24             /* first byte match? */
    b.ne .Lsearch_next

    /* First byte matched, check remaining 5 bytes */
    add x10, x23, x25      /* pointer to candidate */
    ldrb w11, [x10, #1]
    ldrb w12, [x8, #1]     /* 0x17 */
    cmp w11, w12
    b.ne .Lsearch_next

    ldrb w11, [x10, #2]
    ldrb w12, [x8, #2]     /* 0xcf */
    cmp w11, w12
    b.ne .Lsearch_next

    ldrb w11, [x10, #3]
    ldrb w12, [x8, #3]     /* 0xbc */
    cmp w11, w12
    b.ne .Lsearch_next

    ldrb w11, [x10, #4]
    ldrb w12, [x8, #4]     /* 0xa4 */
    cmp w11, w12
    b.ne .Lsearch_next

    ldrb w11, [x10, #5]
    ldrb w12, [x8, #5]     /* 0xe3 */
    cmp w11, w12
    b.ne .Lsearch_next

    /* FULL MATCH! Print offset */
    adrp x0, fmt_mac
    add x0, x0, :lo12:fmt_mac
    mov w1, w25
    bl printk

    /* Print 6 bytes at this offset for verification */
    add x10, x23, x25
    adrp x0, fmt_hex
    add x0, x0, :lo12:fmt_hex
    mov w1, w25
    ldrb w2, [x10, #0]
    ldrb w3, [x10, #1]
    ldrb w4, [x10, #2]
    ldrb w5, [x10, #3]
    ldrb w6, [x10, #4]
    ldrb w7, [x10, #5]
    bl printk

.Lsearch_next:
    add w25, w25, #1
    b .Lsearch

    /* Now search for home BSSID (8c:de:f9:b3:9e:20) */
.Lsearch_bssid:
    adrp x8, home_bssid
    add x8, x8, :lo12:home_bssid
    ldrb w24, [x8, #0]     /* 0x8c */
    mov w25, #0

.Lsearch_b:
    cmp w25, #2048
    b.ge .Lnext_session

    ldrb w9, [x23, x25]
    cmp w9, w24
    b.ne .Lsearch_b_next

    add x10, x23, x25
    ldrb w11, [x10, #1]
    ldrb w12, [x8, #1]
    cmp w11, w12
    b.ne .Lsearch_b_next

    ldrb w11, [x10, #2]
    ldrb w12, [x8, #2]
    cmp w11, w12
    b.ne .Lsearch_b_next

    ldrb w11, [x10, #3]
    ldrb w12, [x8, #3]
    cmp w11, w12
    b.ne .Lsearch_b_next

    ldrb w11, [x10, #4]
    ldrb w12, [x8, #4]
    cmp w11, w12
    b.ne .Lsearch_b_next

    ldrb w11, [x10, #5]
    ldrb w12, [x8, #5]
    cmp w11, w12
    b.ne .Lsearch_b_next

    /* BSSID MATCH */
    adrp x0, fmt_mac
    add x0, x0, :lo12:fmt_mac
    mov w1, w25
    bl printk

    add x10, x23, x25
    adrp x0, fmt_hex
    add x0, x0, :lo12:fmt_hex
    mov w1, w25
    ldrb w2, [x10, #0]
    ldrb w3, [x10, #1]
    ldrb w4, [x10, #2]
    ldrb w5, [x10, #3]
    ldrb w6, [x10, #4]
    ldrb w7, [x10, #5]
    bl printk

.Lsearch_b_next:
    add w25, w25, #1
    b .Lsearch_b

.Lno_session:
    adrp x0, fmt_nosess
    add x0, x0, :lo12:fmt_nosess
    mov w1, w22
    bl printk

.Lnext_session:
    add w22, w22, #1
    b .Ltry_session

.Lscan_done:
    adrp x0, fmt_done
    add x0, x0, :lo12:fmt_done
    bl printk
    mov w0, #0
    b .Lret

.Lerr:
    adrp x0, fmt_err
    add x0, x0, :lo12:fmt_err
    bl printk
    mov w0, #-1

.Lret:
    ldp x25, x26, [sp, #64]
    ldp x23, x24, [sp, #48]
    ldp x21, x22, [sp, #32]
    ldp x19, x20, [sp, #16]
    ldp x29, x30, [sp], #96
    ret

.section .exit.text, "ax"
.globl cleanup_module
.type cleanup_module, %function
cleanup_module:
    ret

.section .note.Linux, "a", @note
    .long 6
    .long 0
    .long 0x100
    .asciz "Linux"
    .balign 4

.section .plt, "ax"
    .balign 8
    .space 8

.section .init.plt, "ax"
    .balign 8
    .space 8

.section .text.ftrace_trampoline, "ax"
    .balign 8
    .space 8
