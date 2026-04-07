/*
 * petx3.S - Discover PE session MAC offsets (FIXED)
 *
 * Fixed: use callee-saved registers for pattern pointers.
 * x19=cds_get_context, x20=pe_find, x21=mac_ctx, x22=session_id counter
 * x23=session, x24=our_mac ptr(saved), x25=search offset, x26=home_bssid ptr
 *
 * Build: as -o petx3.o petx3.S && ld -r -o petx3.ko petx3.o
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

fmt_init:    .asciz "petx3: PE session scan (fixed)\n"
fmt_sym:     .asciz "petx3: cds=%px pe_find=%px\n"
fmt_ctx:     .asciz "petx3: mac_ctx=%px\n"
fmt_sess:    .asciz "petx3: session[%d]=%px\n"
fmt_selfmac: .asciz "petx3: selfMacAddr at +0x%x: %02x:%02x:%02x:%02x:%02x:%02x\n"
fmt_bssid:   .asciz "petx3: bssId at +0x%x: %02x:%02x:%02x:%02x:%02x:%02x\n"
fmt_nosess:  .asciz "petx3: no session for id %d\n"
fmt_err:     .asciz "petx3: symbol error\n"
fmt_done:    .asciz "petx3: complete\n"

.balign 8
our_mac:
    .byte 0x5c,0x17,0xcf,0xbc,0xa4,0xe3
    .byte 0,0

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
    stp x27, x28, [sp, #80]

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

    /* Get mac_ctx */
    mov w0, #53
    blr x19
    cbz x0, .Lerr
    mov x21, x0

    adrp x0, fmt_ctx
    add x0, x0, :lo12:fmt_ctx
    mov x1, x21
    bl printk

    /* Load pattern pointers into callee-saved regs */
    adrp x24, our_mac
    add x24, x24, :lo12:our_mac
    adrp x26, home_bssid
    add x26, x26, :lo12:home_bssid

    /* Try session 0 only */
    mov x0, x21
    mov w1, #0
    blr x20
    cbz x0, .Lnosess
    mov x23, x0

    adrp x0, fmt_sess
    add x0, x0, :lo12:fmt_sess
    mov w1, #0
    mov x2, x23
    bl printk

    /* ===== Search for selfMacAddr (our_mac) ===== */
    mov w25, #0
.Lsearch_mac:
    cmp w25, #2048
    b.ge .Lsearch_bssid_start

    /* Compare 6 bytes at session+w25 against our_mac */
    add x8, x23, x25
    ldrb w9, [x8]
    ldrb w10, [x24]
    cmp w9, w10
    b.ne .Lmac_next

    ldrb w9, [x8, #1]
    ldrb w10, [x24, #1]
    cmp w9, w10
    b.ne .Lmac_next

    ldrb w9, [x8, #2]
    ldrb w10, [x24, #2]
    cmp w9, w10
    b.ne .Lmac_next

    ldrb w9, [x8, #3]
    ldrb w10, [x24, #3]
    cmp w9, w10
    b.ne .Lmac_next

    ldrb w9, [x8, #4]
    ldrb w10, [x24, #4]
    cmp w9, w10
    b.ne .Lmac_next

    ldrb w9, [x8, #5]
    ldrb w10, [x24, #5]
    cmp w9, w10
    b.ne .Lmac_next

    /* MATCH - print it */
    /* Re-load bytes from session for printing (x8 will be clobbered) */
    add x8, x23, x25
    adrp x0, fmt_selfmac
    add x0, x0, :lo12:fmt_selfmac
    mov w1, w25
    ldrb w2, [x8, #0]
    ldrb w3, [x8, #1]
    ldrb w4, [x8, #2]
    ldrb w5, [x8, #3]
    ldrb w6, [x8, #4]
    ldrb w7, [x8, #5]
    bl printk

.Lmac_next:
    add w25, w25, #1
    b .Lsearch_mac

    /* ===== Search for bssId (home_bssid) ===== */
.Lsearch_bssid_start:
    mov w25, #0
.Lsearch_bss:
    cmp w25, #2048
    b.ge .Ldone

    add x8, x23, x25
    ldrb w9, [x8]
    ldrb w10, [x26]
    cmp w9, w10
    b.ne .Lbss_next

    ldrb w9, [x8, #1]
    ldrb w10, [x26, #1]
    cmp w9, w10
    b.ne .Lbss_next

    ldrb w9, [x8, #2]
    ldrb w10, [x26, #2]
    cmp w9, w10
    b.ne .Lbss_next

    ldrb w9, [x8, #3]
    ldrb w10, [x26, #3]
    cmp w9, w10
    b.ne .Lbss_next

    ldrb w9, [x8, #4]
    ldrb w10, [x26, #4]
    cmp w9, w10
    b.ne .Lbss_next

    ldrb w9, [x8, #5]
    ldrb w10, [x26, #5]
    cmp w9, w10
    b.ne .Lbss_next

    /* MATCH - print it */
    add x8, x23, x25
    adrp x0, fmt_bssid
    add x0, x0, :lo12:fmt_bssid
    mov w1, w25
    ldrb w2, [x8, #0]
    ldrb w3, [x8, #1]
    ldrb w4, [x8, #2]
    ldrb w5, [x8, #3]
    ldrb w6, [x8, #4]
    ldrb w7, [x8, #5]
    bl printk

.Lbss_next:
    add w25, w25, #1
    b .Lsearch_bss

.Lnosess:
    adrp x0, fmt_nosess
    add x0, x0, :lo12:fmt_nosess
    mov w1, #0
    bl printk

.Ldone:
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
    ldp x27, x28, [sp, #80]
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
