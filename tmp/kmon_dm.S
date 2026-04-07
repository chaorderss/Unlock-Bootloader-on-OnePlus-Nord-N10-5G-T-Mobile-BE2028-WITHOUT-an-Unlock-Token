/*
 * kmon_dm.S - Set adapter device_mode to QDF_MONITOR_MODE (4)
 *             and set dev->type to ARPHRD_IEEE80211_RADIOTAP (803)
 *
 * From hdd_mon_open disassembly:
 *   dev+0x234 = dev->type + hard_header_len packed (STR at +0x74: 0x000E0323)
 *   dev+0x228 = MTU (set to 1500)
 *
 * From adapter dump:
 *   adapter = dev + 0x880
 *   adapter+0x48 = device_mode (0=STA, 4=MONITOR)
 *
 * After this module:
 *   1. kmon6 + kmon7 patches already applied (cfg80211 allows monitor type)
 *   2. wlan0 must be DOWN and type set to monitor via iw
 *   3. This module sets device_mode=4 and dev->type=radiotap
 *   4. Then `ip link set wlan0 up` calls hdd_open -> hdd_start_adapter(MONITOR)
 */

.section .gnu.linkonce.this_module, "aw"
.balign 256
__this_module:
    .fill 24, 1, 0
    .asciz "kread"
    .fill 50, 1, 0
    .fill 256, 1, 0
    .quad init_module
    .fill 440, 1, 0
    .quad cleanup_module
    .fill 40, 1, 0

.section .modinfo, "a"
    .asciz "vermagic=4.19.81-perf+ SMP preempt mod_unload modversions aarch64"
    .asciz "name=kread"
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
sym_devget:     .asciz "dev_get_by_name"
sym_net:        .asciz "init_net"
devname:        .asciz "wlan0"

fmt_dev:    .asciz "kdm: dev=%px adapter=%px\n"
fmt_dm:     .asciz "kdm: device_mode: %d -> 4 (QDF_MONITOR_MODE)\n"
fmt_type:   .asciz "kdm: dev->type @+0x234: 0x%08x -> 0x000e0323 (radiotap)\n"
fmt_done:   .asciz "kdm: done. Now do: ip link set wlan0 up\n"
fmt_err:    .asciz "kdm: error\n"

.section .init.text, "ax"
.globl init_module
.type init_module, %function
init_module:
    stp x29, x30, [sp, #-64]!
    mov x29, sp
    stp x19, x20, [sp, #16]
    stp x21, x22, [sp, #32]
    stp x23, x24, [sp, #48]

    /* Resolve dev_get_by_name */
    adrp x0, sym_devget
    add x0, x0, :lo12:sym_devget
    bl kallsyms_lookup_name
    mov x19, x0
    cbz x0, .Lerr

    /* Resolve init_net */
    adrp x0, sym_net
    add x0, x0, :lo12:sym_net
    bl kallsyms_lookup_name
    mov x20, x0
    cbz x0, .Lerr

    /* Get wlan0 net_device */
    mov x0, x20
    adrp x1, devname
    add x1, x1, :lo12:devname
    blr x19
    mov x21, x0        /* x21 = dev */
    cbz x0, .Lerr

    /* adapter = dev + 0x880 */
    add x22, x21, #0x880  /* x22 = adapter */

    adrp x0, fmt_dev
    add x0, x0, :lo12:fmt_dev
    mov x1, x21
    mov x2, x22
    bl printk

    /* ---- PATCH 1: Set device_mode = 4 ---- */
    ldr w23, [x22, #0x48]   /* old device_mode */
    adrp x0, fmt_dm
    add x0, x0, :lo12:fmt_dm
    mov w1, w23
    bl printk

    mov w23, #4
    str w23, [x22, #0x48]

    /* ---- PATCH 2: Set dev->type to ARPHRD_IEEE80211_RADIOTAP ---- */
    /* From hdd_mon_open: STR 0x000E0323 to dev+0x234 */
    /* 0x0323 = 803 = ARPHRD_IEEE80211_RADIOTAP */
    /* 0x000E = 14 = hard_header_len for radiotap? */
    ldr w23, [x21, #0x234]   /* old value */
    adrp x0, fmt_type
    add x0, x0, :lo12:fmt_type
    mov w1, w23
    bl printk

    mov w23, #0x0323         /* ARPHRD_IEEE80211_RADIOTAP */
    movk w23, #0x000E, lsl #16   /* hard_header_len = 14 */
    str w23, [x21, #0x234]

    /* Done */
    adrp x0, fmt_done
    add x0, x0, :lo12:fmt_done
    bl printk
    b .Lret

.Lerr:
    adrp x0, fmt_err
    add x0, x0, :lo12:fmt_err
    bl printk

.Lret:
    mov w0, #-1
    ldp x23, x24, [sp, #48]
    ldp x21, x22, [sp, #32]
    ldp x19, x20, [sp, #16]
    ldp x29, x30, [sp], #64
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
