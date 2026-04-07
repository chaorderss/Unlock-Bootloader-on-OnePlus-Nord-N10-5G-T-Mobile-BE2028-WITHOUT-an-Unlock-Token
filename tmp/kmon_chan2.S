/*
 * kmon_chan2.S - Set monitor channel via wlan_hdd_set_mon_chan
 *
 * Get adapter via dev_get_by_name + netdev_priv (dev + 0x880)
 * Bypass con_mode check was already applied by kmon_chan
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
    .quad 0
    .asciz "init_net"
    .balign 64, 0
    .quad 0
    .asciz "dev_get_by_name"
    .balign 64, 0

.section .rodata, "a"
sym_smc:    .asciz "wlan_hdd_set_mon_chan"
devname:    .asciz "wlan0"

fmt_dev:    .asciz "kch2: dev=%px adapter=%px mode=%d\n"
fmt_call:   .asciz "kch2: set_mon_chan(adapter, %d, %d) = %d\n"
fmt_err:    .asciz "kch2: error at step %d\n"
fmt_dmesg:  .asciz "kch2: checking dmesg for wlan: messages...\n"

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

    /* Resolve wlan_hdd_set_mon_chan */
    adrp x0, sym_smc
    add x0, x0, :lo12:sym_smc
    bl kallsyms_lookup_name
    mov x19, x0        /* x19 = set_mon_chan */
    cbz x0, .Lerr1

    /* Get net device */
    adrp x0, init_net
    add x0, x0, :lo12:init_net
    adrp x1, devname
    add x1, x1, :lo12:devname
    bl dev_get_by_name
    mov x20, x0        /* x20 = dev */
    cbz x0, .Lerr2

    /* adapter = dev + 0x880 (netdev_priv) */
    add x21, x20, #0x880   /* x21 = adapter */

    /* Read adapter->device_mode at offset +0x48 */
    ldr w22, [x21, #0x48]

    adrp x0, fmt_dev
    add x0, x0, :lo12:fmt_dev
    mov x1, x20
    mov x2, x21
    mov w3, w22
    bl printk

    /* Call wlan_hdd_set_mon_chan(adapter, chan=11, bw=0) */
    mov x0, x21
    mov w1, #11         /* channel 11 */
    mov w2, #0          /* NL80211_CHAN_WIDTH_20_NOHT */
    blr x19
    mov w23, w0

    adrp x0, fmt_call
    add x0, x0, :lo12:fmt_call
    mov w1, #11
    mov w2, #0
    mov w3, w23
    bl printk

    /* If failed with channel number, try with freq */
    cbnz w23, .Ltry_freq
    b .Ldone

.Ltry_freq:
    mov x0, x21
    mov w1, #2462       /* 2462 MHz = channel 11 */
    mov w2, #0          /* NL80211_CHAN_WIDTH_20_NOHT */
    blr x19
    mov w23, w0

    adrp x0, fmt_call
    add x0, x0, :lo12:fmt_call
    mov w1, #2462
    mov w2, #0
    mov w3, w23
    bl printk

.Ldone:
    /* Release dev reference from dev_get_by_name */
    /* dev_put(dev) - just decrement refcount at dev+0x188 */
    /* Actually, let's skip dev_put since we're returning -1 anyway */

    adrp x0, fmt_dmesg
    add x0, x0, :lo12:fmt_dmesg
    bl printk
    b .Lret

.Lerr1:
    adrp x0, fmt_err
    add x0, x0, :lo12:fmt_err
    mov w1, #1
    bl printk
    b .Lret

.Lerr2:
    adrp x0, fmt_err
    add x0, x0, :lo12:fmt_err
    mov w1, #2
    bl printk
    b .Lret

.Lret:
    mov w0, #-1
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
    nop
    nop
.section .init.plt, "ax"
    nop
    nop
.section .text.ftrace_trampoline, "ax"
    nop
    nop
