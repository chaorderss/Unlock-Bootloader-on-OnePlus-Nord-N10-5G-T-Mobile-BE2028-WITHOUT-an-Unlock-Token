/*
 * kmon_new.S - Create a new monitor adapter via hdd_open_adapter
 *
 * hdd_open_adapter(hdd_ctx, session_type, iface_name, mac_addr, name_assign_type, rtnl_held)
 *
 * Gets hdd_ctx from wlan0's adapter+0x18
 * Creates mon0 with QDF_MONITOR_MODE = 4
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
sym_open_adapter: .asciz "hdd_open_adapter"
sym_rtnl_lock:  .asciz "rtnl_lock"
sym_rtnl_unlock: .asciz "rtnl_unlock"
devname:        .asciz "wlan0"
monname:        .asciz "mon0"

/* MAC address for mon0 (use wlan0's MAC with locally-administered bit) */
mac_addr:       .byte 0x5e, 0x17, 0xcf, 0xbc, 0xa4, 0xe3
                .balign 4

fmt_ctx:    .asciz "knw: hdd_ctx=%px\n"
fmt_call:   .asciz "knw: calling hdd_open_adapter(ctx, 4=MON, 'mon0', mac, 3, 1)...\n"
fmt_ret:    .asciz "knw: hdd_open_adapter returned %px\n"
fmt_err:    .asciz "knw: error at step %d\n"

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

    /* Resolve dev_get_by_name */
    adrp x0, sym_devget
    add x0, x0, :lo12:sym_devget
    bl kallsyms_lookup_name
    mov x19, x0
    cbz x0, .Lerr1

    /* Resolve init_net */
    adrp x0, sym_net
    add x0, x0, :lo12:sym_net
    bl kallsyms_lookup_name
    mov x20, x0
    cbz x0, .Lerr2

    /* Resolve hdd_open_adapter */
    adrp x0, sym_open_adapter
    add x0, x0, :lo12:sym_open_adapter
    bl kallsyms_lookup_name
    mov x23, x0       /* x23 = hdd_open_adapter */
    cbz x0, .Lerr3

    /* Resolve rtnl_lock */
    adrp x0, sym_rtnl_lock
    add x0, x0, :lo12:sym_rtnl_lock
    bl kallsyms_lookup_name
    mov x24, x0
    cbz x0, .Lerr4

    /* Resolve rtnl_unlock */
    adrp x0, sym_rtnl_unlock
    add x0, x0, :lo12:sym_rtnl_unlock
    bl kallsyms_lookup_name
    mov x25, x0
    cbz x0, .Lerr5

    /* Get wlan0 net_device */
    mov x0, x20
    adrp x1, devname
    add x1, x1, :lo12:devname
    blr x19
    mov x21, x0
    cbz x0, .Lerr6

    /* Get hdd_ctx from adapter+0x18 */
    add x22, x21, #0x880   /* adapter = dev + 0x880 */
    ldr x26, [x22, #0x18]  /* hdd_ctx = adapter+0x18 */

    adrp x0, fmt_ctx
    add x0, x0, :lo12:fmt_ctx
    mov x1, x26
    bl printk

    /* Acquire RTNL lock */
    blr x24                /* rtnl_lock() */

    /* Print call info */
    adrp x0, fmt_call
    add x0, x0, :lo12:fmt_call
    bl printk

    /* Call hdd_open_adapter(hdd_ctx, 4, "mon0", mac_addr, 3, 1) */
    mov x0, x26                     /* hdd_ctx */
    mov w1, #4                      /* QDF_MONITOR_MODE */
    adrp x2, monname
    add x2, x2, :lo12:monname      /* iface_name = "mon0" */
    adrp x3, mac_addr
    add x3, x3, :lo12:mac_addr     /* mac_addr */
    mov w4, #3                      /* NET_NAME_USER */
    mov w5, #1                      /* rtnl_held = true */
    blr x23                         /* hdd_open_adapter */

    mov x27, x0                    /* save result (adapter or NULL/ERR_PTR) */

    /* Release RTNL lock */
    blr x25                         /* rtnl_unlock() */

    /* Print result */
    adrp x0, fmt_ret
    add x0, x0, :lo12:fmt_ret
    mov x1, x27
    bl printk

    b .Lret

.Lerr1:
    mov w1, #1
    b .Lerr
.Lerr2:
    mov w1, #2
    b .Lerr
.Lerr3:
    mov w1, #3
    b .Lerr
.Lerr4:
    mov w1, #4
    b .Lerr
.Lerr5:
    mov w1, #5
    b .Lerr
.Lerr6:
    mov w1, #6
    b .Lerr

.Lerr:
    adrp x0, fmt_err
    add x0, x0, :lo12:fmt_err
    bl printk

.Lret:
    mov w0, #-1
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
