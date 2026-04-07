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
    .asciz "dev_get_by_name"
    .balign 64, 0
    .quad 0
    .asciz "kallsyms_lookup_name"
    .balign 64, 0

.section .plt,"ax"
.space 8
.section .init.plt,"ax"
.space 8
.section .text.ftrace_trampoline,"ax"
.space 8

.section .rodata, "a"
wlan0_str:   .asciz "wlan0"
sym_umac:    .asciz "g_umac_glb_obj"
sym_gp_cds:  .asciz "gp_cds_context"
fmt_dev:     .asciz "WMA2: dev=%px adapter=%px hdd_ctx=%px\n"
fmt_hdd:     .asciz "WMA2: hdd_ctx+0x%03lx: %016lx %016lx\n"
fmt_umac:    .asciz "WMA2: g_umac_glb@%px\n"
fmt_umac_d:  .asciz "WMA2: umac+0x%03lx: %016lx %016lx\n"
fmt_gp:      .asciz "WMA2: gp_cds=%px val=%px\n"
fmt_cds_d:   .asciz "WMA2: cds+0x%03lx: %016lx %016lx\n"

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

    // ===== Part 1: Get adapter and hdd_ctx from wlan0 =====
    // dev_get_by_name(&init_net, "wlan0")
    adrp x0, sym_umac           // dummy, will use init_net below
    // Actually lookup init_net
    adrp x0, wlan0_str
    add x0, x0, :lo12:wlan0_str
    // Need init_net pointer - it's at a fixed kernel address
    // Let's use kallsyms_lookup_name to find it
    str x30, [sp, #96]

    // First, find init_net
    adr x0, .Lsym_initnet
    bl kallsyms_lookup_name
    mov x19, x0                 // x19 = &init_net

    // dev_get_by_name(init_net, "wlan0")
    mov x0, x19
    adrp x1, wlan0_str
    add x1, x1, :lo12:wlan0_str
    bl dev_get_by_name
    cbz x0, .Ldone
    mov x20, x0                 // x20 = netdev

    // adapter = netdev_priv(dev) = (char*)dev + ALIGN(sizeof(net_device), NETDEV_ALIGN)
    // On this kernel, offset is 0x880 (known from prior work)
    add x21, x20, #0x880        // x21 = adapter

    // hdd_ctx = adapter + 0x18
    ldr x22, [x21, #0x18]       // x22 = hdd_ctx

    // Print dev, adapter, hdd_ctx
    adrp x0, fmt_dev
    add x0, x0, :lo12:fmt_dev
    mov x1, x20
    mov x2, x21
    mov x3, x22
    bl printk

    // Dump hdd_ctx: first 512 bytes
    cbz x22, .Lskip_hdd
    mov x23, #0

.Lhdd_loop:
    cmp x23, #512
    b.ge .Lskip_hdd

    ldr x2, [x22, x23]
    add x24, x23, #8
    ldr x3, [x22, x24]

    adrp x0, fmt_hdd
    add x0, x0, :lo12:fmt_hdd
    mov x1, x23
    bl printk

    add x23, x23, #16
    b .Lhdd_loop

.Lskip_hdd:
    // ===== Part 2: Dump g_umac_glb_obj =====
    adrp x0, sym_umac
    add x0, x0, :lo12:sym_umac
    bl kallsyms_lookup_name
    cbz x0, .Lskip_umac
    mov x25, x0                 // x25 = &g_umac_glb_obj

    adrp x0, fmt_umac
    add x0, x0, :lo12:fmt_umac
    mov x1, x25
    bl printk

    // Dump first 256 bytes of g_umac_glb_obj
    mov x23, #0

.Lumac_loop:
    cmp x23, #256
    b.ge .Lskip_umac

    ldr x2, [x25, x23]
    add x24, x23, #8
    ldr x3, [x25, x24]

    adrp x0, fmt_umac_d
    add x0, x0, :lo12:fmt_umac_d
    mov x1, x23
    bl printk

    add x23, x23, #16
    b .Lumac_loop

.Lskip_umac:
    // ===== Part 3: Read gp_cds_context and dump its struct =====
    adrp x0, sym_gp_cds
    add x0, x0, :lo12:sym_gp_cds
    bl kallsyms_lookup_name
    cbz x0, .Ldone
    mov x25, x0                 // x25 = &gp_cds_context
    ldr x26, [x25]              // x26 = value of gp_cds_context

    adrp x0, fmt_gp
    add x0, x0, :lo12:fmt_gp
    mov x1, x25
    mov x2, x26
    bl printk

    // Dump the struct that gp_cds_context points to (if non-NULL)
    cbz x26, .Ldone
    mov x23, #0

.Lcds_loop:
    cmp x23, #256
    b.ge .Ldone

    ldr x2, [x26, x23]
    add x24, x23, #8
    ldr x3, [x26, x24]

    adrp x0, fmt_cds_d
    add x0, x0, :lo12:fmt_cds_d
    mov x1, x23
    bl printk

    add x23, x23, #16
    b .Lcds_loop

.Ldone:
    // Release netdev ref if we got one
    mov x0, #-1
    ldp x27, x28, [sp, #80]
    ldp x25, x26, [sp, #64]
    ldp x23, x24, [sp, #48]
    ldp x21, x22, [sp, #32]
    ldp x19, x20, [sp, #16]
    ldp x29, x30, [sp], #112
    ret

.Lsym_initnet:
    .asciz "init_net"

.text
.globl cleanup_module
.type cleanup_module, %function
cleanup_module:
    ret
