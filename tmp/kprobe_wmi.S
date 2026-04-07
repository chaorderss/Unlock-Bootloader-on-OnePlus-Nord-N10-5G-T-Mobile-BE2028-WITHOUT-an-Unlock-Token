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
sym_gp:     .asciz "gp_cds_context"
sym_svs:    .asciz "send_vdev_start_cmd_tlv"
sym_wba:    .asciz "wmi_buf_alloc_fl"
fmt_ptrs:   .asciz "kwmi: cds_d0=%px cds_d8=%px cds_e0=%px\n"
fmt_wma:    .asciz "kwmi: wma+%03x: %016px\n"
fmt_found:  .asciz "kwmi: FOUND wmi_handle at wma+0x%03x: %px\n"
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

    /* Get gp_cds_context */
    adrp x0, sym_gp
    add x0, x0, :lo12:sym_gp
    bl kallsyms_lookup_name
    mov x19, x0
    cbz x0, .Lret

    /* Get send_vdev_start_cmd_tlv address for reference */
    adrp x0, sym_svs
    add x0, x0, :lo12:sym_svs
    bl kallsyms_lookup_name
    mov x22, x0

    /* Get wmi_buf_alloc_fl for finding wmi_handle */
    adrp x0, sym_wba
    add x0, x0, :lo12:sym_wba
    bl kallsyms_lookup_name
    mov x23, x0      /* x23 = wmi_buf_alloc address */

    /* Deref gp_cds_context to get CDS struct */
    ldr x20, [x19]    /* x20 = &g_cds_context struct */
    cbz x20, .Lret

    /* Load pointers at +0xD0, +0xD8, +0xE0 */
    ldr x24, [x20, #0xD0]  /* possible MAC ctx */
    ldr x25, [x20, #0xD8]  /* possible WMA ctx */
    ldr x26, [x20, #0xE0]  /* possible DP SOC */

    adrp x0, fmt_ptrs
    add x0, x0, :lo12:fmt_ptrs
    mov x1, x24
    mov x2, x25
    mov x3, x26
    bl printk

    /* Now dump the WMA handle candidate (at cds+0xD8) looking for WMI handle
     * The WMI handle is typically in the first few hundred bytes.
     * We look for a pointer that, when deref'd, contains wmi_buf_alloc in its ops table.
     * But simpler: just dump first 512 bytes and look for kernel pointers.
     */
    cbz x25, .Lret

    mov x21, #0
.Ldump_wma:
    adrp x0, fmt_wma
    add x0, x0, :lo12:fmt_wma
    mov x1, x21
    ldr x2, [x25, x21]
    bl printk
    add x21, x21, #8
    cmp x21, #512
    b.lt .Ldump_wma

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
