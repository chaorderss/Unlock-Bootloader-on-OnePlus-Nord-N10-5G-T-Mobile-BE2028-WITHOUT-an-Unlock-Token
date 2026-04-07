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
sym_gmc:    .asciz "global_mac_context"
sym_wvs:    .asciz "wma_vdev_start"
fmt_gmc:    .asciz "kfwma: global_mac_ctx addr=%px val=%px\n"
fmt_mac:    .asciz "kfwma: mac+%04x: %016px\n"
fmt_found:  .asciz "kfwma: CANDIDATE wma at mac+0x%04x = %px (first_field=%px)\n"
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

    /* Get global_mac_context */
    adrp x0, sym_gmc
    add x0, x0, :lo12:sym_gmc
    bl kallsyms_lookup_name
    mov x19, x0
    cbz x0, .Lret

    /* Read the pointer value */
    ldr x20, [x19]    /* x20 = MAC context pointer */

    adrp x0, fmt_gmc
    add x0, x0, :lo12:fmt_gmc
    mov x1, x19
    mov x2, x20
    bl printk

    cbz x20, .Lret

    /* Dump first 2048 bytes of MAC context, looking for pointers 
     * Skip huge dump, just look at common WMA offsets: 
     * Many driver versions have WMA at mac->wma_handle 
     * Try offsets 0x00-0x100 step 8
     */
    mov x21, #0
.Ldump:
    ldr x22, [x20, x21]
    
    /* Print all non-null pointers */
    cbz x22, .Lskip
    
    /* Check if pointer looks like a heap pointer (0xffffffd...) */
    lsr x23, x22, #40
    mov x24, #0xffff
    movk x24, #0xff, lsl #16
    cmp x23, x24
    b.lo .Lskip

    adrp x0, fmt_mac
    add x0, x0, :lo12:fmt_mac
    mov x1, x21
    mov x2, x22
    bl printk

.Lskip:
    add x21, x21, #8
    cmp x21, #4096
    b.lt .Ldump

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
