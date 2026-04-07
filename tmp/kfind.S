/*
 * kfind.S - Minimal module to look up and print cfg80211_mlme_mgmt_tx address
 * and dump first 64 instructions for analysis.
 * Build: as -o kfind.o kfind.S && ld -r -o kfind.ko kfind.o
 */

.section .gnu.linkonce.this_module, "aw"
.balign 256
__this_module:
    .fill 24, 1, 0
    .asciz "kfind"
    .fill 50, 1, 0             /* pad name to 56 bytes (24+6+50=80) */
    .fill 256, 1, 0            /* bytes 80-335: pad to offset 0x150 */
    .quad init_module          /* offset 0x150 = 336: init function */
    .fill 440, 1, 0            /* bytes 344-783: pad to offset 0x310 */
    .quad cleanup_module       /* offset 0x310 = 784: exit function */
    .fill 40, 1, 0             /* bytes 792-831: pad to 0x340 */

/* ============== .modinfo ============== */
.section .modinfo, "a"
    .asciz "vermagic=4.19.81-perf+ SMP preempt mod_unload modversions aarch64"
    .asciz "name=kfind"
    .asciz "license=GPL"
    .asciz "description=Dump wma_tx_packet instructions"

/* ============== __versions ============== */
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

/* ============== .rodata ============== */
.section .rodata, "a"
str_name:
    .asciz "wmi_mgmt_unified_cmd_send"
str_fmt:
    .asciz "kfind: wmi_mgmt_unified_cmd_send at %px\n"
str_ifmt:
    .asciz "kfind: +0x%03x: %08x\n"
str_notfound:
    .asciz "kfind: wmi_mgmt_unified_cmd_send not found\n"

/* ============== .data ============== */
.section .data, "aw"
func_addr:
    .quad 0

/* ============== .init.text ============== */
.section .init.text, "ax"
.globl init_module
.type init_module, %function
init_module:
    stp x29, x30, [sp, #-64]!
    mov x29, sp
    stp x19, x20, [sp, #16]
    stp x21, x22, [sp, #32]

    /* Look up cfg80211_mlme_mgmt_tx via kallsyms */
    adrp x0, str_name
    add x0, x0, :lo12:str_name
    bl kallsyms_lookup_name
    cbz x0, .Lnotfound
    mov x20, x0                /* x20 = cfg80211_mlme_mgmt_tx addr */

    /* Save address */
    adrp x1, func_addr
    add x1, x1, :lo12:func_addr
    str x20, [x1]

    /* Print address */
    adrp x0, str_fmt
    add x0, x0, :lo12:str_fmt
    mov x1, x20
    bl printk

    /* Dump instructions 0-128 */
    mov x21, #0                /* start offset (instruction index) */
    mov x22, #256              /* end offset */
.Ldump_loop:
    cmp x21, x22
    b.ge .Ldone

    ldr w2, [x20, x21, lsl #2]  /* read instruction at func + index*4 */
    lsl w1, w21, #2              /* byte offset = index * 4 */
    adrp x0, str_ifmt
    add x0, x0, :lo12:str_ifmt
    bl printk

    add x21, x21, #1
    b .Ldump_loop

.Ldone:
    mov w0, #0
    ldp x21, x22, [sp, #32]
    ldp x19, x20, [sp, #16]
    ldp x29, x30, [sp], #64
    ret

.Lnotfound:
    adrp x0, str_notfound
    add x0, x0, :lo12:str_notfound
    bl printk
    mov w0, #-1
    ldp x21, x22, [sp, #32]
    ldp x19, x20, [sp, #16]
    ldp x29, x30, [sp], #64
    ret

/* ============== .exit.text ============== */
.section .exit.text, "ax"
.globl cleanup_module
.type cleanup_module, %function
cleanup_module:
    ret

/* ============== .note.Linux ============== */
.section .note.Linux, "a", @note
    .long 6
    .long 0
    .long 0x100
    .asciz "Linux"
    .balign 4

/* ============== PLT sections ============== */
.section .plt, "ax"
    .balign 8
    .space 8

.section .init.plt, "ax"
    .balign 8
    .space 8

.section .text.ftrace_trampoline, "ax"
    .balign 8
    .space 8
