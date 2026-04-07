/*
 * kprobe6.S - Check WMI_SERVICE_MGMT_TX_WMI and try calling wma_mgmt_unified_cmd_send
 * Build: as -o kprobe6.o kprobe6.S && ld -r -o kprobe6.ko kprobe6.o
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
str_cds:
    .asciz "cds_get_context"
str_svc:
    .asciz "wmi_service_enabled"
fmt_svc:
    .asciz "kp6: wmi_service_enabled(0x5B) = %d\n"
fmt_wmi:
    .asciz "kp6: wmi_handle=%px wma=%px\n"
fmt_err:
    .asciz "kp6: error\n"

.section .init.text, "ax"
.globl init_module
.type init_module, %function
init_module:
    stp x29, x30, [sp, #-64]!
    mov x29, sp
    stp x19, x20, [sp, #16]
    stp x21, x22, [sp, #32]

    /* Resolve cds_get_context */
    adrp x0, str_cds
    add x0, x0, :lo12:str_cds
    bl kallsyms_lookup_name
    cbz x0, .Lerr
    mov x19, x0

    /* Resolve wmi_service_enabled */
    adrp x0, str_svc
    add x0, x0, :lo12:str_svc
    bl kallsyms_lookup_name
    cbz x0, .Lerr
    mov x20, x0

    /* Get WMA context (ID=54) */
    mov w0, #54
    blr x19
    cbz x0, .Lerr
    mov x21, x0              /* x21 = wma */

    /* Get wmi_handle = wma[0x0] */
    ldr x22, [x21]            /* x22 = wmi_handle */

    adrp x0, fmt_wmi
    add x0, x0, :lo12:fmt_wmi
    mov x1, x22
    mov x2, x21
    bl printk

    /* Check WMI_SERVICE_MGMT_TX_WMI = 0x5B (91) */
    mov x0, x22               /* wmi_handle */
    mov w1, #0x5B             /* service ID 91 */
    blr x20                   /* wmi_service_enabled */

    mov w23, w0
    adrp x0, fmt_svc
    add x0, x0, :lo12:fmt_svc
    mov w1, w23
    bl printk

    mov w0, #0
    ldp x21, x22, [sp, #32]
    ldp x19, x20, [sp, #16]
    ldp x29, x30, [sp], #64
    ret

.Lerr:
    adrp x0, fmt_err
    add x0, x0, :lo12:fmt_err
    bl printk
    mov w0, #-1
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
