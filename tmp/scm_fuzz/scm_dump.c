/*
 * scm_dump.c - Dump scm_call2 function bytes for disassembly
 */
#include <linux/module.h>
#include <linux/kernel.h>
#include <linux/init.h>

MODULE_LICENSE("GPL");

extern int scm_call2(unsigned long fn_id, void *desc);

static int __init scm_dump_init(void)
{
    unsigned char *p = (unsigned char *)scm_call2;
    int i;

    pr_info("scm_dump: scm_call2 at %px\n", p);

    /* Dump 1024 bytes (covers scm_call2 + __scm_call2) in hex lines */
    for (i = 0; i < 1024; i += 16) {
        pr_info("scm_dump: %04x: %*ph\n", i, 16, p + i);
    }

    return 0;
}

static void __exit scm_dump_exit(void)
{
    pr_info("scm_dump: unloaded\n");
}

module_init(scm_dump_init);
module_exit(scm_dump_exit);
