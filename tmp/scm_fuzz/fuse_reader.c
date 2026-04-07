/*
 * fuse_reader.c - Read QFPROM fuse values carefully
 * Only read known-safe regions to avoid TZ faults
 */

#include <linux/module.h>
#include <linux/kernel.h>
#include <linux/io.h>

MODULE_LICENSE("GPL");

#define QFPROM_CORR_BASE    0x00780000ULL
#define QFPROM_SIZE         0x7000

static int __init fuse_reader_init(void)
{
    void __iomem *base;
    u32 val;
    int i;

    pr_info("fuse_reader: mapping QFPROM at PA 0x%llx size 0x%x\n", QFPROM_CORR_BASE, QFPROM_SIZE);

    base = ioremap(QFPROM_CORR_BASE, QFPROM_SIZE);
    if (!base) {
        pr_err("fuse_reader: ioremap failed\n");
        return -ENOMEM;
    }

    pr_info("fuse_reader: mapped OK\n");

    /* Read security/config area only (0x6000-0x6200) */
    pr_info("fuse_reader: === Security Config 0x6000-0x6200 ===\n");
    for (i = 0x6000; i < 0x6200; i += 4) {
        val = readl(base + i);
        pr_info("fuse_reader: +0x%04x = 0x%08x\n", i, val);
    }

    iounmap(base);
    pr_info("fuse_reader: done\n");

    return -EAGAIN;
}

static void __exit fuse_reader_exit(void)
{
    pr_info("fuse_reader: unloaded\n");
}

module_init(fuse_reader_init);
module_exit(fuse_reader_exit);
