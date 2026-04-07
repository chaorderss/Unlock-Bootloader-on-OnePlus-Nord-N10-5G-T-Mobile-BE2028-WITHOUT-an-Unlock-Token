/* scm_test_init.c - Minimal init_image test
 * Compare with scm_fuzz4 op=1 which works */
#include <linux/module.h>
#include <linux/kernel.h>
#include <linux/init.h>
#include <linux/slab.h>
#include <linux/mm.h>

MODULE_LICENSE("GPL");

struct scm_desc {
    u32 arginfo;
    u64 args[10];
    u64 ret[3];
};

extern int scm_call2(u32 fn_id, struct scm_desc *desc);

static int __init scm_test_init_init(void)
{
    struct scm_desc desc;
    void *buf;
    phys_addr_t phys;
    int ret;

    buf = (void *)__get_free_pages(GFP_KERNEL | __GFP_ZERO, 0);
    if (!buf) return -ENOMEM;

    phys = virt_to_phys(buf);
    pr_info("scm_test: buf=%px phys=0x%llx\n", buf, (u64)phys);

    memset(&desc, 0, sizeof(desc));
    desc.arginfo = 2 | (0 << 4) | (2 << 6); /* ARGS_2(VAL, RW) */
    desc.args[0] = 9;
    desc.args[1] = phys;

    pr_info("scm_test: calling scm_call2...\n");
    ret = scm_call2(0x42000201, &desc);
    pr_info("scm_test: ret=%d r0=0x%llx\n", ret, desc.ret[0]);

    free_pages((unsigned long)buf, 0);
    return 0;
}

static void __exit scm_test_init_exit(void)
{
    pr_info("scm_test: unloaded\n");
}

module_init(scm_test_init_init);
module_exit(scm_test_init_exit);
