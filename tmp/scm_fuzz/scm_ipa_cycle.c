/*
 * scm_ipa_cycle.c - Full PAS auth cycle for IPA (PID 15)
 * Step-by-step with logging between each SCM call
 *
 * test=0: init_image only (baseline)
 * test=1: init + mem_setup
 * test=2: init + mem_setup + auth_and_reset
 * test=3: init + mem_setup (normal argcount) + auth (normal)
 */
#include <linux/module.h>
#include <linux/kernel.h>
#include <linux/init.h>
#include <linux/mm.h>
#include <linux/delay.h>
#include <linux/moduleparam.h>
#include <linux/fs.h>

MODULE_LICENSE("GPL");

static int test = 0;
module_param(test, int, 0);

#define MAX_SCM_ARGS 10
#define MAX_SCM_RETS 3
struct scm_desc {
    u32 arginfo;
    u64 args[MAX_SCM_ARGS];
    u64 ret[MAX_SCM_RETS];
    u64 __pad[8];
};

#define SCM_SIP_FNID(s, c)    (0x42000000UL | (((s) & 0xFF) << 8) | ((c) & 0xFF))
#define IPA_PID     15
#define IPA_REGION  0x8b700000ULL
#define IPA_SIZE    0x10000ULL

extern int scm_call2(u32 fn_id, struct scm_desc *desc);
extern void __dma_flush_area(const void *start, size_t size);

static int __init do_shutdown(void)
{
    struct scm_desc desc = {};
    desc.arginfo = 1;
    desc.args[0] = IPA_PID;
    return scm_call2(SCM_SIP_FNID(0x02, 0x06), &desc);
}

static int __init do_init_image(void)
{
    struct file *f;
    loff_t fsize, pos = 0;
    void *buf;
    int order, ret;
    struct scm_desc desc = {};

    f = filp_open("/tmp/fw_meta.bin", O_RDONLY, 0);
    if (IS_ERR(f)) return PTR_ERR(f);
    fsize = i_size_read(file_inode(f));
    if (fsize <= 0 || fsize > 64*1024) { filp_close(f, NULL); return -EINVAL; }
    order = get_order(fsize);
    buf = (void *)__get_free_pages(GFP_KERNEL | __GFP_ZERO, order);
    if (!buf) { filp_close(f, NULL); return -ENOMEM; }
    kernel_read(f, buf, fsize, &pos);
    filp_close(f, NULL);
    __dma_flush_area(buf, PAGE_SIZE << order);

    desc.arginfo = 2 | (0 << 4) | (2 << 6); /* 2 args, VAL + RW */
    desc.args[0] = IPA_PID;
    desc.args[1] = virt_to_phys(buf);

    pr_info("ipa_cycle: init_image phys=0x%llx size=%lld\n",
            (u64)virt_to_phys(buf), fsize);
    ret = scm_call2(SCM_SIP_FNID(0x02, 0x01), &desc);
    pr_info("ipa_cycle: init_image ret=%d r0=0x%llx\n", ret, desc.ret[0]);
    free_pages((unsigned long)buf, order);
    return ret;
}

static int __init do_mem_setup(void)
{
    struct scm_desc desc = {};
    int ret;
    desc.arginfo = 3; /* 3 args, all VAL */
    desc.args[0] = IPA_PID;
    desc.args[1] = IPA_REGION;
    desc.args[2] = IPA_SIZE;
    pr_info("ipa_cycle: mem_setup addr=0x%llx size=0x%llx\n", IPA_REGION, IPA_SIZE);
    ret = scm_call2(SCM_SIP_FNID(0x02, 0x02), &desc);
    pr_info("ipa_cycle: mem_setup ret=%d r0=0x%llx\n", ret, desc.ret[0]);
    return ret;
}

static int __init do_auth_reset(void)
{
    struct scm_desc desc = {};
    int ret;
    desc.arginfo = 1;
    desc.args[0] = IPA_PID;
    pr_info("ipa_cycle: auth_and_reset\n");
    ret = scm_call2(SCM_SIP_FNID(0x02, 0x05), &desc);
    pr_info("ipa_cycle: auth_reset ret=%d r0=0x%llx\n", ret, desc.ret[0]);
    return ret;
}

static int __init ipa_cycle_init(void)
{
    int ret;
    pr_info("ipa_cycle: === test=%d ===\n", test);

    /* Always start with shutdown */
    ret = do_shutdown();
    pr_info("ipa_cycle: shutdown ret=%d\n", ret);
    msleep(100);

    if (test >= 0) {
        ret = do_init_image();
        pr_info("ipa_cycle: === init_image done, ret=%d ===\n", ret);
        if (ret != 0) goto done;
    }

    if (test >= 1) {
        msleep(50);
        ret = do_mem_setup();
        pr_info("ipa_cycle: === mem_setup done, ret=%d ===\n", ret);
        if (ret != 0) goto done;
    }

    if (test >= 2) {
        msleep(50);
        ret = do_auth_reset();
        pr_info("ipa_cycle: === auth_reset done, ret=%d ===\n", ret);
    }

done:
    /* Cleanup: shutdown */
    do_shutdown();
    pr_info("ipa_cycle: === COMPLETE ===\n");
    return -EAGAIN;
}

static void __exit ipa_cycle_exit(void) {}
module_init(ipa_cycle_init);
module_exit(ipa_cycle_exit);
