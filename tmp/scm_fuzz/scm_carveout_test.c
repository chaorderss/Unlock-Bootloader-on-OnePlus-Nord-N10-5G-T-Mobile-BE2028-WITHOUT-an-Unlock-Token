/*
 * scm_carveout_test.c - Test IPA carveout accessibility
 *
 * test=0: just read first 64 bytes from carveout (no SCM)
 * test=1: write + readback to verify write works
 * test=2: shutdown IPA, then read carveout
 * test=3: shutdown IPA, write segments, readback verify, no auth
 * test=4: shutdown+init+memsetup+auth WITHOUT loading segments (confirm auth crashes)
 * test=5: shutdown, load segments via ioremap, iounmap, THEN init+memsetup+auth
 */
#include <linux/module.h>
#include <linux/kernel.h>
#include <linux/init.h>
#include <linux/mm.h>
#include <linux/delay.h>
#include <linux/moduleparam.h>
#include <linux/fs.h>
#include <linux/io.h>
#include <linux/slab.h>

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

#define SCM_SIP_FNID(s, c)  (0x42000000UL | (((s) & 0xFF) << 8) | ((c) & 0xFF))
#define IPA_PID     15
#define IPA_REGION  0x8b700000ULL
#define IPA_SIZE    0x10000ULL

extern int scm_call2(u32 fn_id, struct scm_desc *desc);
extern void __dma_flush_area(const void *start, size_t size);

static int scm_shutdown(void)
{
    struct scm_desc desc = {};
    desc.arginfo = 1;
    desc.args[0] = IPA_PID;
    return scm_call2(SCM_SIP_FNID(0x02, 0x06), &desc);
}

static int scm_init_image_from_file(void)
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

    desc.arginfo = 2 | (0 << 4) | (2 << 6);
    desc.args[0] = IPA_PID;
    desc.args[1] = virt_to_phys(buf);
    ret = scm_call2(SCM_SIP_FNID(0x02, 0x01), &desc);
    pr_info("cvt: init_image ret=%d\n", ret);
    free_pages((unsigned long)buf, order);
    return ret;
}

static int scm_mem_setup(void)
{
    struct scm_desc desc = {};
    int ret;
    desc.arginfo = 3;
    desc.args[0] = IPA_PID;
    desc.args[1] = IPA_REGION;
    desc.args[2] = IPA_SIZE;
    ret = scm_call2(SCM_SIP_FNID(0x02, 0x02), &desc);
    pr_info("cvt: mem_setup ret=%d\n", ret);
    return ret;
}

static int scm_auth_reset(void)
{
    struct scm_desc desc = {};
    int ret;
    desc.arginfo = 1;
    desc.args[0] = IPA_PID;
    ret = scm_call2(SCM_SIP_FNID(0x02, 0x05), &desc);
    pr_info("cvt: auth_reset ret=%d\n", ret);
    return ret;
}

static void *read_seg_file(const char *path, size_t *out_size)
{
    struct file *f;
    loff_t fsize, pos = 0;
    void *buf;
    f = filp_open(path, O_RDONLY, 0);
    if (IS_ERR(f)) return ERR_CAST(f);
    fsize = i_size_read(file_inode(f));
    buf = kmalloc(fsize, GFP_KERNEL);
    if (!buf) { filp_close(f, NULL); return ERR_PTR(-ENOMEM); }
    kernel_read(f, buf, fsize, &pos);
    filp_close(f, NULL);
    *out_size = fsize;
    return buf;
}

static int load_segments(void __iomem *co)
{
    struct { const char *p; u32 off; } segs[] = {
        {"/tmp/ipa_b02.bin", 0x0},
        {"/tmp/ipa_b03.bin", 0x5000},
        {"/tmp/ipa_b04.bin", 0x5080},
    };
    int i;

    memset_io(co, 0, IPA_SIZE);
    for (i = 0; i < 3; i++) {
        size_t sz;
        void *d = read_seg_file(segs[i].p, &sz);
        if (IS_ERR(d)) return PTR_ERR(d);
        memcpy_toio(co + segs[i].off, d, sz);
        pr_info("cvt: loaded %zu bytes at 0x%x\n", sz, segs[i].off);
        kfree(d);
    }
    mb();
    return 0;
}

static int __init cvt_init(void)
{
    void __iomem *co;
    int ret, i;
    u32 buf[16];

    pr_info("cvt: === test=%d ===\n", test);

    if (test == 0) {
        /* Just read from carveout - no SCM */
        co = ioremap_wc(IPA_REGION, IPA_SIZE);
        if (!co) { pr_err("cvt: ioremap failed\n"); goto out; }
        for (i = 0; i < 16; i++)
            buf[i] = readl_relaxed(co + i*4);
        pr_info("cvt: carveout[0-15]: %08x %08x %08x %08x %08x %08x %08x %08x\n",
                buf[0], buf[1], buf[2], buf[3], buf[4], buf[5], buf[6], buf[7]);
        pr_info("cvt: carveout[8-15]: %08x %08x %08x %08x %08x %08x %08x %08x\n",
                buf[8], buf[9], buf[10], buf[11], buf[12], buf[13], buf[14], buf[15]);
        iounmap(co);
    }
    else if (test == 1) {
        /* Write pattern, readback */
        co = ioremap_wc(IPA_REGION, IPA_SIZE);
        if (!co) { pr_err("cvt: ioremap failed\n"); goto out; }
        writel_relaxed(0xAA55AA55, co);
        writel_relaxed(0xDEADBEEF, co + 4);
        mb();
        buf[0] = readl_relaxed(co);
        buf[1] = readl_relaxed(co + 4);
        pr_info("cvt: write/read: %08x %08x (expect AA55AA55 DEADBEEF)\n", buf[0], buf[1]);
        /* Restore */
        writel_relaxed(0, co);
        writel_relaxed(0, co + 4);
        mb();
        iounmap(co);
    }
    else if (test == 2) {
        /* Shutdown then read */
        ret = scm_shutdown();
        pr_info("cvt: shutdown ret=%d\n", ret);
        msleep(200);
        co = ioremap_wc(IPA_REGION, IPA_SIZE);
        if (!co) { pr_err("cvt: ioremap failed\n"); goto out; }
        for (i = 0; i < 16; i++)
            buf[i] = readl_relaxed(co + i*4);
        pr_info("cvt: post-shutdown[0-7]: %08x %08x %08x %08x %08x %08x %08x %08x\n",
                buf[0], buf[1], buf[2], buf[3], buf[4], buf[5], buf[6], buf[7]);
        iounmap(co);
    }
    else if (test == 3) {
        /* Shutdown, load segments, verify readback */
        ret = scm_shutdown();
        pr_info("cvt: shutdown ret=%d\n", ret);
        msleep(200);
        co = ioremap_wc(IPA_REGION, IPA_SIZE);
        if (!co) { pr_err("cvt: ioremap failed\n"); goto out; }
        ret = load_segments(co);
        if (ret < 0) { iounmap(co); goto out; }
        /* Readback first 16 words */
        for (i = 0; i < 16; i++)
            buf[i] = readl_relaxed(co + i*4);
        pr_info("cvt: seg readback[0-7]: %08x %08x %08x %08x %08x %08x %08x %08x\n",
                buf[0], buf[1], buf[2], buf[3], buf[4], buf[5], buf[6], buf[7]);
        /* Readback from seg[3] offset */
        for (i = 0; i < 4; i++)
            buf[i] = readl_relaxed(co + 0x5000 + i*4);
        pr_info("cvt: seg3 readback: %08x %08x %08x %08x\n",
                buf[0], buf[1], buf[2], buf[3]);
        iounmap(co);
    }
    else if (test == 4) {
        /* Full PAS cycle WITHOUT loading segments */
        ret = scm_shutdown();
        pr_info("cvt: shutdown ret=%d\n", ret);
        msleep(100);
        ret = scm_init_image_from_file();
        if (ret) goto out;
        msleep(50);
        ret = scm_mem_setup();
        if (ret) goto out;
        msleep(50);
        pr_info("cvt: === calling auth_and_reset (NO segments loaded) ===\n");
        ret = scm_auth_reset();
        pr_info("cvt: auth ret=%d\n", ret);
    }
    else if (test == 5) {
        /* Load segments FIRST, unmap, THEN do PAS cycle */
        ret = scm_shutdown();
        pr_info("cvt: shutdown ret=%d\n", ret);
        msleep(200);

        /* Load segments */
        co = ioremap_wc(IPA_REGION, IPA_SIZE);
        if (!co) { pr_err("cvt: ioremap failed\n"); goto out; }
        ret = load_segments(co);
        if (ret < 0) { iounmap(co); goto out; }
        /* Verify a few bytes */
        buf[0] = readl_relaxed(co);
        pr_info("cvt: seg[2] first word: %08x\n", buf[0]);
        iounmap(co);
        pr_info("cvt: iounmap done, carveout released\n");
        msleep(100);

        /* Now PAS cycle */
        ret = scm_init_image_from_file();
        if (ret) goto out;
        msleep(50);
        ret = scm_mem_setup();
        if (ret) goto out;
        msleep(50);
        pr_info("cvt: === calling auth_and_reset (segments loaded, mapping released) ===\n");
        ret = scm_auth_reset();
        pr_info("cvt: auth ret=%d\n", ret);
    }

    else if (test == 6) {
        /* CORRECT PIL ORDER: shutdown → init → load → mem_setup → auth */
        ret = scm_shutdown();
        pr_info("cvt: shutdown ret=%d\n", ret);
        msleep(200);

        /* 1. Init image FIRST */
        ret = scm_init_image_from_file();
        pr_info("cvt: init_image ret=%d\n", ret);
        if (ret) goto out;
        msleep(50);

        /* 2. Load segments into carveout */
        co = ioremap_wc(IPA_REGION, IPA_SIZE);
        if (!co) { pr_err("cvt: ioremap failed\n"); goto out; }
        ret = load_segments(co);
        pr_info("cvt: segments loaded, ret=%d\n", ret);
        /* Verify */
        buf[0] = readl_relaxed(co);
        buf[1] = readl_relaxed(co + 0x5000);
        pr_info("cvt: verify seg[2][0]=0x%08x seg[3][0]=0x%08x\n", buf[0], buf[1]);
        iounmap(co);
        msleep(50);

        /* 3. Mem setup */
        ret = scm_mem_setup();
        pr_info("cvt: mem_setup ret=%d\n", ret);
        if (ret) goto out;
        msleep(50);

        /* 4. Auth and reset */
        pr_info("cvt: === calling auth_and_reset (CORRECT PIL ORDER) ===\n");
        ret = scm_auth_reset();
        pr_info("cvt: auth ret=%d\n", ret);
    }
    else if (test == 7) {
        /* NIL PID test: PID=23 (NPU) which may not be running */
        struct scm_desc desc = {};
        int npid = 23;
        pr_info("cvt: testing PID=%d (NPU)\n", npid);

        /* Shutdown NPU (might not be running) */
        desc.arginfo = 1;
        desc.args[0] = npid;
        ret = scm_call2(SCM_SIP_FNID(0x02, 0x06), &desc);
        pr_info("cvt: NPU shutdown ret=%d\n", ret);
        msleep(100);

        /* Init with IPA metadata for NPU PID */
        ret = scm_init_image_from_file();
        /* Override PID - we need to call with NPU PID */
        {
            struct file *f;
            loff_t fsize, pos = 0;
            void *mbuf;
            int order;
            struct scm_desc d2 = {};

            f = filp_open("/tmp/fw_meta.bin", O_RDONLY, 0);
            if (!IS_ERR(f)) {
                fsize = i_size_read(file_inode(f));
                order = get_order(fsize);
                mbuf = (void *)__get_free_pages(GFP_KERNEL | __GFP_ZERO, order);
                if (mbuf) {
                    kernel_read(f, mbuf, fsize, &pos);
                    __dma_flush_area(mbuf, PAGE_SIZE << order);
                    d2.arginfo = 2 | (0 << 4) | (2 << 6);
                    d2.args[0] = npid;
                    d2.args[1] = virt_to_phys(mbuf);
                    ret = scm_call2(SCM_SIP_FNID(0x02, 0x01), &d2);
                    pr_info("cvt: NPU init_image ret=%d\n", ret);
                    free_pages((unsigned long)mbuf, order);
                }
                filp_close(f, NULL);
            }
        }
        if (ret) goto out;
        msleep(50);

        /* Mem setup with IPA region */
        {
            struct scm_desc d3 = {};
            d3.arginfo = 3;
            d3.args[0] = npid;
            d3.args[1] = IPA_REGION;
            d3.args[2] = IPA_SIZE;
            ret = scm_call2(SCM_SIP_FNID(0x02, 0x02), &d3);
            pr_info("cvt: NPU mem_setup ret=%d\n", ret);
        }
        if (ret) goto out;
        msleep(50);

        /* Auth */
        {
            struct scm_desc d4 = {};
            d4.arginfo = 1;
            d4.args[0] = npid;
            pr_info("cvt: === NPU auth_and_reset ===\n");
            ret = scm_call2(SCM_SIP_FNID(0x02, 0x05), &d4);
            pr_info("cvt: NPU auth ret=%d\n", ret);
        }
    }

    else if (test == 10) {
        /* Minimal write test after shutdown */
        ret = scm_shutdown();
        pr_info("cvt: shutdown ret=%d\n", ret);
        msleep(200);
        co = ioremap_wc(IPA_REGION, 0x1000); /* only 1 page */
        if (!co) { pr_err("cvt: ioremap failed\n"); goto out; }
        pr_info("cvt: ioremap OK, reading first...\n");
        buf[0] = readl_relaxed(co);
        pr_info("cvt: read[0]=0x%08x, now writing...\n", buf[0]);
        writel_relaxed(0xCAFEBABE, co);
        mb();
        buf[1] = readl_relaxed(co);
        pr_info("cvt: write+readback=0x%08x (expect CAFEBABE)\n", buf[1]);
        /* restore */
        writel_relaxed(buf[0], co);
        mb();
        iounmap(co);
    }
    else if (test == 11) {
        /* Write 4K after shutdown */
        ret = scm_shutdown();
        pr_info("cvt: shutdown ret=%d\n", ret);
        msleep(200);
        co = ioremap_wc(IPA_REGION, 0x1000);
        if (!co) { pr_err("cvt: ioremap failed\n"); goto out; }
        pr_info("cvt: memset_io 4K...\n");
        memset_io(co, 0xAA, 0x1000);
        mb();
        buf[0] = readl_relaxed(co);
        pr_info("cvt: memset_io 4K done, read=0x%08x\n", buf[0]);
        iounmap(co);
    }
    else if (test == 12) {
        /* Write full 1MB after shutdown */
        ret = scm_shutdown();
        pr_info("cvt: shutdown ret=%d\n", ret);
        msleep(200);
        co = ioremap_wc(IPA_REGION, IPA_SIZE);
        if (!co) { pr_err("cvt: ioremap failed\n"); goto out; }
        pr_info("cvt: memset_io 1MB...\n");
        memset_io(co, 0, IPA_SIZE);
        mb();
        buf[0] = readl_relaxed(co);
        pr_info("cvt: memset_io 1MB done, read=0x%08x\n", buf[0]);
        iounmap(co);
    }

out:
    scm_shutdown();
    pr_info("cvt: === COMPLETE ===\n");
    return -EAGAIN;
}

static void __exit cvt_exit(void) {}
module_init(cvt_init);
module_exit(cvt_exit);
