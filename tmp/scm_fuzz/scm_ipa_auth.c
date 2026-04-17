/*
 * scm_ipa_auth.c - Full IPA PIL auth cycle with real firmware loading
 *
 * test=0: load segments + full auth cycle (normal path)
 * test=1: load segments with mutated seg[2] (first 16 bytes zeroed)
 * test=2: load segments with all-zero seg[2]
 * test=3: load segments but skip seg[2] (leave carveout zeroed)
 * test=4: load segments, auth, then re-auth without re-init (double auth)
 * test=5: load segments with e_entry mutated in metadata
 * test=6: load flipped hash segment (corrupt hash table)
 * test=7: auth with smaller mem_setup size (0x1000 instead of 0x100000)
 * test=8: auth with oversized mem_setup (0x200000)
 * test=9: load segments, auth, modify seg in carveout, re-auth
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

#define SCM_SIP_FNID(s, c)    (0x42000000UL | (((s) & 0xFF) << 8) | ((c) & 0xFF))
#define IPA_PID     15
#define IPA_REGION  0x8b700000ULL
#define IPA_SIZE    0x10000ULL

extern int scm_call2(u32 fn_id, struct scm_desc *desc);
extern void __dma_flush_area(const void *start, size_t size);

/* 32-bit ELF program header */
struct elf32_phdr_s {
    uint32_t p_type;
    uint32_t p_offset;
    uint32_t p_vaddr;
    uint32_t p_paddr;
    uint32_t p_filesz;
    uint32_t p_memsz;
    uint32_t p_flags;
    uint32_t p_align;
};

static int scm_shutdown(void)
{
    struct scm_desc desc = {};
    desc.arginfo = 1;
    desc.args[0] = IPA_PID;
    return scm_call2(SCM_SIP_FNID(0x02, 0x06), &desc);
}

static int scm_init_image(void *meta_buf, size_t meta_size)
{
    struct scm_desc desc = {};
    int order = get_order(meta_size);
    void *dma_buf;
    int ret;

    dma_buf = (void *)__get_free_pages(GFP_KERNEL | __GFP_ZERO, order);
    if (!dma_buf) return -ENOMEM;
    memcpy(dma_buf, meta_buf, meta_size);
    __dma_flush_area(dma_buf, PAGE_SIZE << order);

    desc.arginfo = 2 | (0 << 4) | (2 << 6); /* 2 args: VAL, RW */
    desc.args[0] = IPA_PID;
    desc.args[1] = virt_to_phys(dma_buf);

    ret = scm_call2(SCM_SIP_FNID(0x02, 0x01), &desc);
    pr_info("ipa_auth: init_image ret=%d r0=0x%llx\n", ret, desc.ret[0]);
    free_pages((unsigned long)dma_buf, order);
    return ret;
}

static int scm_mem_setup(u64 addr, u64 size)
{
    struct scm_desc desc = {};
    int ret;
    desc.arginfo = 3;
    desc.args[0] = IPA_PID;
    desc.args[1] = addr;
    desc.args[2] = size;
    ret = scm_call2(SCM_SIP_FNID(0x02, 0x02), &desc);
    pr_info("ipa_auth: mem_setup(0x%llx, 0x%llx) ret=%d r0=0x%llx\n",
            addr, size, ret, desc.ret[0]);
    return ret;
}

static int scm_auth_reset(void)
{
    struct scm_desc desc = {};
    int ret;
    desc.arginfo = 1;
    desc.args[0] = IPA_PID;
    ret = scm_call2(SCM_SIP_FNID(0x02, 0x05), &desc);
    pr_info("ipa_auth: auth_reset ret=%d r0=0x%llx\n", ret, desc.ret[0]);
    return ret;
}

static void *read_file_alloc(const char *path, size_t *out_size)
{
    struct file *f;
    loff_t fsize, pos = 0;
    void *buf;

    f = filp_open(path, O_RDONLY, 0);
    if (IS_ERR(f)) return ERR_CAST(f);
    fsize = i_size_read(file_inode(f));
    if (fsize <= 0 || fsize > 1024*1024) {
        filp_close(f, NULL);
        return ERR_PTR(-EINVAL);
    }
    buf = kmalloc(fsize, GFP_KERNEL);
    if (!buf) { filp_close(f, NULL); return ERR_PTR(-ENOMEM); }
    kernel_read(f, buf, fsize, &pos);
    filp_close(f, NULL);
    *out_size = fsize;
    return buf;
}

static int load_segments_to_carveout(void __iomem *carveout, int test_mode)
{
    /* Segment files and their offsets in carveout (from ELF paddr) */
    static const struct {
        const char *path;
        uint32_t paddr;  /* offset into carveout */
        uint32_t filesz;
        int seg_idx;
    } segs[] = {
        { "/tmp/ipa_b02.bin", 0x00000, 0x3690, 2 },
        { "/tmp/ipa_b03.bin", 0x05000, 0x80,   3 },
        { "/tmp/ipa_b04.bin", 0x05080, 0x230,  4 },
    };
    int i, loaded = 0;

    /* Zero the carveout first */
    memset_io(carveout, 0, IPA_SIZE);

    for (i = 0; i < ARRAY_SIZE(segs); i++) {
        size_t fsize;
        void *data;

        /* test=3: skip seg[2] entirely */
        if (test_mode == 3 && segs[i].seg_idx == 2)
            continue;

        data = read_file_alloc(segs[i].path, &fsize);
        if (IS_ERR(data)) {
            pr_err("ipa_auth: failed to read %s: %ld\n",
                   segs[i].path, PTR_ERR(data));
            return PTR_ERR(data);
        }

        if (fsize > segs[i].filesz) fsize = segs[i].filesz;

        /* test=1: zero first 16 bytes of seg[2] */
        if (test_mode == 1 && segs[i].seg_idx == 2) {
            memset(data, 0, min((size_t)16, fsize));
            pr_info("ipa_auth: zeroed first 16 bytes of seg[2]\n");
        }

        /* test=2: all-zero seg[2] */
        if (test_mode == 2 && segs[i].seg_idx == 2) {
            memset(data, 0, fsize);
            pr_info("ipa_auth: zeroed all of seg[2]\n");
        }

        pr_info("ipa_auth: loading seg[%d] %u bytes at offset 0x%x\n",
                segs[i].seg_idx, (unsigned)fsize, segs[i].paddr);
        memcpy_toio(carveout + segs[i].paddr, data, fsize);
        kfree(data);
        loaded++;
    }

    /* Flush after writing all segments */
    mb();
    return loaded;
}

static int __init run_auth_cycle(void *meta_buf, size_t meta_size,
                                  void __iomem *carveout, u64 mem_size)
{
    int ret;

    /* 1. Shutdown */
    ret = scm_shutdown();
    pr_info("ipa_auth: shutdown ret=%d\n", ret);
    msleep(100);

    /* 2. Init image */
    ret = scm_init_image(meta_buf, meta_size);
    if (ret) {
        pr_err("ipa_auth: init_image failed: %d\n", ret);
        return ret;
    }
    msleep(50);

    /* 3. Load segments into carveout */
    ret = load_segments_to_carveout(carveout, test);
    if (ret < 0) {
        pr_err("ipa_auth: segment load failed: %d\n", ret);
        return ret;
    }
    pr_info("ipa_auth: loaded %d segments\n", ret);
    msleep(50);

    /* 4. Mem setup */
    ret = scm_mem_setup(IPA_REGION, mem_size);
    if (ret) {
        pr_err("ipa_auth: mem_setup failed: %d\n", ret);
        return ret;
    }
    msleep(50);

    /* 5. Auth and reset */
    pr_info("ipa_auth: === calling auth_and_reset ===\n");
    ret = scm_auth_reset();
    pr_info("ipa_auth: auth_and_reset returned %d\n", ret);
    return ret;
}

static int __init ipa_auth_init(void)
{
    void *meta_buf = NULL;
    void __iomem *carveout = NULL;
    size_t meta_size;
    int ret;
    u64 mem_size = IPA_SIZE;

    pr_info("ipa_auth: === test=%d ===\n", test);

    /* Read metadata */
    meta_buf = read_file_alloc("/tmp/fw_meta.bin", &meta_size);
    if (IS_ERR(meta_buf)) {
        pr_err("ipa_auth: failed to read metadata: %ld\n", PTR_ERR(meta_buf));
        return -EAGAIN;
    }
    pr_info("ipa_auth: metadata size=%zu\n", meta_size);

    /* Map IPA carveout */
    carveout = ioremap_wc(IPA_REGION, IPA_SIZE);
    if (!carveout) {
        pr_err("ipa_auth: failed to ioremap 0x%llx\n", IPA_REGION);
        kfree(meta_buf);
        return -EAGAIN;
    }
    pr_info("ipa_auth: mapped carveout at 0x%llx\n", IPA_REGION);

    /* test=5: mutate e_entry in metadata */
    if (test == 5) {
        uint32_t *e_entry = (uint32_t *)(meta_buf + 0x18); /* 32-bit ELF e_entry offset */
        pr_info("ipa_auth: original e_entry=0x%x, setting to 0xdeadbeef\n", *e_entry);
        *e_entry = 0xdeadbeef;
    }

    /* test=6: corrupt hash table in metadata */
    if (test == 6) {
        /* seg[1] at offset 0x1000 is hash table, flip all bits */
        size_t i;
        uint8_t *p = meta_buf;
        pr_info("ipa_auth: flipping hash table bits (offset 0x1000+)\n");
        for (i = 0x1000; i < meta_size && i < 0x1000 + 0x1a00; i++)
            p[i] ^= 0xff;
    }

    /* test=7: smaller mem_setup */
    if (test == 7) {
        mem_size = 0x6000; /* just enough for segments: max is paddr 0x5080+0x230=0x52b0 */
        pr_info("ipa_auth: using small mem_size=0x%llx\n", mem_size);
    }

    /* test=8: oversized mem_setup */
    if (test == 8) {
        mem_size = 0x200000;
        pr_info("ipa_auth: using oversized mem_size=0x%llx\n", mem_size);
    }

    /* Run the auth cycle */
    ret = run_auth_cycle(meta_buf, meta_size, carveout, mem_size);

    /* test=4: double auth - try auth again without re-init */
    if (test == 4 && ret == 0) {
        pr_info("ipa_auth: === double auth attempt ===\n");
        msleep(100);
        ret = scm_auth_reset();
        pr_info("ipa_auth: double auth ret=%d\n", ret);
    }

    /* test=9: modify carveout after auth, then re-auth */
    if (test == 9 && ret == 0) {
        pr_info("ipa_auth: === post-auth carveout modification ===\n");
        /* Flip first 4 bytes of code segment */
        uint32_t val;
        val = readl_relaxed(carveout);
        writel_relaxed(val ^ 0xffffffff, carveout);
        mb();
        msleep(50);
        /* Shutdown and try re-auth with modified carveout */
        scm_shutdown();
        msleep(100);
        ret = scm_init_image(meta_buf, meta_size);
        if (ret == 0) {
            ret = scm_mem_setup(IPA_REGION, IPA_SIZE);
            if (ret == 0) {
                pr_info("ipa_auth: === re-auth with modified carveout ===\n");
                ret = scm_auth_reset();
                pr_info("ipa_auth: re-auth with modified data ret=%d\n", ret);
            }
        }
    }

    /* Cleanup */
    scm_shutdown();
    iounmap(carveout);
    kfree(meta_buf);

    pr_info("ipa_auth: === COMPLETE ret=%d ===\n", ret);
    return -EAGAIN;
}

static void __exit ipa_auth_exit(void) {}
module_init(ipa_auth_init);
module_exit(ipa_auth_exit);
