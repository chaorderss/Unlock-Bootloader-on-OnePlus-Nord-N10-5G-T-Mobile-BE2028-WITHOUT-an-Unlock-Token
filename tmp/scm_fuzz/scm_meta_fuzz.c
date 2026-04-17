/*
 * scm_meta_fuzz.c - Systematic init_image metadata fuzzer
 *
 * Tests which bytes in the .mdt metadata TZ actually validates
 * by flipping individual bytes and checking init_image return value.
 *
 * test=0: baseline - pass unmodified metadata (should return 0)
 * test=1: byte-by-byte flip scan (start_off to end_off)
 * test=2: 16-byte block scan (faster, find interesting regions)
 * test=3: scan specific region in detail
 * test=4: test metadata truncation (pass shorter buffers)
 * test=5: test metadata extension (append data)
 * test=6: fuzz with specific byte values (0x00, 0xFF) at each offset
 *
 * Parameters:
 *   pid_val  - PAS ID (default 15 for IPA)
 *   start_off - start offset for scanning
 *   end_off  - end offset for scanning
 *   step     - step size for scanning
 */
#include <linux/module.h>
#include <linux/kernel.h>
#include <linux/init.h>
#include <linux/mm.h>
#include <linux/delay.h>
#include <linux/moduleparam.h>
#include <linux/fs.h>
#include <linux/slab.h>

MODULE_LICENSE("GPL");

static int test = 0;
module_param(test, int, 0);
static int pid_val = 15;
module_param(pid_val, int, 0);
static int start_off = 0;
module_param(start_off, int, 0);
static int end_off = 0; /* 0 = auto (file size) */
module_param(end_off, int, 0);
static int step = 1;
module_param(step, int, 0);

#define MAX_SCM_ARGS 10
#define MAX_SCM_RETS 3
struct scm_desc {
    u32 arginfo;
    u64 args[MAX_SCM_ARGS];
    u64 ret[MAX_SCM_RETS];
    u64 __pad[8];
};

#define SCM_SIP_FNID(s, c) (0x42000000UL | (((s) & 0xFF) << 8) | ((c) & 0xFF))
extern int scm_call2(u32 fn_id, struct scm_desc *desc);
extern void __dma_flush_area(const void *start, size_t size);

static int do_init_image(int pid, void *meta, size_t size)
{
    struct scm_desc desc = {};
    int order = get_order(size);
    void *buf;
    int ret;

    buf = (void *)__get_free_pages(GFP_KERNEL | __GFP_ZERO, order);
    if (!buf) return -ENOMEM;
    memcpy(buf, meta, size);
    __dma_flush_area(buf, PAGE_SIZE << order);

    desc.arginfo = 2 | (0 << 4) | (2 << 6);
    desc.args[0] = pid;
    desc.args[1] = virt_to_phys(buf);
    ret = scm_call2(SCM_SIP_FNID(0x02, 0x01), &desc);
    free_pages((unsigned long)buf, order);
    return ret;
}

static int do_shutdown(int pid)
{
    struct scm_desc desc = {};
    desc.arginfo = 1;
    desc.args[0] = pid;
    return scm_call2(SCM_SIP_FNID(0x02, 0x06), &desc);
}

static void *load_metadata(size_t *out_size)
{
    struct file *f;
    loff_t fsize, pos = 0;
    void *buf;

    f = filp_open("/tmp/fw_meta.bin", O_RDONLY, 0);
    if (IS_ERR(f)) return ERR_CAST(f);
    fsize = i_size_read(file_inode(f));
    if (fsize <= 0 || fsize > 128*1024) {
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

static int __init meta_fuzz_init(void)
{
    void *meta;
    size_t meta_size;
    int ret, i, baseline;
    int accepted = 0, rejected = 0;

    meta = load_metadata(&meta_size);
    if (IS_ERR(meta)) {
        pr_err("mfuzz: failed to load metadata: %ld\n", PTR_ERR(meta));
        return -EAGAIN;
    }
    pr_info("mfuzz: loaded metadata %zu bytes, test=%d pid=%d\n",
            meta_size, test, pid_val);

    /* Shutdown first */
    do_shutdown(pid_val);
    msleep(100);

    if (end_off == 0 || (size_t)end_off > meta_size)
        end_off = meta_size;

    if (test == 0) {
        /* Baseline */
        ret = do_init_image(pid_val, meta, meta_size);
        pr_info("mfuzz: baseline ret=%d\n", ret);
        do_shutdown(pid_val);
    }
    else if (test == 1) {
        /* Byte-by-byte flip scan */
        baseline = do_init_image(pid_val, meta, meta_size);
        do_shutdown(pid_val);
        msleep(50);
        pr_info("mfuzz: baseline=%d, scanning bytes %d-%d step=%d\n",
                baseline, start_off, end_off, step);

        for (i = start_off; i < end_off; i += step) {
            uint8_t *p = (uint8_t *)meta;
            uint8_t orig = p[i];

            p[i] ^= 0xFF; /* flip all bits */
            ret = do_init_image(pid_val, meta, meta_size);
            p[i] = orig; /* restore */
            do_shutdown(pid_val);

            if (ret == baseline) {
                accepted++;
                /* Only log accepted mutations (interesting!) */
                pr_info("mfuzz: ACCEPT off=0x%x orig=0x%02x\n", i, orig);
            } else {
                rejected++;
            }
            /* Brief pause every 100 iterations */
            if ((i - start_off) % 100 == 99)
                msleep(10);
        }
        pr_info("mfuzz: scan done: %d accepted, %d rejected\n",
                accepted, rejected);
    }
    else if (test == 2) {
        /* 16-byte block scan */
        baseline = do_init_image(pid_val, meta, meta_size);
        do_shutdown(pid_val);
        msleep(50);
        pr_info("mfuzz: block scan baseline=%d range=%d-%d\n",
                baseline, start_off, end_off);

        for (i = start_off; i < end_off; i += 16) {
            uint8_t *p = (uint8_t *)meta;
            uint8_t saved[16];
            int len = min(16, end_off - i);
            int j;

            memcpy(saved, p + i, len);
            for (j = 0; j < len; j++)
                p[i + j] ^= 0xFF;
            ret = do_init_image(pid_val, meta, meta_size);
            memcpy(p + i, saved, len);
            do_shutdown(pid_val);

            if (ret == baseline)
                pr_info("mfuzz: BLOCK_ACCEPT off=0x%03x-0x%03x\n", i, i+len-1);
            else
                pr_info("mfuzz: BLOCK_REJECT off=0x%03x-0x%03x ret=%d\n", i, i+len-1, ret);

            if ((i / 16) % 50 == 49)
                msleep(10);
        }
    }
    else if (test == 4) {
        /* Metadata truncation test */
        pr_info("mfuzz: truncation test\n");
        /* Try various truncated sizes */
        int sizes[] = {52, 100, 212, 256, 512, 1024, 2048, 4096, 4100, 4200, 4300, 4400, 4500, 4600, 4700, 4800, 4900, 5000, 5500, 6000, 6500, 6800, 6868};
        int ns = sizeof(sizes)/sizeof(sizes[0]);
        for (i = 0; i < ns; i++) {
            if ((size_t)sizes[i] > meta_size) continue;
            ret = do_init_image(pid_val, meta, sizes[i]);
            do_shutdown(pid_val);
            pr_info("mfuzz: trunc size=%d ret=%d\n", sizes[i], ret);
        }
    }
    else if (test == 5) {
        /* Extension test - append data */
        void *ext_meta;
        int ext_sizes[] = {6868+16, 6868+256, 6868+4096, 8192, 16384, 32768, 65536};
        int ns = sizeof(ext_sizes)/sizeof(ext_sizes[0]);
        pr_info("mfuzz: extension test\n");
        for (i = 0; i < ns; i++) {
            ext_meta = kzalloc(ext_sizes[i], GFP_KERNEL);
            if (!ext_meta) continue;
            memcpy(ext_meta, meta, meta_size);
            /* Fill extension with pattern */
            memset(ext_meta + meta_size, 0x41, ext_sizes[i] - meta_size);
            ret = do_init_image(pid_val, ext_meta, ext_sizes[i]);
            do_shutdown(pid_val);
            pr_info("mfuzz: ext size=%d ret=%d\n", ext_sizes[i], ret);
            kfree(ext_meta);
        }
    }
    else if (test == 6) {
        /* Test each offset with 0x00 and 0xFF */
        baseline = do_init_image(pid_val, meta, meta_size);
        do_shutdown(pid_val);
        pr_info("mfuzz: value scan baseline=%d range=%d-%d\n",
                baseline, start_off, end_off);

        for (i = start_off; i < end_off; i += step) {
            uint8_t *p = (uint8_t *)meta;
            uint8_t orig = p[i];
            int r0, rff;

            if (orig != 0x00) {
                p[i] = 0x00;
                r0 = do_init_image(pid_val, meta, meta_size);
                do_shutdown(pid_val);
            } else {
                r0 = baseline; /* setting to same value = baseline */
            }

            if (orig != 0xFF) {
                p[i] = 0xFF;
                rff = do_init_image(pid_val, meta, meta_size);
                do_shutdown(pid_val);
            } else {
                rff = baseline;
            }

            p[i] = orig;

            if (r0 == baseline || rff == baseline) {
                pr_info("mfuzz: FLEX off=0x%x orig=0x%02x set00=%d setFF=%d\n",
                        i, orig, r0, rff);
            }
        }
    }

    kfree(meta);
    do_shutdown(pid_val);
    pr_info("mfuzz: === COMPLETE ===\n");
    return -EAGAIN;
}

static void __exit meta_fuzz_exit(void) {}
module_init(meta_fuzz_init);
module_exit(meta_fuzz_exit);
