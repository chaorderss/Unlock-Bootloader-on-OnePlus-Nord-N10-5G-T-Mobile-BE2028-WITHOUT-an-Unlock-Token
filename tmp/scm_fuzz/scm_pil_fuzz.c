/*
 * scm_pil_fuzz.c - Fuzz PIL authentication SCM calls
 *
 * Tests:
 * 1. pas_init_image with various PIDs + crafted metadata
 * 2. pas_auth_and_reset with unexpected PIDs
 * 3. pas_mem_setup with WLAN MSA addresses
 * 4. Try to abuse supported PIDs to affect WLAN memory
 */

#include <linux/module.h>
#include <linux/kernel.h>
#include <linux/io.h>
#include <linux/dma-mapping.h>
#include <linux/slab.h>
#include <linux/delay.h>
#include <linux/kallsyms.h>

MODULE_LICENSE("GPL");

static int test = 0;
module_param(test, int, 0);

/* kallsyms approach */
typedef unsigned long (*kallsyms_fn)(const char *name);
static kallsyms_fn ks_lookup;

/* SCM call function types */
typedef int (*scm_pas_init_fn)(u32 peripheral, const void *metadata, int size);
typedef int (*scm_pas_mem_fn)(u32 peripheral, phys_addr_t addr, phys_addr_t size);
typedef int (*scm_pas_auth_fn)(u32 peripheral);
typedef int (*scm_pas_shutdown_fn)(u32 peripheral);
typedef bool (*scm_pas_supported_fn)(u32 peripheral);

static scm_pas_init_fn pas_init_image;
static scm_pas_mem_fn pas_mem_setup;
static scm_pas_auth_fn pas_auth_and_reset;
static scm_pas_shutdown_fn pas_shutdown;
static scm_pas_supported_fn pas_supported;

#define MSA_PA      0x8b500000ULL
#define MSA_SIZE    0x200000

static int resolve_symbols(void)
{
    ks_lookup = (kallsyms_fn)kallsyms_lookup_name;
    if (!ks_lookup) {
        pr_err("scm_pil_fuzz: no kallsyms_lookup_name\n");
        return -ENOENT;
    }

    pas_init_image = (scm_pas_init_fn)ks_lookup("qcom_scm_pas_init_image");
    pas_mem_setup = (scm_pas_mem_fn)ks_lookup("qcom_scm_pas_mem_setup");
    pas_auth_and_reset = (scm_pas_auth_fn)ks_lookup("qcom_scm_pas_auth_and_reset");
    pas_shutdown = (scm_pas_shutdown_fn)ks_lookup("qcom_scm_pas_shutdown");
    pas_supported = (scm_pas_supported_fn)ks_lookup("qcom_scm_pas_supported");

    pr_info("scm_pil_fuzz: pas_init=%px mem=%px auth=%px shutdown=%px supported=%px\n",
            pas_init_image, pas_mem_setup, pas_auth_and_reset, pas_shutdown, pas_supported);

    return (pas_init_image && pas_mem_setup && pas_auth_and_reset &&
            pas_shutdown && pas_supported) ? 0 : -ENOENT;
}

/* Test 0: Check PAS support for known-safe PIDs only */
static void test_pas_support(void)
{
    int safe_pids[] = {1, 4, 9, 10, 13, 15, 18, 19, 20, 21, 23};
    int i;
    pr_info("scm_pil_fuzz: === PAS Support Scan (safe PIDs only) ===\n");
    for (i = 0; i < sizeof(safe_pids)/sizeof(safe_pids[0]); i++) {
        bool sup = pas_supported(safe_pids[i]);
        pr_info("scm_pil_fuzz: PID %d: %s\n", safe_pids[i], sup ? "SUPPORTED" : "not supported");
    }
}

/* Test 1: Call pas_init_image with various PIDs */
static void test_init_image(void)
{
    int pid;
    int ret;
    /* Use the ORIGINAL wlanmdsp.mbn metadata (first 0x114 bytes = ELF+PHDRs) */
    /* We'll read this from MSA memory which has the firmware loaded */
    void __iomem *msa;
    u8 *metadata;
    int metadata_size = 0x114; /* ELF header + PHDRs */

    pr_info("scm_pil_fuzz: === PAS Init Image Test ===\n");

    /* Read firmware metadata from MSA */
    msa = ioremap_wc(MSA_PA, 0x1000);
    if (!msa) {
        pr_err("scm_pil_fuzz: can't map MSA\n");
        return;
    }

    metadata = kmalloc(0x2000, GFP_KERNEL);
    if (!metadata) {
        iounmap(msa);
        return;
    }

    /* The firmware ELF starts much earlier in MSA, at offset 0x0 or a specific location */
    /* Actually, the metadata for pas_init_image is the ELF header + hash segment from .mdt file */
    /* Let's create a minimal valid-looking metadata from scratch */

    /* Actually, pas_init_image expects the .mdt file (ELF header + hash/cert segment) */
    /* The metadata needs to be a valid MBN with ELF header + hash segment */
    /* For testing, let's just pass zeros or small data to see how TZ responds */

    memset(metadata, 0, 0x2000);

    iounmap(msa);

    /* Test with supported PIDs first to see normal behavior */
    pr_info("scm_pil_fuzz: Testing with empty metadata on various PIDs\n");

    /* Only test supported PIDs to avoid crashing TZ */
    int test_pids[] = {1, 4, 9, 10, 13, 15, 18, 19, 20, 21, 23};
    int i;
    for (i = 0; i < sizeof(test_pids)/sizeof(test_pids[0]); i++) {
        pid = test_pids[i];
        ret = pas_init_image(pid, metadata, metadata_size);
        pr_info("scm_pil_fuzz: pas_init_image(pid=%d, zeros, %d) = %d\n",
                pid, metadata_size, ret);
        msleep(50);
    }

    kfree(metadata);
}

/* Test 2: pas_mem_setup - try to register MSA as memory for different PIDs */
static void test_mem_setup(void)
{
    int ret;
    int pids[] = {1, 4, 9, 13, 15, 18, 19, 20, 21, 23};
    int i;

    pr_info("scm_pil_fuzz: === PAS Mem Setup Test ===\n");
    pr_info("scm_pil_fuzz: Trying to register MSA addr as memory for various PIDs\n");

    for (i = 0; i < sizeof(pids)/sizeof(pids[0]); i++) {
        /* Try to set up MSA memory region for this PID */
        ret = pas_mem_setup(pids[i], MSA_PA, MSA_SIZE);
        pr_info("scm_pil_fuzz: pas_mem_setup(pid=%d, 0x%llx, 0x%x) = %d\n",
                pids[i], MSA_PA, MSA_SIZE, ret);
        msleep(50);

        if (ret == 0) {
            pr_info("scm_pil_fuzz: *** MEM SETUP SUCCEEDED for PID %d! ***\n", pids[i]);
        }
    }

    /* Also try with different memory regions */
    pr_info("scm_pil_fuzz: Trying different memory bases for PID 20\n");
    phys_addr_t test_addrs[] = {MSA_PA, 0x86a00000ULL, 0x8b700000ULL, 0x8c400000ULL};
    for (i = 0; i < sizeof(test_addrs)/sizeof(test_addrs[0]); i++) {
        ret = pas_mem_setup(20, test_addrs[i], MSA_SIZE);
        pr_info("scm_pil_fuzz: pas_mem_setup(pid=20, 0x%llx, 0x%x) = %d\n",
                test_addrs[i], MSA_SIZE, ret);
        msleep(50);
    }
}

/* Test 3: Try PAS shutdown on WLAN-related PIDs */
static void test_shutdown(void)
{
    int ret;
    int pids[] = {18, 20, 21};  /* Only safe PIDs */
    int i;

    pr_info("scm_pil_fuzz: === PAS Shutdown Test (safe PIDs only) ===\n");

    for (i = 0; i < sizeof(pids)/sizeof(pids[0]); i++) {
        ret = pas_shutdown(pids[i]);
        pr_info("scm_pil_fuzz: pas_shutdown(pid=%d) = %d\n", pids[i], ret);
        msleep(100);
    }

    /* Check if MSA is writable after shutdown */
    pr_info("scm_pil_fuzz: Checking MSA write after shutdown\n");
    {
        void __iomem *msa = ioremap_wc(MSA_PA, 0x1000);
        if (msa) {
            u32 val = readl(msa);
            pr_info("scm_pil_fuzz: MSA+0x0 read = 0x%08x\n", val);
            /* Don't actually write yet - just check readability */
            iounmap(msa);
        }
    }
}

/* Test 4: Try auth_and_reset after fake init on supported PIDs */
static void test_auth_cycle(void)
{
    int ret;
    u8 *metadata;
    int pid = 20;  /* PID 20 is in supported list, probably safe */

    pr_info("scm_pil_fuzz: === Auth Cycle Test (PID %d) ===\n", pid);

    metadata = kzalloc(0x2000, GFP_KERNEL);
    if (!metadata) return;

    /* Step 1: init_image with empty metadata */
    ret = pas_init_image(pid, metadata, 0x114);
    pr_info("scm_pil_fuzz: init_image(pid=%d) = %d\n", pid, ret);

    if (ret == 0) {
        /* Step 2: mem_setup pointing to MSA */
        ret = pas_mem_setup(pid, MSA_PA, MSA_SIZE);
        pr_info("scm_pil_fuzz: mem_setup(pid=%d, MSA) = %d\n", pid, ret);

        if (ret == 0) {
            /* Step 3: auth_and_reset */
            ret = pas_auth_and_reset(pid);
            pr_info("scm_pil_fuzz: auth_and_reset(pid=%d) = %d\n", pid, ret);

            /* Step 4: check MSA write access */
            void __iomem *msa = ioremap_wc(MSA_PA, 0x1000);
            if (msa) {
                u32 val = readl(msa);
                pr_info("scm_pil_fuzz: MSA readable: 0x%08x\n", val);
                iounmap(msa);
            }

            /* Step 5: shutdown */
            ret = pas_shutdown(pid);
            pr_info("scm_pil_fuzz: shutdown(pid=%d) = %d\n", pid, ret);
        }
    }

    kfree(metadata);
}

/* Test 5: Try shutdown on each PID then attempt MSA write */
static void test_shutdown_write(void)
{
    int ret;
    int pids[] = {18, 19, 20, 21, 23};
    int i;
    void __iomem *msa;
    u32 orig_val, read_back;

    pr_info("scm_pil_fuzz: === Shutdown + MSA Write Test ===\n");

    for (i = 0; i < sizeof(pids)/sizeof(pids[0]); i++) {
        ret = pas_shutdown(pids[i]);
        pr_info("scm_pil_fuzz: pas_shutdown(pid=%d) = %d\n", pids[i], ret);
        msleep(100);
    }

    /* After shutting down subsystems, try MSA write */
    msa = ioremap_wc(MSA_PA, 0x1000);
    if (!msa) {
        pr_err("scm_pil_fuzz: can't map MSA after shutdown\n");
        return;
    }

    orig_val = readl(msa);
    pr_info("scm_pil_fuzz: MSA+0x0 = 0x%08x (before write attempt)\n", orig_val);

    /* Try write - this previously crashed, but maybe not after shutdown */
    pr_info("scm_pil_fuzz: Attempting MSA write...\n");
    writel(orig_val, msa);  /* Write back same value to minimize damage */
    mb();
    read_back = readl(msa);
    pr_info("scm_pil_fuzz: MSA+0x0 = 0x%08x (after write attempt)\n", read_back);

    iounmap(msa);
}

/* Test 6: Try to re-init WLAN PID (10) via other PIDs' mem_setup */
static void test_msa_via_other_pid(void)
{
    int ret;
    u8 *metadata;
    int pids[] = {4, 9, 15, 18, 20};
    int i;

    pr_info("scm_pil_fuzz: === MSA via Other PID Test ===\n");

    metadata = kzalloc(0x2000, GFP_KERNEL);
    if (!metadata) return;

    for (i = 0; i < sizeof(pids)/sizeof(pids[0]); i++) {
        pr_info("scm_pil_fuzz: --- Trying PID %d ---\n", pids[i]);

        /* Init with empty metadata */
        ret = pas_init_image(pids[i], metadata, 0x114);
        pr_info("scm_pil_fuzz: init_image(pid=%d) = %d\n", pids[i], ret);

        if (ret != 0) continue;  /* Can't proceed if init fails */

        /* Point mem_setup to MSA region */
        ret = pas_mem_setup(pids[i], MSA_PA, MSA_SIZE);
        pr_info("scm_pil_fuzz: mem_setup(pid=%d, MSA) = %d\n", pids[i], ret);

        /* Shutdown regardless of mem_setup result */
        ret = pas_shutdown(pids[i]);
        pr_info("scm_pil_fuzz: shutdown(pid=%d) = %d\n", pids[i], ret);
        msleep(100);
    }

    /* Check MSA state after manipulations */
    {
        void __iomem *msa = ioremap_wc(MSA_PA, 0x1000);
        if (msa) {
            pr_info("scm_pil_fuzz: MSA+0x0 = 0x%08x\n", readl(msa));
            iounmap(msa);
        }
    }

    kfree(metadata);
}

static int __init scm_pil_fuzz_init(void)
{
    int ret;

    pr_info("scm_pil_fuzz: loaded, test=%d\n", test);

    ret = resolve_symbols();
    if (ret) {
        pr_err("scm_pil_fuzz: symbol resolution failed\n");
        return -EAGAIN;
    }

    switch (test) {
    case 0:
        test_pas_support();
        break;
    case 1:
        test_init_image();
        break;
    case 2:
        test_mem_setup();
        break;
    case 3:
        test_shutdown();
        break;
    case 4:
        test_auth_cycle();
        break;
    case 5:
        test_shutdown_write();
        break;
    case 6:
        test_msa_via_other_pid();
        break;
    default:
        pr_info("scm_pil_fuzz: unknown test %d\n", test);
    }

    return -EAGAIN;
}

static void __exit scm_pil_fuzz_exit(void)
{
}

module_init(scm_pil_fuzz_init);
module_exit(scm_pil_fuzz_exit);
