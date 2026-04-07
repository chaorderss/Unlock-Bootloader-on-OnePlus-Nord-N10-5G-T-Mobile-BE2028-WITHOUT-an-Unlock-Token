/*
 * wlan_probe.c - WLAN firmware memory probe via icnss athdiag
 *
 * Uses the exported icnss_athdiag_read/write functions to read/write
 * WLAN firmware memory through the QMI interface, bypassing XPU.
 *
 * sub_test=0: Find icnss device, dump basic info
 * sub_test=1: Power on + athdiag_read scan (mem_type 0-4)
 * sub_test=2: Dump firmware code memory (IRAM)
 * sub_test=3: Dump firmware data memory (DRAM)
 * sub_test=4: Write test - modify a firmware data value
 */

#include <linux/module.h>
#include <linux/kernel.h>
#include <linux/init.h>
#include <linux/slab.h>
#include <linux/platform_device.h>
#include <linux/device.h>
#include <linux/delay.h>
#include <linux/moduleparam.h>

MODULE_LICENSE("GPL");
MODULE_AUTHOR("research");
MODULE_DESCRIPTION("WLAN firmware memory probe via icnss athdiag");

static int sub_test = 0;
static unsigned long offset_val = 0;
static int mem_type_val = 0;
static int read_len = 64;

module_param(sub_test, int, 0);
module_param(offset_val, ulong, 0);
module_param(mem_type_val, int, 0);
module_param(read_len, int, 0);

/* ---- Extern icnss symbols (exported by built-in icnss driver) ---- */
/* Note: Don't use extern declarations - use kallsyms for everything
 * to avoid symbol resolution issues at module load time */

/* kallsyms for non-exported symbols */
#include <linux/kallsyms.h>

#define ICNSS_MAGIC 0x5abc5abc

/* MSA offset discovered from struct dump:
 * offset 0x2B0: msa_pa (phys_addr_t, 8 bytes)
 * offset 0x2B8: msa_mem_size (u32, 4 bytes) -- padding to 0x2C0
 * offset 0x2C0: msa_va (void *, 8 bytes)
 * offset 0x2C8: state (unsigned long, 8 bytes)
 */
#define PRIV_OFFSET_MSA_PA    0x2B0
#define PRIV_OFFSET_MSA_SIZE  0x2B8
#define PRIV_OFFSET_MSA_VA    0x2C0
#define PRIV_OFFSET_STATE     0x2C8

/* ICNSS state bits */
#define ICNSS_WLFW_CONNECTED  0
#define ICNSS_POWER_ON        1
#define ICNSS_FW_READY        2

/* QMI function types */
typedef int (*athdiag_read_fn)(void *priv, uint32_t offset,
			       uint32_t mem_type, uint32_t data_len,
			       uint8_t *data);
typedef int (*athdiag_write_fn)(void *priv, uint32_t offset,
			        uint32_t mem_type, uint32_t data_len,
			        uint8_t *input);

/* Resolved pointers */
static void *penv_ptr = NULL;
static athdiag_read_fn fn_athdiag_read = NULL;
static athdiag_write_fn fn_athdiag_write = NULL;

static int resolve_symbols(void)
{
	unsigned long addr;
	void **penv_pp;

	/* Resolve penv global pointer */
	addr = kallsyms_lookup_name("penv");
	if (!addr) {
		pr_err("WLAN_PROBE: Cannot find 'penv' symbol\n");
		return -ENOENT;
	}
	penv_pp = (void **)addr;
	penv_ptr = *penv_pp;
	if (!penv_ptr) {
		pr_err("WLAN_PROBE: penv is NULL\n");
		return -ENODEV;
	}

	/* Validate magic */
	if (*(uint32_t *)penv_ptr != ICNSS_MAGIC) {
		pr_err("WLAN_PROBE: Magic mismatch: 0x%08x\n",
		       *(uint32_t *)penv_ptr);
		return -EINVAL;
	}

	pr_info("WLAN_PROBE: penv=%pK, magic=OK\n", penv_ptr);

	/* Resolve QMI functions */
	addr = kallsyms_lookup_name("wlfw_athdiag_read_send_sync_msg");
	if (!addr) {
		pr_err("WLAN_PROBE: Cannot find athdiag_read\n");
		return -ENOENT;
	}
	fn_athdiag_read = (athdiag_read_fn)addr;

	addr = kallsyms_lookup_name("wlfw_athdiag_write_send_sync_msg");
	if (!addr) {
		pr_err("WLAN_PROBE: Cannot find athdiag_write\n");
		return -ENOENT;
	}
	fn_athdiag_write = (athdiag_write_fn)addr;

	pr_info("WLAN_PROBE: athdiag_read=%pK, athdiag_write=%pK\n",
		fn_athdiag_read, fn_athdiag_write);

	return 0;
}

/* Sub-test 0: Basic info dump */
static void __init test_basic_info(void)
{
	unsigned long state;
	phys_addr_t msa_pa;
	uint32_t msa_size;
	void *msa_va;

	pr_info("WLAN_PROBE: === Sub-test 0: Basic info ===\n");

	if (resolve_symbols())
		return;

	/* Read state to check FW_READY */
	state = *(unsigned long *)(penv_ptr + PRIV_OFFSET_STATE);
	pr_info("WLAN_PROBE: state=0x%lx, FW_READY=%d, POWER_ON=%d, CONNECTED=%d\n",
		state,
		!!(state & (1UL << ICNSS_FW_READY)),
		!!(state & (1UL << ICNSS_POWER_ON)),
		!!(state & (1UL << ICNSS_WLFW_CONNECTED)));

	/* Read key fields from icnss_priv */
	msa_pa = *(phys_addr_t *)(penv_ptr + PRIV_OFFSET_MSA_PA);
	msa_size = *(uint32_t *)(penv_ptr + PRIV_OFFSET_MSA_SIZE);
	msa_va = *(void **)(penv_ptr + PRIV_OFFSET_MSA_VA);
	state = *(unsigned long *)(penv_ptr + PRIV_OFFSET_STATE);

	pr_info("WLAN_PROBE: msa_pa=0x%llx, msa_size=0x%x, msa_va=%pK, state=0x%lx\n",
		(u64)msa_pa, msa_size, msa_va, state);

	/* Dump first 512 bytes of icnss_priv */
	pr_info("WLAN_PROBE: icnss_priv first 256 bytes:\n");
	print_hex_dump(KERN_INFO, "priv[0x000]: ", DUMP_PREFIX_OFFSET,
		       16, 8, penv_ptr, 256, false);

	pr_info("WLAN_PROBE: icnss_priv bytes 256-512:\n");
	print_hex_dump(KERN_INFO, "priv[0x100]: ", DUMP_PREFIX_OFFSET,
		       16, 8, penv_ptr + 256, 256, false);

	pr_info("WLAN_PROBE: icnss_priv bytes 512-768:\n");
	print_hex_dump(KERN_INFO, "priv[0x200]: ", DUMP_PREFIX_OFFSET,
		       16, 8, penv_ptr + 512, 256, false);

	pr_info("WLAN_PROBE: Sub-test 0 complete\n");
}

/* Sub-test 1: Comprehensive athdiag scan */
static void __init test_athdiag_scan(void)
{
	uint8_t buf[16];
	int ret, mt, i;
	unsigned long state;

	pr_info("WLAN_PROBE: === Sub-test 1: athdiag scan ===\n");

	if (resolve_symbols())
		return;

	state = *(unsigned long *)(penv_ptr + PRIV_OFFSET_STATE);
	pr_info("WLAN_PROBE: state=0x%lx\n", state);

	if (!(state & (1UL << ICNSS_WLFW_CONNECTED))) {
		pr_err("WLAN_PROBE: FW not connected!\n");
		return;
	}

	/* Scan safe mem_types 0-3 at offset 0 (types 4+ crash device!) */
	for (mt = 0; mt <= 3; mt++) {
		memset(buf, 0xAA, sizeof(buf));
		ret = fn_athdiag_read(penv_ptr, 0, mt, 16, buf);
		pr_info("WLAN_PROBE: type=%d off=0x0: ret=%d data=%08x %08x %08x %08x\n",
			mt, ret,
			*(uint32_t *)buf, *(uint32_t *)(buf+4),
			*(uint32_t *)(buf+8), *(uint32_t *)(buf+12));
		msleep(100);
	}

	/* Scan offsets with mem_type=0 (target RAM) - conservative range */
	{
		uint32_t offs[] = {
			0x00000000, 0x00000100, 0x00001000, 0x00002000,
			0x00004000, 0x00008000, 0x00010000, 0x00020000,
			0x00040000, 0x00080000, 0x00100000, 0x001F0000,
		};
		pr_info("WLAN_PROBE: --- type=0 offset scan ---\n");
		for (i = 0; i < ARRAY_SIZE(offs); i++) {
			memset(buf, 0xAA, sizeof(buf));
			ret = fn_athdiag_read(penv_ptr, offs[i], 0, 16, buf);
			if (ret == 0) {
				pr_info("WLAN_PROBE: [0x%08x] %08x %08x %08x %08x\n",
					offs[i],
					*(uint32_t *)buf, *(uint32_t *)(buf+4),
					*(uint32_t *)(buf+8), *(uint32_t *)(buf+12));
			} else {
				pr_info("WLAN_PROBE: [0x%08x] FAIL ret=%d\n",
					offs[i], ret);
			}
			msleep(100);
		}
	}

	pr_info("WLAN_PROBE: Sub-test 1 complete\n");
}

/* Sub-test 2: Dump firmware memory at specified offset and mem_type */
static void __init test_dump_fw_mem(void)
{
	uint8_t *buf;
	int ret;
	int len = (read_len > 6144) ? 6144 : read_len;

	pr_info("WLAN_PROBE: === Sub-test 2: Dump FW mem ===\n");
	pr_info("WLAN_PROBE: offset=0x%lx, mem_type=%d, len=%d\n",
		offset_val, mem_type_val, len);

	if (resolve_symbols())
		return;

	buf = kmalloc(len, GFP_KERNEL);
	if (!buf) return;

	memset(buf, 0xAA, len);
	ret = fn_athdiag_read(penv_ptr, (uint32_t)offset_val,
			      (uint32_t)mem_type_val, (uint32_t)len, buf);
	pr_info("WLAN_PROBE: athdiag_read ret=%d\n", ret);

	if (ret == 0) {
		print_hex_dump(KERN_INFO, "FW_DUMP: ", DUMP_PREFIX_OFFSET,
			       16, 4, buf, len, false);
	}

	kfree(buf);
	pr_info("WLAN_PROBE: Sub-test 2 complete\n");
}

/* Sub-test 3: Continuous read - dump large firmware region */
static void __init test_dump_region(void)
{
	uint8_t buf[256];
	int ret;
	uint32_t addr;
	int chunk_count = 0;
	int max_chunks = 32;

	pr_info("WLAN_PROBE: === Sub-test 3: Dump FW region ===\n");
	pr_info("WLAN_PROBE: start=0x%lx, mem_type=%d, chunks=%d\n",
		offset_val, mem_type_val, max_chunks);

	if (resolve_symbols())
		return;

	for (addr = (uint32_t)offset_val;
	     chunk_count < max_chunks;
	     addr += 256, chunk_count++) {

		memset(buf, 0xAA, sizeof(buf));
		ret = fn_athdiag_read(penv_ptr, addr, mem_type_val, 256, buf);
		if (ret != 0) {
			pr_info("WLAN_PROBE: FAIL at 0x%08x ret=%d, stopping\n",
				addr, ret);
			break;
		}

		pr_info("WLAN_PROBE: [0x%08x]:\n", addr);
		print_hex_dump(KERN_INFO, "  ", DUMP_PREFIX_OFFSET,
			       16, 4, buf, 256, false);
	}

	pr_info("WLAN_PROBE: Sub-test 3 complete (dumped %d chunks)\n",
		chunk_count);
}

/* Sub-test 4: Write test */
static void __init test_write_fw_mem(void)
{
	uint8_t rbuf[16], wbuf[4];
	int ret;

	pr_info("WLAN_PROBE: === Sub-test 4: FW write test ===\n");
	pr_info("WLAN_PROBE: offset=0x%lx, mem_type=%d\n",
		offset_val, mem_type_val);

	if (resolve_symbols())
		return;

	/* Read original value */
	memset(rbuf, 0, sizeof(rbuf));
	ret = fn_athdiag_read(penv_ptr, (uint32_t)offset_val,
			      mem_type_val, 16, rbuf);
	pr_info("WLAN_PROBE: PRE-WRITE read ret=%d\n", ret);
	if (ret == 0) {
		pr_info("WLAN_PROBE: BEFORE: %08x %08x %08x %08x\n",
			*(uint32_t *)(rbuf),
			*(uint32_t *)(rbuf + 4),
			*(uint32_t *)(rbuf + 8),
			*(uint32_t *)(rbuf + 12));
	} else {
		pr_err("WLAN_PROBE: Read failed, aborting write test\n");
		return;
	}

	/* Write test pattern */
	wbuf[0] = 0xEF; wbuf[1] = 0xBE; wbuf[2] = 0xAD; wbuf[3] = 0xDE;
	ret = fn_athdiag_write(penv_ptr, (uint32_t)offset_val,
			       mem_type_val, 4, wbuf);
	pr_info("WLAN_PROBE: WRITE ret=%d (wrote 0xDEADBEEF)\n", ret);

	/* Read back */
	memset(rbuf, 0, sizeof(rbuf));
	ret = fn_athdiag_read(penv_ptr, (uint32_t)offset_val,
			      mem_type_val, 16, rbuf);
	pr_info("WLAN_PROBE: POST-WRITE read ret=%d\n", ret);
	if (ret == 0) {
		pr_info("WLAN_PROBE: AFTER: %08x %08x %08x %08x\n",
			*(uint32_t *)(rbuf),
			*(uint32_t *)(rbuf + 4),
			*(uint32_t *)(rbuf + 8),
			*(uint32_t *)(rbuf + 12));
	}

	pr_info("WLAN_PROBE: Sub-test 4 complete\n");
}

/* Sub-test 5: Sparse scan - find non-zero regions in 0-512KB */
static void __init test_sparse_scan(void)
{
	uint8_t buf[256];
	int ret, j;
	uint32_t addr;
	int has_data;
	int total_data_chunks = 0;

	pr_info("WLAN_PROBE: === Sub-test 5: Sparse non-zero scan ===\n");

	if (resolve_symbols())
		return;

	/* Scan 0x0 to 0x7FFFF in 0x100 (256 byte) steps = 2048 reads */
	/* But that's too many. Use 0x400 (1KB) steps = 512 reads */
	for (addr = 0; addr < 0x80000; addr += 0x400) {
		memset(buf, 0, sizeof(buf));
		ret = fn_athdiag_read(penv_ptr, addr, 0, 256, buf);
		if (ret != 0) {
			pr_info("WLAN_PROBE: FAIL at 0x%05x ret=%d\n", addr, ret);
			break;
		}

		/* Check if any bytes are non-zero */
		has_data = 0;
		for (j = 0; j < 256; j++) {
			if (buf[j] != 0) {
				has_data = 1;
				break;
			}
		}

		if (has_data) {
			total_data_chunks++;
			pr_info("WLAN_PROBE: DATA at 0x%05x: %08x %08x %08x %08x ... %08x %08x %08x %08x\n",
				addr,
				*(uint32_t *)(buf),
				*(uint32_t *)(buf + 4),
				*(uint32_t *)(buf + 8),
				*(uint32_t *)(buf + 12),
				*(uint32_t *)(buf + 240),
				*(uint32_t *)(buf + 244),
				*(uint32_t *)(buf + 248),
				*(uint32_t *)(buf + 252));
		}
		/* No msleep needed - single call per iteration, kernel handles pacing */
		if ((addr & 0x3FFF) == 0)
			msleep(10); /* Small pause every 16KB to not overwhelm QMI */
	}

	pr_info("WLAN_PROBE: Sparse scan complete. %d non-zero chunks found in 0-512KB\n",
		total_data_chunks);
}

/* Sub-test 6: Read directly from MSA memory via existing kernel mapping */
static void __init test_msa_direct_read(void)
{
	void *msa_va;
	uint32_t msa_size;
	phys_addr_t msa_pa;
	uint32_t off;
	int found_regions = 0;

	pr_info("WLAN_PROBE: === Sub-test 6: MSA direct read ===\n");

	if (resolve_symbols())
		return;

	msa_va = *(void **)(penv_ptr + PRIV_OFFSET_MSA_VA);
	msa_size = *(uint32_t *)(penv_ptr + PRIV_OFFSET_MSA_SIZE);
	msa_pa = *(phys_addr_t *)(penv_ptr + PRIV_OFFSET_MSA_PA);

	pr_info("WLAN_PROBE: msa_pa=0x%llx, msa_va=%pK, size=0x%x\n",
		(u64)msa_pa, msa_va, msa_size);

	if (!msa_va || msa_size == 0) {
		pr_err("WLAN_PROBE: MSA not mapped!\n");
		return;
	}

	/* Dump first 256 bytes of MSA - this is the firmware header */
	pr_info("WLAN_PROBE: MSA first 256 bytes (firmware header):\n");
	print_hex_dump(KERN_INFO, "MSA[0x000]: ", DUMP_PREFIX_OFFSET,
		       16, 4, msa_va, 256, false);

	/* Scan through MSA in 4KB steps to find non-zero regions */
	pr_info("WLAN_PROBE: --- MSA sparse scan (4KB steps) ---\n");
	for (off = 0; off < msa_size && off < 0x200000; off += 0x1000) {
		uint32_t *p = (uint32_t *)(msa_va + off);
		int j, has_data = 0;

		for (j = 0; j < 1024; j++) {  /* Check 4KB / 4 = 1024 words */
			if (p[j] != 0) {
				has_data = 1;
				break;
			}
		}

		if (has_data) {
			found_regions++;
			pr_info("WLAN_PROBE: MSA[0x%06x]: %08x %08x %08x %08x ... %08x %08x %08x %08x\n",
				off, p[0], p[1], p[2], p[3],
				p[1020], p[1021], p[1022], p[1023]);
		}
	}

	pr_info("WLAN_PROBE: MSA scan complete. %d non-zero 4KB pages in %dKB\n",
		found_regions, msa_size / 1024);
}

/* Sub-test 7: Test MSA direct write via kernel mapping */
static void __init test_msa_write(void)
{
	void *msa_va;
	uint32_t msa_size;
	volatile uint32_t *target;
	uint32_t orig_val, test_val = 0xCAFEBABE;
	uint32_t readback;
	uint32_t write_off;

	pr_info("WLAN_PROBE: === Sub-test 7: MSA write test ===\n");

	if (resolve_symbols())
		return;

	msa_va = *(void **)(penv_ptr + PRIV_OFFSET_MSA_VA);
	msa_size = *(uint32_t *)(penv_ptr + PRIV_OFFSET_MSA_SIZE);

	if (!msa_va || msa_size == 0) {
		pr_err("WLAN_PROBE: MSA not mapped!\n");
		return;
	}

	/* Write to a safe offset - use parameter or default to 0x1FF000 (near end) */
	write_off = (uint32_t)offset_val;
	if (write_off >= msa_size - 4) {
		write_off = 0x1FF000; /* Near end of 2MB MSA, should be unused */
	}

	target = (volatile uint32_t *)(msa_va + write_off);

	/* Read original value */
	orig_val = *target;
	pr_info("WLAN_PROBE: MSA[0x%06x] BEFORE: 0x%08x\n", write_off, orig_val);

	/* Try to write */
	*target = test_val;
	mb(); /* Memory barrier */

	/* Read back */
	readback = *target;
	pr_info("WLAN_PROBE: MSA[0x%06x] WRITE 0x%08x, READBACK: 0x%08x\n",
		write_off, test_val, readback);

	if (readback == test_val) {
		pr_info("WLAN_PROBE: *** MSA WRITE SUCCESS! ***\n");
		/* Restore original value */
		*target = orig_val;
		mb();
		readback = *target;
		pr_info("WLAN_PROBE: RESTORED: 0x%08x\n", readback);
	} else if (readback == orig_val) {
		pr_info("WLAN_PROBE: Write had NO EFFECT (XPU blocked)\n");
	} else {
		pr_info("WLAN_PROBE: Unexpected readback value!\n");
	}

	/* Also test athdiag read of the same region to compare */
	if (fn_athdiag_read) {
		uint8_t buf[16];
		int ret;
		/* Check if MSA[0x198000] corresponds to athdiag offset 0 */
		pr_info("WLAN_PROBE: Cross-check: athdiag read at offset=0, type=0:\n");
		ret = fn_athdiag_read(penv_ptr, 0, 0, 16, buf);
		if (ret == 0) {
			pr_info("WLAN_PROBE: athdiag: %08x %08x %08x %08x\n",
				*(uint32_t *)buf, *(uint32_t *)(buf+4),
				*(uint32_t *)(buf+8), *(uint32_t *)(buf+12));
		}
	}

	pr_info("WLAN_PROBE: Sub-test 7 complete\n");
}

static int __init wlan_probe_init(void)
{
	pr_info("WLAN_PROBE: loading, sub_test=%d\n", sub_test);

	switch (sub_test) {
	case 0:
		test_basic_info();
		break;
	case 1:
		test_athdiag_scan();
		break;
	case 2:
		test_dump_fw_mem();
		break;
	case 3:
		test_dump_region();
		break;
	case 4:
		test_write_fw_mem();
		break;
	case 5:
		test_sparse_scan();
		break;
	case 6:
		test_msa_direct_read();
		break;
	case 7:
		test_msa_write();
		break;
	default:
		pr_err("WLAN_PROBE: Unknown sub_test=%d\n", sub_test);
		break;
	}

	return -EAGAIN; /* Always fail to auto-unload */
}

static void __exit wlan_probe_exit(void)
{
	pr_info("WLAN_PROBE: unloaded\n");
}

module_init(wlan_probe_init);
module_exit(wlan_probe_exit);
