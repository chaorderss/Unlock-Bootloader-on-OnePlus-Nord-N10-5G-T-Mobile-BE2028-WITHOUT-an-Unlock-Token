#!/usr/bin/env python3
"""
Build a minimal AArch64 kernel module (.ko) that patches the nl80211_tx_mgmt
iftype bitmask in the running kernel to add MONITOR mode support.

The module:
  init_module:
    1. Reads nl80211_tx_mgmt address from a module parameter (or hardcoded)
    2. Calculates the MOVZ instruction address (func + 0x74)
    3. Calls set_memory_rw() on the page
    4. Patches 0x528073cb -> 0x52807bcb (MOVZ W11,#0x39e -> #0x3de)
    5. Calls set_memory_ro() to restore protection
    6. Calls printk() to log success

  cleanup_module:
    1. Reverses the patch (0x52807bcb -> 0x528073cb)
"""

import struct
import sys

OUTPUT = "/Users/xmxx/pinganhuijia/tmp/kpatch.ko"

# ==================== AArch64 Assembly ====================

def aarch64_asm():
    """Hand-assemble the init and exit functions."""

    # Register conventions:
    # x0 = first arg, return value
    # x19-x28 = callee-saved
    # x29 = frame pointer, x30 = link register

    # ---- INIT MODULE ----
    # Reads the target address from a global variable (set via relocation)
    #
    # Pseudocode:
    #   unsigned long target_addr = nl80211_func_addr + 0x74;
    #   unsigned long page_addr = target_addr & ~0xFFF;
    #   int ret = set_memory_rw(page_addr, 1);
    #   if (ret == 0) {
    #       uint32_t *p = (uint32_t *)target_addr;
    #       if (*p == 0x528073cb) {
    #           *p = 0x52807bcb;
    #           __flush_icache_range(target_addr, target_addr + 4);
    #           set_memory_ro(page_addr, 1);
    #           printk("kpatch: patched OK\n");
    #           return 0;
    #       }
    #   }
    #   return -1;

    init_code = []

    # Prologue
    init_code.append(0xa9be7bfd)  # stp x29, x30, [sp, #-32]!
    init_code.append(0x910003fd)  # mov x29, sp
    init_code.append(0xa9014ff4)  # stp x20, x19, [sp, #16]

    # Load nl80211_tx_mgmt address from data (relocation will fill this)
    # ADRP x0, target_addr_var   (relocation will handle this)
    # LDR x19, [x0, #:lo12:target_addr_var]  (relocation will handle this)
    init_code.append(0x90000000)  # adrp x0, ... (reloc)
    init_code.append(0xf9400013)  # ldr x19, [x0] (reloc)

    # x19 = nl80211_tx_mgmt address
    # Add 0x74 to get the MOVZ instruction
    init_code.append(0x91001d33)  # add x19, x19, #0x74  (but 0x74/4=0x1d, hmm)
    # Wait: add x19, x19, #0x74 = 0x9101D273
    # Actually: ADD Xd, Xn, #imm -> 0x91 | (imm12 << 10) | (Xn << 5) | Xd
    # imm=0x74=116, Xn=x19=19, Xd=x19=19
    # = 0x91000000 | (116 << 10) | (19 << 5) | 19
    # = 0x91000000 | 0x1D000 | 0x260 | 0x13
    # = 0x9101D273
    init_code[-1] = 0x9101D273  # add x19, x19, #0x74

    # Page-align: x20 = x19 & ~0xFFF
    # AND x20, x19, #~0xFFF  -> AND Xd, Xn, #imm
    # #~0xFFF = 0xFFFFFFFFFFFFF000 -> immr=12, imms=51 for 64-bit
    # BIC is AND with NOT, but we can use AND with bitmask immediate
    # AND x20, x19, #0xfffffffffffff000
    # N=1, immr=12, imms=51
    init_code.append(0x9274CE74)  # and x20, x19, #0xfffffffffffff000

    # Call set_memory_rw(page_addr, 1)
    init_code.append(0xaa1403e0)  # mov x0, x20
    init_code.append(0x52800021)  # mov w1, #1
    # BL set_memory_rw (relocation)
    init_code.append(0x94000000)  # bl set_memory_rw (reloc)

    # Check return value
    init_code.append(0x35000280)  # cbnz w0, fail (forward jump)

    # Read current instruction value
    init_code.append(0xb9400268)  # ldr w8, [x19]

    # Compare with expected value 0x528073cb
    # Need to build the constant: MOVZ + MOVK
    init_code.append(0x5290e788)  # movz w8, ... nah, need to compare
    # Actually let's use a different approach - just compare bytes
    # MOV w9, #0x73cb; MOVK w9, #0x5280, lsl#16
    init_code.append(0x5290e789)  # movz w9, #0x873c ... hmm

    # Let me be more careful with MOVZ/MOVK encoding
    # MOVZ Wd, #imm16, lsl#shift
    # Wd=w9=9, imm16=0x73cb, shift=0
    # = 0x52800000 | (0x73cb << 5) | 9 = 0x52800000 | 0xE7960 | 9 = 0x528E7969
    init_code[-1] = 0x528E7969  # movz w9, #0x73cb
    # MOVK w9, #0x5280, lsl#16
    # = 0x72A00000 | (0x5280 << 5) | 9 = 0x72A00000 | 0xA5000 | 9 = 0x72AA5009
    init_code.append(0x72AA5009)  # movk w9, #0x5280, lsl#16

    # Compare w8, w9
    init_code.append(0x6B09011F)  # cmp w8, w9

    # If not equal, goto fail
    init_code.append(0x54000181)  # b.ne fail (forward, adjust later)

    # Patch: write new value 0x52807bcb
    # MOV w8, #0x7bcb; MOVK w8, #0x5280, lsl#16
    init_code.append(0x528F7968)  # movz w8, #0x7bcb
    init_code.append(0x72AA5008)  # movk w8, #0x5280, lsl#16

    # Store patched instruction
    init_code.append(0xb9000268)  # str w8, [x19]

    # Flush icache: dc cvau, x19 ; dsb ish ; ic ivau, x19 ; dsb ish ; isb
    init_code.append(0xd50b7b33)  # dc cvau, x19
    init_code.append(0xd5033b9f)  # dsb ish
    init_code.append(0xd50b7533)  # ic ivau, x19
    init_code.append(0xd5033b9f)  # dsb ish
    init_code.append(0xd5033fdf)  # isb

    # Restore RO: set_memory_ro(page_addr, 1)
    init_code.append(0xaa1403e0)  # mov x0, x20
    init_code.append(0x52800021)  # mov w1, #1
    init_code.append(0x94000000)  # bl set_memory_ro (reloc)

    # printk("kpatch: monitor TX enabled\n")
    init_code.append(0x90000000)  # adrp x0, msg (reloc)
    init_code.append(0x91000000)  # add x0, x0, #:lo12:msg (reloc)
    init_code.append(0x94000000)  # bl printk (reloc)

    # Return 0
    init_code.append(0x52800000)  # mov w0, #0
    init_code.append(0x14000003)  # b epilogue

    # fail: return -1
    # (this is the target for the cbnz/b.ne jumps)
    fail_offset = len(init_code)
    init_code.append(0x12800000)  # mov w0, #-1 (movn w0, #0)
    init_code.append(0xd503201f)  # nop (padding)

    # Epilogue
    init_code.append(0xa9414ff4)  # ldp x20, x19, [sp, #16]
    init_code.append(0xa8c27bfd)  # ldp x29, x30, [sp], #32
    init_code.append(0xd65f03c0)  # ret

    # Fix branch targets
    # cbnz w0 at index 9 should jump to fail_offset
    cbnz_idx = 9
    cbnz_imm = fail_offset - cbnz_idx
    init_code[cbnz_idx] = 0x35000000 | (cbnz_imm << 5) | 0  # cbnz w0, #offset

    # b.ne at index 13 should jump to fail_offset
    bne_idx = 13
    bne_imm = fail_offset - bne_idx
    init_code[bne_idx] = 0x54000001 | ((bne_imm & 0x7ffff) << 5)  # b.ne #offset

    return init_code, fail_offset


def aarch64_exit_asm():
    """cleanup_module: restore original instruction."""
    exit_code = []

    # Prologue
    exit_code.append(0xa9be7bfd)  # stp x29, x30, [sp, #-32]!
    exit_code.append(0x910003fd)  # mov x29, sp
    exit_code.append(0xa9014ff4)  # stp x20, x19, [sp, #16]

    # Load target address
    exit_code.append(0x90000000)  # adrp x0, target_addr_var (reloc)
    exit_code.append(0xf9400013)  # ldr x19, [x0] (reloc)
    exit_code.append(0x9101D273)  # add x19, x19, #0x74

    # Page-align
    exit_code.append(0x9274CE74)  # and x20, x19, #0xfffffffffffff000

    # set_memory_rw(page, 1)
    exit_code.append(0xaa1403e0)  # mov x0, x20
    exit_code.append(0x52800021)  # mov w1, #1
    exit_code.append(0x94000000)  # bl set_memory_rw (reloc)

    # Check
    exit_code.append(0x35000180)  # cbnz w0, done (forward)

    # Restore original: 0x528073cb
    exit_code.append(0x528E7968)  # movz w8, #0x73cb
    exit_code.append(0x72AA5008)  # movk w8, #0x5280, lsl#16
    exit_code.append(0xb9000268)  # str w8, [x19]

    # Flush icache
    exit_code.append(0xd50b7b33)  # dc cvau, x19
    exit_code.append(0xd5033b9f)  # dsb ish
    exit_code.append(0xd50b7533)  # ic ivau, x19
    exit_code.append(0xd5033b9f)  # dsb ish
    exit_code.append(0xd5033fdf)  # isb

    # set_memory_ro(page, 1)
    exit_code.append(0xaa1403e0)  # mov x0, x20
    exit_code.append(0x52800021)  # mov w1, #1
    exit_code.append(0x94000000)  # bl set_memory_ro (reloc)

    # printk
    exit_code.append(0x90000000)  # adrp x0, exit_msg (reloc)
    exit_code.append(0x91000000)  # add x0, x0, #:lo12:exit_msg (reloc)
    exit_code.append(0x94000000)  # bl printk (reloc)

    # done:
    done_offset = len(exit_code)
    exit_code.append(0xa9414ff4)  # ldp x20, x19, [sp, #16]
    exit_code.append(0xa8c27bfd)  # ldp x29, x30, [sp], #32
    exit_code.append(0xd65f03c0)  # ret

    # Fix cbnz target (index 10 -> done_offset)
    cbnz_idx = 10
    cbnz_imm = done_offset - cbnz_idx
    exit_code[cbnz_idx] = 0x35000000 | (cbnz_imm << 5) | 0

    return exit_code, done_offset


def build_ko():
    """Build a complete ELF64 .ko file."""

    init_insns, _ = aarch64_asm()
    exit_insns, _ = aarch64_exit_asm()

    init_bytes = b''.join(struct.pack('<I', x) for x in init_insns)
    exit_bytes = b''.join(struct.pack('<I', x) for x in exit_insns)

    # String data
    init_msg = b"\x01kpatch: nl80211 monitor TX bitmask patched\n\x00"  # \x01 = KERN_ALERT
    exit_msg = b"\x01kpatch: nl80211 monitor TX bitmask restored\n\x00"

    # Module info
    vermagic = b"vermagic=4.19.81-perf+ SMP preempt mod_unload modversions aarch64\x00"
    mod_name = b"name=kpatch\x00"
    license_str = b"license=GPL\x00"
    desc = b"description=Patch nl80211_tx_mgmt to allow monitor TX\x00"
    modinfo_data = vermagic + mod_name + license_str + desc

    # __versions (CRC table for dependent symbols)
    # Each entry: 8 bytes CRC + 56 bytes name (null-padded)
    # We need module_layout + set_memory_rw + set_memory_ro + printk
    # CRCs must match what the kernel expects
    # Since CONFIG_MODULE_FORCE_LOAD=y, we can use dummy CRCs
    versions_entries = []
    for sym_name in [b'module_layout', b'set_memory_rw', b'set_memory_ro', b'printk']:
        entry = struct.pack('<Q', 0) + sym_name + b'\x00' * (56 - len(sym_name))
        versions_entries.append(entry)
    versions_data = b''.join(versions_entries)

    # .gnu.linkonce.this_module (struct module)
    # Size: 0x340 bytes (from the rdbg.ko template)
    module_data = bytearray(0x340)
    # Module name at offset 24
    name = b'kpatch'
    module_data[24:24+len(name)] = name
    # init function pointer at offset 0x150 (filled by relocation)
    # exit function pointer at offset 0x310 (filled by relocation)

    # .data section: target address storage (8 bytes, filled at runtime)
    # Actually, we need the kernel to resolve nl80211_tx_mgmt for us.
    # In a .ko, we can reference kernel symbols via relocations.
    # But nl80211_tx_mgmt is a static (local) symbol, not exported.
    # We need to use kallsyms_lookup_name instead!

    # Revised approach: call kallsyms_lookup_name("nl80211_tx_mgmt") in init
    # But kallsyms_lookup_name IS exported in this kernel

    print(f"init_text: {len(init_bytes)} bytes ({len(init_insns)} insns)")
    print(f"exit_text: {len(exit_bytes)} bytes ({len(exit_insns)} insns)")
    print(f"modinfo: {len(modinfo_data)} bytes")
    print(f"versions: {len(versions_data)} bytes")

    print("\nNOTE: Need to use kallsyms_lookup_name to find nl80211_tx_mgmt")
    print("since it's a static symbol not exported via EXPORT_SYMBOL.")


build_ko()
