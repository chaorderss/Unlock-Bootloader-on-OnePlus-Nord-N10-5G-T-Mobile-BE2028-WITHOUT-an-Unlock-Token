#!/usr/bin/env python3
"""
Minimal binary patch for qca_cld3_wlan.ko to enable monitor mode TX.

Two in-place changes (no size change, no data shifting):

1. mgmt_stypes[MONITOR] (file offset 0x30b4a8):
   Change TX=0x0000 RX=0x0000 → TX=0xffff RX=0x3c15 (same as AP entry)
   This registers monitor mode for all management frame subtypes.

2. wlan_mon_drv_ops relocation: replace hdd_get_stats entry (+0x98)
   with ndo_start_xmit entry (+0x20 → hdd_hard_start_xmit).
   This enables raw packet TX on monitor interface via AF_PACKET.
"""

import struct
import sys
import os

INPUT  = "/Users/xmxx/pinganhuijia/tmp/qca_cld3_wlan.ko"
OUTPUT = "/Users/xmxx/pinganhuijia/tmp/qca_cld3_wlan_patched4.ko"

# Constants from analysis
MGMT_STYPES_MONITOR_OFF = 0x30b4a8   # file offset of mgmt_stypes[6] (MONITOR)
MGMT_STYPES_MONITOR_ORIG = b'\x00\x00\x00\x00'  # tx=0x0000, rx=0x0000
MGMT_STYPES_MONITOR_NEW  = b'\xff\xff\x15\x3c'   # tx=0xffff, rx=0x3c15 (like AP)

# .rela.rodata section
RELA_RODATA_OFF  = 0x969260
RELA_RODATA_SIZE = 0x157b0
RELA_ENTSIZE     = 24  # sizeof(Elf64_Rela)

# Target relocation to find: wlan_mon_drv_ops+0x98 (hdd_get_stats)
MON_OPS_GET_STATS_ROFF = 0x5fa8  # r_offset for the hdd_get_stats entry

# New relocation: wlan_mon_drv_ops+0x20 (ndo_start_xmit → hdd_hard_start_xmit)
MON_OPS_XMIT_ROFF = 0x5f30       # r_offset for ndo_start_xmit
XMIT_SYM_IDX      = 8423          # symbol index for hdd_hard_start_xmit
R_AARCH64_ABS64   = 257            # relocation type
XMIT_ADDEND       = 0              # addend

def make_rela_entry(r_offset, sym_idx, rtype, r_addend):
    """Pack an Elf64_Rela entry (24 bytes)."""
    r_info = (sym_idx << 32) | rtype
    return struct.pack('<QqQ'[:3], r_offset, r_info, r_addend)
    # Actually Elf64_Rela: r_offset(u64), r_info(u64), r_addend(s64)

def make_rela_entry_correct(r_offset, sym_idx, rtype, r_addend):
    """Pack an Elf64_Rela entry (24 bytes)."""
    r_info = (sym_idx << 32) | rtype
    return struct.pack('<QQq', r_offset, r_info, r_addend)


def main():
    with open(INPUT, 'rb') as f:
        data = bytearray(f.read())

    orig_size = len(data)
    print(f"Original size: {orig_size} bytes")

    # === PATCH 1: mgmt_stypes[MONITOR] ===
    current = bytes(data[MGMT_STYPES_MONITOR_OFF:MGMT_STYPES_MONITOR_OFF+4])
    if current != MGMT_STYPES_MONITOR_ORIG:
        print(f"ERROR: mgmt_stypes[MONITOR] at 0x{MGMT_STYPES_MONITOR_OFF:x} is {current.hex()}, expected {MGMT_STYPES_MONITOR_ORIG.hex()}")
        sys.exit(1)
    data[MGMT_STYPES_MONITOR_OFF:MGMT_STYPES_MONITOR_OFF+4] = MGMT_STYPES_MONITOR_NEW
    print(f"PATCH 1: mgmt_stypes[MONITOR] @ 0x{MGMT_STYPES_MONITOR_OFF:x}: {MGMT_STYPES_MONITOR_ORIG.hex()} → {MGMT_STYPES_MONITOR_NEW.hex()}")

    # === PATCH 2: Replace hdd_get_stats relocation with ndo_start_xmit ===
    # Scan .rela.rodata for the entry with r_offset == MON_OPS_GET_STATS_ROFF
    num_entries = RELA_RODATA_SIZE // RELA_ENTSIZE
    found_idx = -1
    found_off = -1

    for i in range(num_entries):
        entry_off = RELA_RODATA_OFF + i * RELA_ENTSIZE
        r_offset = struct.unpack_from('<Q', data, entry_off)[0]
        if r_offset == MON_OPS_GET_STATS_ROFF:
            r_info = struct.unpack_from('<Q', data, entry_off + 8)[0]
            r_addend = struct.unpack_from('<q', data, entry_off + 16)[0]
            sym_idx = r_info >> 32
            rtype = r_info & 0xffffffff
            found_idx = i
            found_off = entry_off
            print(f"\nFound hdd_get_stats rela at entry [{i}], file offset 0x{entry_off:x}")
            print(f"  r_offset=0x{r_offset:x}, sym_idx={sym_idx}, type={rtype}, addend=0x{r_addend:x}")
            break

    if found_idx < 0:
        print(f"ERROR: Could not find relocation entry for r_offset=0x{MON_OPS_GET_STATS_ROFF:x}")
        sys.exit(1)

    # Build new relocation entry
    new_entry = make_rela_entry_correct(MON_OPS_XMIT_ROFF, XMIT_SYM_IDX, R_AARCH64_ABS64, XMIT_ADDEND)
    assert len(new_entry) == RELA_ENTSIZE

    # Show what we're replacing
    old_entry = bytes(data[found_off:found_off+RELA_ENTSIZE])
    print(f"\n  Old entry: {old_entry.hex()}")
    print(f"  New entry: {new_entry.hex()}")

    data[found_off:found_off+RELA_ENTSIZE] = new_entry
    print(f"PATCH 2: Replaced rela entry @ 0x{found_off:x}: wlan_mon_drv_ops+0x98(hdd_get_stats) → +0x20(hdd_hard_start_xmit)")

    # === Verify size unchanged ===
    assert len(data) == orig_size, f"Size changed! {orig_size} → {len(data)}"

    # === Write output ===
    with open(OUTPUT, 'wb') as f:
        f.write(data)
    print(f"\nWritten: {OUTPUT} ({len(data)} bytes, same as original)")

    # === Verify patches ===
    print("\n=== Verification ===")
    with open(OUTPUT, 'rb') as f:
        vdata = f.read()

    # Check mgmt_stypes[MONITOR]
    v1 = vdata[MGMT_STYPES_MONITOR_OFF:MGMT_STYPES_MONITOR_OFF+4]
    print(f"mgmt_stypes[MONITOR]: {v1.hex()} (expected {MGMT_STYPES_MONITOR_NEW.hex()}) {'OK' if v1 == MGMT_STYPES_MONITOR_NEW else 'FAIL'}")

    # Check relocation
    v2_off = struct.unpack_from('<Q', vdata, found_off)[0]
    v2_info = struct.unpack_from('<Q', vdata, found_off + 8)[0]
    v2_sym = v2_info >> 32
    v2_type = v2_info & 0xffffffff
    v2_addend = struct.unpack_from('<q', vdata, found_off + 16)[0]
    print(f"Rela entry @ 0x{found_off:x}: r_offset=0x{v2_off:x} sym={v2_sym} type={v2_type} addend={v2_addend}")
    ok = (v2_off == MON_OPS_XMIT_ROFF and v2_sym == XMIT_SYM_IDX and v2_type == R_AARCH64_ABS64 and v2_addend == 0)
    print(f"ndo_start_xmit relocation: {'OK' if ok else 'FAIL'}")

    # Count total differences
    with open(INPUT, 'rb') as f:
        orig = f.read()
    diffs = sum(1 for a, b in zip(orig, vdata) if a != b)
    print(f"\nTotal bytes changed: {diffs} (expected ~28)")


if __name__ == '__main__':
    main()
