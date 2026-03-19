#!/usr/bin/env python3
"""
Post-boot partition comparison tool.

PURPOSE: After the device boots (and ABL's init_defaults writes devinfo
defaults somewhere), read back ALL small partitions via EDL and compare
with the pre-boot backup to find WHERE ABL actually writes devinfo data.

USAGE:
  Step 1: Boot the device normally
  Step 2: Put device in EDL mode (hold Vol+ Vol- with USB, or 'adb reboot edl')
  Step 3: Run: python3 post_boot_compare.py dump
           (This reads back key partitions to edl_backup_postboot/)
  Step 4: Run: python3 post_boot_compare.py compare
           (This compares pre-boot and post-boot backups)
  Step 5: Run: python3 post_boot_compare.py search
           (Searches ALL backup files for ANDROID-BOOT! magic)
"""

import sys
import os
import subprocess
import hashlib

EDL = "/Library/Frameworks/Python.framework/Versions/3.14/bin/edl"
PRE_BOOT = "/Users/xmxx/pinganhuijia/edl_backup"
POST_BOOT = "/Users/xmxx/pinganhuijia/edl_backup_postboot"

# Partitions to read back (small ones + key ones)
# Format: (partition_name, lun, expected_size_comment)
PARTITIONS = [
    # LUN0
    ("config", 0, "512K"),
    ("frp", 0, "512K"),
    ("keystore", 0, "512K"),
    ("misc", 0, "1M"),
    ("param", 0, "1M"),
    ("ssd", 0, "8K"),
    ("oem_dycnvbk", 0, "10M"),
    ("oem_stanvbk", 0, "10M"),
    # LUN1
    ("xbl_a", 1, "3.5M"),
    ("xbl_config_a", 1, "256K"),
    # LUN3
    ("logfs", 3, "8M"),
    ("limits", 3, "4K"),
    ("toolsfv", 3, "1M"),
    # LUN4
    ("devinfo", 4, "4K"),
    ("dip", 4, "1M"),
    ("aop_a", 4, "512K"),
    ("apdp", 4, "256K"),
    ("devcfg_a", 4, "128K"),
    ("imagefv_a", 4, "256K"),
    ("multiimgoem_a", 4, "32K"),
    ("reserve1", 4, "8K"),
    ("reserve2", 4, "8K"),
    ("secdata", 4, "4K"),
    ("op1", 4, "various"),
    ("catecontentfv", 4, "1M"),
    ("catefv", 4, "512K"),
    # LUN5
    ("fsc", 5, "128K"),
    ("modemst1", 5, "2.5M"),
    ("modemst2", 5, "2.5M"),
]

def cmd_dump():
    """Read back partitions via EDL."""
    os.makedirs(POST_BOOT, exist_ok=True)

    print(f"Reading {len(PARTITIONS)} partitions via EDL...")
    print(f"Output directory: {POST_BOOT}")
    print()

    failed = []
    for name, lun, size_comment in PARTITIONS:
        outfile = os.path.join(POST_BOOT, f"{name}_lun{lun}.bin")
        print(f"  Reading {name} (LUN{lun}, ~{size_comment})...", end=" ", flush=True)

        try:
            result = subprocess.run(
                [EDL, "r", name, outfile, f"--lun={lun}"],
                capture_output=True, text=True, timeout=60
            )
            if os.path.exists(outfile) and os.path.getsize(outfile) > 0:
                sz = os.path.getsize(outfile)
                print(f"OK ({sz:,} bytes)")
            else:
                print(f"FAILED (no output)")
                failed.append(name)
        except subprocess.TimeoutExpired:
            print("TIMEOUT")
            failed.append(name)
        except Exception as e:
            print(f"ERROR: {e}")
            failed.append(name)

    print()
    if failed:
        print(f"Failed partitions: {', '.join(failed)}")
    print(f"Done. Now run: python3 {sys.argv[0]} compare")

def cmd_compare():
    """Compare pre-boot and post-boot backups."""
    if not os.path.isdir(POST_BOOT):
        print(f"Post-boot backup directory not found: {POST_BOOT}")
        print(f"Run: python3 {sys.argv[0]} dump")
        return

    print("Comparing pre-boot vs post-boot backups...")
    print()

    # Map pre-boot files
    pre_files = {}
    for lun_dir in sorted(os.listdir(PRE_BOOT)):
        lun_path = os.path.join(PRE_BOOT, lun_dir)
        if os.path.isdir(lun_path) and lun_dir.startswith("lun"):
            lun_num = int(lun_dir[3:])
            for fname in os.listdir(lun_path):
                if fname.endswith(".bin") and not fname.startswith("gpt_") and not fname.startswith("rawprogram"):
                    pname = fname.replace(".bin", "")
                    pre_files[(pname, lun_num)] = os.path.join(lun_path, fname)
    # Also check root frp.bin
    root_frp = os.path.join(PRE_BOOT, "frp.bin")
    if os.path.exists(root_frp):
        pre_files[("frp", -1)] = root_frp

    changed = []
    unchanged = []
    missing = []

    for name, lun, _ in PARTITIONS:
        post_file = os.path.join(POST_BOOT, f"{name}_lun{lun}.bin")

        # Find matching pre-boot file
        pre_file = pre_files.get((name, lun))
        if pre_file is None:
            # Try without lun
            for (pn, pl), pf in pre_files.items():
                if pn == name:
                    pre_file = pf
                    break

        if not os.path.exists(post_file):
            missing.append(f"{name} (LUN{lun}): no post-boot file")
            continue

        if pre_file is None or not os.path.exists(pre_file):
            missing.append(f"{name} (LUN{lun}): no pre-boot file")
            continue

        with open(pre_file, "rb") as f:
            pre_data = f.read()
        with open(post_file, "rb") as f:
            post_data = f.read()

        pre_hash = hashlib.sha256(pre_data).hexdigest()[:16]
        post_hash = hashlib.sha256(post_data).hexdigest()[:16]

        if pre_data == post_data:
            unchanged.append(f"{name} (LUN{lun})")
        else:
            # Find first difference
            diff_off = -1
            for i in range(min(len(pre_data), len(post_data))):
                if pre_data[i] != post_data[i]:
                    diff_off = i
                    break
            if diff_off < 0 and len(pre_data) != len(post_data):
                diff_off = min(len(pre_data), len(post_data))

            magic = b"ANDROID-BOOT!"
            has_magic_pre = magic in pre_data
            has_magic_post = magic in post_data

            info = f"{name} (LUN{lun}): CHANGED"
            info += f" (pre={len(pre_data):,}B, post={len(post_data):,}B, first_diff=0x{diff_off:X})"
            if has_magic_post and not has_magic_pre:
                info += " *** NEW ANDROID-BOOT! ***"
            elif has_magic_post:
                info += " (has ANDROID-BOOT!)"

            changed.append(info)

    print(f"=== CHANGED PARTITIONS ({len(changed)}) ===")
    for c in changed:
        print(f"  {c}")

    print(f"\n=== UNCHANGED PARTITIONS ({len(unchanged)}) ===")
    for u in unchanged:
        print(f"  {u}")

    if missing:
        print(f"\n=== MISSING ({len(missing)}) ===")
        for m in missing:
            print(f"  {m}")

def cmd_search():
    """Search ALL backup files for ANDROID-BOOT! magic."""
    magic = b"ANDROID-BOOT!"

    print("Searching for ANDROID-BOOT! magic in all backup files...")
    print()

    for backup_dir, label in [(PRE_BOOT, "PRE-BOOT"), (POST_BOOT, "POST-BOOT")]:
        if not os.path.isdir(backup_dir):
            print(f"  {label}: directory not found ({backup_dir})")
            continue

        print(f"=== {label} ({backup_dir}) ===")
        found_any = False

        for root, dirs, files in os.walk(backup_dir):
            for fname in sorted(files):
                if not fname.endswith(".bin"):
                    continue
                fpath = os.path.join(root, fname)
                try:
                    with open(fpath, "rb") as f:
                        data = f.read()
                except:
                    continue

                pos = 0
                while True:
                    pos = data.find(magic, pos)
                    if pos < 0:
                        break
                    rel_path = os.path.relpath(fpath, backup_dir)
                    print(f"  FOUND in {rel_path} at offset 0x{pos:X}")
                    # Show some context
                    ctx = data[pos:pos+32]
                    print(f"    Hex: {ctx.hex()}")
                    print(f"    is_unlocked byte (off+0xD): 0x{data[pos+0xD]:02X}")
                    found_any = True
                    pos += len(magic)

        if not found_any:
            print(f"  No ANDROID-BOOT! found in any file.")
        print()

def cmd_rawsearch():
    """Search pre-boot backup with different sector size interpretations."""
    magic = b"ANDROID-BOOT!"

    print("Testing sector-size hypothesis...")
    print()

    # devinfo is at GPT sector 535022
    # With 4K sectors: byte offset = 535022 * 4096 = 0x829EE000
    # With 512B sectors: byte offset = 535022 * 512 = 0x1053DC00

    # Check if there's a full LUN4 dump or if we can read raw sectors
    print("The DXE driver may use a different sector mapping than EDL.")
    print("Key byte offsets to check on LUN4:")
    print(f"  4K sectors:  sector 535022 = byte 0x829EE000 ({535022 * 4096:,})")
    print(f"  512B sectors: sector 535022 = byte 0x1053DC00 ({535022 * 512:,})")
    print()
    print("To test: use EDL to read raw sectors at both offsets:")
    print(f"  edl rf 4 535022 1 /tmp/devinfo_4k.bin --sectorsize=4096")
    print(f"  edl rf 4 4280176 1 /tmp/devinfo_512.bin --sectorsize=512")
    print()
    print("Or read a range of 512-byte sectors starting at byte 0x829EE000:")
    print(f"  edl rf 4 4280176 8 /tmp/devinfo_512range.bin --sectorsize=512")

if __name__ == "__main__":
    if len(sys.argv) < 2:
        print(f"Usage: python3 {sys.argv[0]} <command>")
        print(f"  dump      - Read back partitions via EDL")
        print(f"  compare   - Compare pre-boot vs post-boot")
        print(f"  search    - Search all backups for ANDROID-BOOT!")
        print(f"  rawsearch - Show raw sector search instructions")
        sys.exit(1)

    cmd = sys.argv[1]
    if cmd == "dump":
        cmd_dump()
    elif cmd == "compare":
        cmd_compare()
    elif cmd == "search":
        cmd_search()
    elif cmd == "rawsearch":
        cmd_rawsearch()
    else:
        print(f"Unknown command: {cmd}")
        sys.exit(1)
