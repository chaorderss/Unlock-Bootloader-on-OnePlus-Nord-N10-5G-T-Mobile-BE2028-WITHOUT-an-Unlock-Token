#!/usr/bin/env python3
"""
Quick CVE / exploit applicability check for:
  OnePlus Nord N10 5G T-Mobile (BE2028)
  Android 10 (Q), API 29
  Kernel 4.19.81-perf+
  Security patch: 2021-02-05
  SoC: Qualcomm SM6350 (lito) - Snapdragon 690
  Adreno 619L GPU
"""

import subprocess, re

def adb(cmd):
    r = subprocess.run(f'adb shell "{cmd}"', shell=True, capture_output=True, text=True, timeout=10)
    return r.stdout.strip()

print("=" * 70)
print("DEVICE SECURITY PROFILE SUMMARY")
print("=" * 70)

info = {
    "Android": "10 (Q) API 29",
    "Kernel": "4.19.81-perf+ (Jan 28 2021)",
    "Security Patch": "2021-02-05",
    "SoC": "SM6350 (Snapdragon 690) - lito",
    "GPU": "Adreno 619L (kgsl-3d0, world-writable)",
    "SELinux": "Enforcing",
    "Verified Boot": "green (locked)",
    "dm-verity": "enforcing",
    "Encryption": "encrypted (FBE/FDE)",
    "Build Type": "user (release-keys)",
    "ro.debuggable": "1 (debug bridge enabled)",
    "ro.secure": "1",
    "ADB user": "shell (uid=2000)",
    "Seccomp": "0 (not filtered for shell)",
    "NoNewPrivs": "0",
    "perf_event_paranoid": "3 (restricted)",
    "CONFIG_MODULES": "y (loadable modules supported)",
    "CONFIG_BPF_SYSCALL": "y",
    "CONFIG_BPF_JIT": "NOT SET",
    "CONFIG_USERFAULTFD": "NOT SET",
    "CONFIG_USER_NS": "NOT SET",
    "CONFIG_DEVMEM": "NOT SET",
    "CFI": "NOT FOUND (no CONFIG_CFI_CLANG)",
    "Shadow Call Stack": "NOT FOUND",
    "KASLR": "CONFIG_RANDOMIZE_BASE=y",
    "STACKPROTECTOR_STRONG": "y",
    "HARDENED_USERCOPY": "y",
    "SLAB_FREELIST_HARDENED": "y",
    "FORTIFY_SOURCE": "y",
    "debugfs": "mounted but not accessible from shell",
    "kallsyms": "Permission denied",
    "Block devices": "Not accessible from shell (root/system owned)",
}

for k, v in info.items():
    print(f"  {k:30s}: {v}")

print("\n" + "=" * 70)
print("ACCESSIBLE ATTACK SURFACE FROM ADB SHELL")
print("=" * 70)

surface = {
    "/dev/binder": "rw-rw-rw- (world accessible) - Android IPC",
    "/dev/hwbinder": "rw-rw-rw- (world accessible) - HAL IPC",
    "/dev/vndbinder": "rw-rw-rw- (world accessible) - Vendor IPC",
    "/dev/ashmem": "rw-rw-rw- (world accessible) - Shared memory",
    "/dev/kgsl-3d0": "rw-rw-rw- (world accessible) - Adreno GPU",
    "/dev/ion": "rw-rw-r-- (system group) - ION allocator",
    "/dev/diag": "rw-rw-rw- (world accessible!) - Qualcomm diag",
    "/dev/qseecom": "rw-rw-rw- (world accessible!) - QSEE TEE",
    "/dev/smcinvoke": "rw-rw---- (system/drmrpc) - SMC invoke",
}

for k, v in surface.items():
    print(f"  {k:25s}: {v}")

print("\n" + "=" * 70)
print("KNOWN CVE ANALYSIS (Kernel 4.19.81, Android 10, Patch 2021-02)")
print("=" * 70)

# CVEs that affect kernel 4.19.x before certain patches
cves = [
    {
        "id": "CVE-2021-1048",
        "desc": "Use-after-free in ep_loop_check_proc (epoll)",
        "kernel": "4.19.x < 4.19.219",
        "patch": "2021-12-01",
        "type": "Kernel LPE",
        "exploitability": "HIGH - actively exploited ITW, good public analysis",
        "accessible": True,
        "notes": "epoll available from unprivileged process. No special perms needed.",
    },
    {
        "id": "CVE-2021-0920",
        "desc": "Use-after-free in unix garbage collector (AF_UNIX)",
        "kernel": "4.19.x < 4.19.219",
        "patch": "2021-11-01",
        "type": "Kernel LPE",
        "exploitability": "HIGH - ITW exploit, used with CVE-2021-1048",
        "accessible": True,
        "notes": "AF_UNIX sockets available from shell. Race condition.",
    },
    {
        "id": "CVE-2020-0041",
        "desc": "Binder OOB write via BC_TRANSACTION",
        "kernel": "< 4.19.71 (patched in 4.19.71+)",
        "patch": "2020-03-01",
        "type": "Kernel LPE",
        "exploitability": "LOW - patched in 4.19.81",
        "accessible": True,
        "notes": "Kernel is 4.19.81, LIKELY PATCHED. Need to verify.",
    },
    {
        "id": "CVE-2021-0399",
        "desc": "Use-after-free in nl80211",
        "kernel": "4.19.x",
        "patch": "2021-03-01",
        "type": "Kernel LPE",
        "exploitability": "MEDIUM - needs specific wifi state",
        "accessible": False,
        "notes": "Needs CAP_NET_ADMIN or specific netlink permissions.",
    },
    {
        "id": "CVE-2021-28663 / CVE-2021-28664",
        "desc": "Mali GPU driver vulnerabilities",
        "kernel": "N/A",
        "patch": "N/A",
        "type": "Kernel LPE via GPU",
        "exploitability": "N/A - This device uses Adreno, not Mali",
        "accessible": False,
        "notes": "Wrong GPU. Device has Adreno 619L.",
    },
    {
        "id": "CVE-2020-11239 / CVE-2021-1905 / CVE-2021-1906",
        "desc": "Qualcomm Adreno GPU (kgsl) use-after-free / OOB",
        "kernel": "Qualcomm kgsl driver",
        "patch": "2021-05-01 / 2021-06-01",
        "type": "Kernel LPE via GPU",
        "exploitability": "HIGH - kgsl-3d0 is world-writable, no special perms",
        "accessible": True,
        "notes": "CVE-2021-1905: UAF in kgsl. CVE-2021-1906: improper GPU memory handling. Both patched AFTER our security patch (2021-02). VERY PROMISING.",
    },
    {
        "id": "CVE-2021-0306",
        "desc": "ContentProvider URI permission bypass",
        "kernel": "N/A (Framework)",
        "patch": "2021-01-01",
        "type": "Android Framework",
        "exploitability": "LOW - may be patched, requires app interaction",
        "accessible": True,
        "notes": "Framework bug, might help for lateral movement but not root.",
    },
    {
        "id": "CVE-2021-0313 / CVE-2021-0316",
        "desc": "Multiple Android Framework RCEs",
        "kernel": "N/A (Framework)",
        "patch": "2021-01-01",
        "type": "Android Framework",
        "exploitability": "LOW - need to send crafted data",
        "accessible": True,
        "notes": "Not directly useful for local privilege escalation.",
    },
    {
        "id": "CVE-2019-2215",
        "desc": "Binder UAF (Bad Binder / iovec)",
        "kernel": "4.14/4.19 unpatched",
        "patch": "2019-10-06",
        "type": "Kernel LPE",
        "exploitability": "LOW - likely patched in 4.19.81",
        "accessible": True,
        "notes": "Old CVE, kernel 4.19.81 with 2021 build should have this fix.",
    },
    {
        "id": "CVE-2021-22555",
        "desc": "Netfilter setsockopt heap OOB write",
        "kernel": "2.6.19-5.12",
        "patch": "2021-07-07",
        "type": "Kernel LPE",
        "exploitability": "HIGH - well-documented, affects 4.19.x",
        "accessible": True,
        "notes": "IPT_SO_SET_REPLACE needs CAP_NET_ADMIN. From unprivileged user namespace it works, but CONFIG_USER_NS is not set! May need to check if accessible from shell context.",
    },
    {
        "id": "CVE-2020-0069",
        "desc": "MediaTek CMDQ driver (mtk-su)",
        "kernel": "MediaTek only",
        "patch": "2020-03-01",
        "type": "Kernel LPE",
        "exploitability": "N/A - Qualcomm device, not MediaTek",
        "accessible": False,
        "notes": "Wrong SoC.",
    },
    {
        "id": "CVE-2020-0423",
        "desc": "binder UAF in binder_release_work",
        "kernel": "4.19.x < certain patch",
        "patch": "2020-10-01",
        "type": "Kernel LPE",
        "exploitability": "MEDIUM - tricky race, may be patched",
        "accessible": True,
        "notes": "Patch date is before build date (Jan 2021), likely fixed.",
    },
    {
        "id": "CVE-2021-3490",
        "desc": "BPF ALU32 bounds tracking",
        "kernel": "5.7-5.11",
        "patch": "2021-05-01",
        "type": "Kernel LPE",
        "exploitability": "N/A - kernel 4.19 not affected",
        "accessible": False,
        "notes": "Requires kernel 5.7+.",
    },
    {
        "id": "CVE-2021-38001 (Chromium V8)",
        "desc": "Chrome V8 type confusion → sandbox escape chain",
        "kernel": "N/A (browser)",
        "patch": "N/A",
        "type": "RCE + sandbox escape",
        "exploitability": "Complex multi-stage",
        "accessible": False,
        "notes": "Requires visiting malicious page, not ADB-based.",
    },
    {
        "id": "CVE-2021-0695 / CVE-2021-0461",
        "desc": "Qualcomm ION heap / KGSL memory leak / OOB",
        "kernel": "Qualcomm vendor",
        "patch": "2021-06/07",
        "type": "Kernel LPE",
        "exploitability": "MEDIUM - requires ION access (not world-writable on this device)",
        "accessible": False,
        "notes": "ION is rw-rw-r-- owned by system. Shell not in system group for ION.",
    },
    {
        "id": "CVE-2022-20186",
        "desc": "Mali GPU driver OOB access (used in ITW chains)",
        "kernel": "Mali only",
        "patch": "N/A",
        "type": "Kernel LPE",
        "exploitability": "N/A - Adreno GPU",
        "accessible": False,
        "notes": "Wrong GPU.",
    },
    {
        "id": "CVE-2023-0266 / CVE-2023-26083",
        "desc": "ALSA / Mali ITW chain",
        "kernel": "varies",
        "patch": "2023+",
        "type": "Kernel LPE",
        "exploitability": "N/A for this device",
        "accessible": False,
        "notes": "ALSA UAF might apply but needs audio group access.",
    },
    {
        "id": "Qualcomm diag (CVE-2019-10540 and similar)",
        "desc": "Qualcomm diagnostics interface exploitation",
        "kernel": "Qualcomm vendor",
        "patch": "varies",
        "type": "Kernel LPE / modem access",
        "exploitability": "MEDIUM-HIGH: /dev/diag is world-writable!",
        "accessible": True,
        "notes": "/dev/diag is rw-rw-rw-. Historically used for baseband exploitation. May allow direct memory access through diag protocol.",
    },
    {
        "id": "QSEECOM exploitation",
        "desc": "Qualcomm Secure Execution Environment via /dev/qseecom",
        "kernel": "Qualcomm vendor",
        "patch": "varies",
        "type": "TrustZone interface",
        "exploitability": "MEDIUM: /dev/qseecom is world-writable!",
        "accessible": True,
        "notes": "qseecom is world-writable. Can communicate with TrustZone applets. Historical CVEs in QSEE allow trustlet loading/manipulation. If we can reach keymaster, might manipulate RPMB.",
    },
    {
        "id": "Dirty Pipe (CVE-2022-0847)",
        "desc": "pipe buffer flag manipulation for file overwrite",
        "kernel": "5.8+",
        "patch": "N/A",
        "type": "Kernel LPE",
        "exploitability": "N/A - requires kernel 5.8+",
        "accessible": False,
        "notes": "Kernel 4.19 not affected.",
    },
]

print("\n--- TOP CANDIDATES (Accessible + High Exploitability) ---\n")
top = [c for c in cves if c["accessible"] and "HIGH" in c["exploitability"]]
for c in top:
    print(f"  ★ {c['id']}")
    print(f"    {c['desc']}")
    print(f"    Type: {c['type']}")
    print(f"    Exploitability: {c['exploitability']}")
    print(f"    Patched: {c['patch']} (our patch: 2021-02-05)")
    print(f"    Notes: {c['notes']}")
    print()

print("--- MEDIUM CANDIDATES ---\n")
med = [c for c in cves if c["accessible"] and "MEDIUM" in c["exploitability"]]
for c in med:
    print(f"  ◆ {c['id']}")
    print(f"    {c['desc']}")
    print(f"    Notes: {c['notes']}")
    print()

print("--- NOT APPLICABLE ---\n")
na = [c for c in cves if not c["accessible"]]
for c in na:
    print(f"  ✗ {c['id']}: {c['notes'][:60]}")

print("\n" + "=" * 70)
print("RECOMMENDED EXPLOITATION STRATEGY (Priority Order)")
print("=" * 70)

print("""
1. ★★★ CVE-2021-1905/1906 (Adreno KGSL UAF/OOB)
   - /dev/kgsl-3d0 is world-writable (crw-rw-rw-)
   - Patched 2021-05/06, our device patch is 2021-02 → VULNERABLE
   - Qualcomm Adreno GPU driver specific
   - Can trigger from unprivileged context via GPU ioctl
   - Would give kernel code execution → full root
   - Public PoCs exist for similar Adreno bugs

2. ★★★ CVE-2021-1048 + CVE-2021-0920 (epoll UAF + unix GC UAF)
   - Both patched 2021-11/12, our device is 2021-02 → VULNERABLE
   - Used together in real-world exploit chains
   - epoll/AF_UNIX available from shell without special permissions
   - Well-documented exploitation techniques
   - Kernel 4.19.81 is definitely vulnerable

3. ★★ /dev/qseecom exploitation
   - World-writable access to TrustZone interface!
   - Can potentially load/call secure applets
   - If keymaster/RPMB interface is reachable through QSEE,
     could potentially manipulate the RPMB-backed devinfo
   - Historical QSEE bugs allow arbitrary trustlet execution

4. ★★ /dev/diag (Qualcomm diagnostics)
   - World-writable!
   - Can potentially access modem/baseband functions
   - Historical exploitation allows memory read/write
   - May provide alternative path to root or partition access

5. ★ CVE-2021-22555 (Netfilter OOB write)
   - Patched 2021-07, our device 2021-02 → VULNERABLE
   - BUT needs CAP_NET_ADMIN
   - CONFIG_USER_NS is not set (can't create unprivileged NS)
   - Would need to chain with another bug for the capability

6. ★ Direct kernel module loading
   - CONFIG_MODULES=y, kernel supports loadable modules
   - BUT module signing is likely enforced
   - If we get root, can potentially load custom .ko

AFTER ROOT:
   - Disable SELinux (setenforce 0) or load permissive policy
   - Direct write to /dev/block/by-name/devinfo (sde46)
   - OR direct RPMB manipulation through root QSEE access
   - OR modify boot.img and flash via dd
   - OR set OEM unlock flag directly in memory via /dev/kmem
""")

# Also check: can we run native binaries?
print("=" * 70)
print("ADDITIONAL CHECKS")
print("=" * 70)

checks = [
    ("Writable temp dir", "ls -la /data/local/tmp/"),
    ("Can push binaries", "touch /data/local/tmp/test_write; echo rc=$?; rm /data/local/tmp/test_write"),
    ("SELinux context", "id -Z"),
    ("Available commands", "which su busybox magisk 2>/dev/null; echo done"),
    ("Installed packages (root)", "pm list packages 2>/dev/null | grep -iE 'root|magisk|supersu|su' | head -5"),
]

for label, cmd in checks:
    print(f"\n  {label}:")
    try:
        result = adb(cmd)
        for line in result.split('\n'):
            print(f"    {line}")
    except Exception as e:
        print(f"    Error: {e}")
