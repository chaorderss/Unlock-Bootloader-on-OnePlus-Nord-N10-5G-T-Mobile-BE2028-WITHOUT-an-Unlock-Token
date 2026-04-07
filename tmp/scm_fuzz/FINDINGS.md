# SCM PIL Authentication Fuzzing Report
## Device: OnePlus Nord N10 5G (SDM765G, QCA6390)
## Kernel: 4.19.81-perf+ (Android/Ubuntu Touch)

---

## Executive Summary

Comprehensive SCM (Secure Channel Manager) fuzzing of the PIL (Peripheral Image Loader)
authentication flow on Qualcomm SDM765G reveals a **robust, hardware-enforced** firmware
verification system. No exploitable vulnerability was found through software-level attacks
from EL1 (Linux kernel). The authentication is secured by:

1. **Cryptographic signature verification** on firmware metadata (init_image)
2. **Per-segment hash verification** of firmware data (auth_and_reset)
3. **Atomic XPU hardware protection** — enabled at the START of auth_and_reset, not after

---

## SCM Infrastructure

### Working Interface
- `scm_call2(fn_id, &desc)` — direct SMC call to TrustZone (EL3)
- `scm_is_call_available(svc, cmd)` — check if an SCM call exists
- **Note**: All `qcom_scm_pas_*()` wrapper functions crash due to NULL `__scm` pointer
  (driver not probed). Only direct `scm_call2()` works.

### SCM Call Format
- Function ID: `0x42000000 | (svc << 8) | cmd`
- Arginfo: count in bits[3:0], type per arg in 2-bit fields from bit 4
- Types: SCM_VAL=0x0, SCM_RO=0x1, SCM_RW=0x2

### Enumerated Services
- 131 available SCM calls across 24 services
- 9 PAS commands (svc=0x02): init_image, mem_setup, auth_and_reset, shutdown,
  is_supported, cmd_0x08, get_pil_range, cmd_0x0e, cmd_0x0f

---

## PIL Authentication Flow (Confirmed Working from EL1)

```
PAS_SHUTDOWN(pid=9)         → ret=0   [XPU released, memory writable]
PAS_INIT_IMAGE(pid, mdt)    → ret=0   [Signature verified by TZ]
PAS_MEM_SETUP(pid, addr, sz)→ ret=0   [Memory region registered]
[Load firmware via ioremap_wc + memcpy_toio]     [5.2MB venus firmware]
PAS_AUTH_AND_RESET(pid)     → ret=0   [Hash verified, subsystem started, XPU locked]
```

### Memory Regions (from device tree)
| Subsystem | PID  | Base Address | Size   |
|-----------|------|-------------|--------|
| Venus     | 0x09 | 0x86a00000  | 5 MB   |
| ADSP      | 0x04 | 0x88d00000  | 40 MB  |
| WLAN FW   | N/A  | 0x8b500000  | 2 MB   |
| Modem     | 0x01 | 0x8b800000  | 248 MB |

### Global PIL Range
- 0x86000000 → 0x9b800000 (352 MB), returned by PAS cmd=0x09

---

## Attack Vectors Tested

### 1. Pre-Auth Firmware Mutation
**Method**: Load valid firmware, flip bytes, then call auth_and_reset
**Result**: ❌ REJECTED (ret=-22)
- Tested at offsets 0x1000-0x1400 in code segment
- TZ performs full hash verification of every segment
- Single byte change detected and rejected

### 2. TOCTOU — Same Thread (No Memory Barrier)
**Method**: Write mutation without `mb()`, immediately call auth_and_reset
**Result**: ❌ REJECTED
- Even without explicit memory barrier, TZ reads the mutated value
- 10 attempts at different 4-byte-aligned offsets, all rejected

### 3. TOCTOU — Concurrent kthread Race
**Method**: kthread on different CPU flips bytes while main thread calls auth_and_reset
**Result**: ❌ DEVICE CRASH
- XPU protection is enabled at the **START** of auth_and_reset
- Writes from other CPUs during auth trigger XPU violation
- **No TOCTOU window exists** — XPU locks atomically before hashing begins

### 4. Post-Auth Memory Modification
**Method**: Write to PIL region after successful auth_and_reset
**Result**: ❌ DEVICE CRASH
- XPU hardware blocks ALL writes after auth
- After fresh boot, XPU blocks reads AND writes
- cmd=0x08 (mystery PAS command) returns success but does NOT unlock XPU

### 5. Double init_image Attack
**Method**: Valid init_image → modified init_image → auth (hoping cached sig)
**Result**: ❌ REJECTED
- TZ re-verifies cryptographic signature on every init_image call
- Modified metadata rejected regardless of prior successful init

### 6. Stale TZ State
**Method**: Shutdown → skip init_image → mem_setup → load → auth
**Result**: ❌ REJECTED
- TZ does not cache metadata between PIL cycles
- init_image is required for every load operation

### 7. Memory Protection Service (svc=0x0c)
**Method**: Use MP commands to unlock XPU after auth
- cmd=0x01 (config_access_control): ret=-95 (EOPNOTSUPP)
- cmd=0x02 (restore_sec_cfg, 2 args): ret=-22, r0=-4
- cmd=0x03 (video_var, 1 arg=PID): ret=0 but no XPU effect
- cmd=0x04 (mem_protect): ret=-22 with all arg combinations
- cmd=0x05 (mem_protect_lock): ret=-22

### 8. TZ Debug Region Access
**Method**: Map 0xefd00000 (revealed by cmd=0x0e for PID 0)
**Result**: ❌ ioremap fails — region is TZ-only, unmappable from EL1

---

## WLAN Firmware Analysis (QCA6390)

### Loading Mechanism
- **MSA (Modem Self Authentication)** — firmware loaded BY modem, not HLOS
- ICNSS driver communicates via QMI, does NOT load firmware directly
- No HLOS PIL entry for WLAN (no PAS PID for WiFi)
- WLAN firmware region (0x8b500000, 2MB) managed by modem subsystem

### Firmware Details
- Chip ID: 0x320 (QCA6390)
- Firmware: WLAN.HL.3.3.1.c10-00007-QCAHLSWMTPLZ-1
- Build: 2020-10-22
- State: FW_READY (loaded by modem at boot)

### Implication
WLAN firmware cannot be modified from HLOS because:
1. No HLOS PIL path for WLAN (modem handles it)
2. Modem is itself PIL-authenticated
3. WLAN memory region not directly accessible from EL1

---

## Key Discoveries

### XPU Timing (Critical Finding)
```
Time:     [shutdown]--[init]--[mem_setup]--[fw_load]--[auth_and_reset]--[running]
XPU:      UNLOCKED   UNLOCKED  UNLOCKED   WRITABLE   LOCKED(atomic!)   LOCKED
EL1 R/W:  YES        YES       YES        YES        CRASH             CRASH
```
**The XPU locks at the ENTRY POINT of auth_and_reset, BEFORE hash verification begins.**
This eliminates all TOCTOU attack possibilities.

### PAS cmd=0x08
- Takes 1 arg (PID), returns success
- Does NOT unlock XPU
- Likely `pas_free_memory` or similar housekeeping command

### cmd=0x0e (PID 0)
- Returns 0xefd00000 / 0x280000 (2.5MB TZ region)
- This region is in TZ-only memory, unmappable from EL1

---

## Conclusion

The Qualcomm SDM765G PIL authentication is **secure against EL1 software attacks**.
The defense-in-depth approach combines:
- Cryptographic signature verification (RSA/ECDSA)
- Per-segment SHA-256 hash verification
- Hardware XPU protection with atomic lock timing
- No TOCTOU window (XPU locks before hashing)
- No stale state exploitation (metadata cleared between cycles)

### Remaining Attack Surface (Out of Scope)
- EL2/EL3 exploits (hypervisor/TZ vulnerabilities)
- Hardware glitching (voltage/clock fault injection)
- JTAG/SWD debug interfaces (if not disabled by fuses)
- Modem firmware vulnerabilities (to reach WLAN firmware)
- Supply chain attacks (pre-signed malicious firmware)
