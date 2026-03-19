import struct

data = open('/tmp/ffs_modules/pe32_59d536f5_1.bin', 'rb').read()

def decode_bl(instr, pc):
    imm26 = instr & 0x03FFFFFF
    if imm26 & 0x02000000:
        imm26 -= 0x04000000
    return pc + imm26 * 4

def decode_adrp(instr, pc):
    immhi = (instr >> 5) & 0x7FFFF
    immlo = (instr >> 29) & 0x3
    imm = (immhi << 2) | immlo
    if imm & (1 << 20):
        imm -= (1 << 21)
    return (pc & ~0xFFF) + (imm << 12)

def disasm_range(start, end):
    for off in range(start, end, 4):
        instr = struct.unpack_from('<I', data, off)[0]
        desc = f'0x{instr:08X}'
        if (instr & 0xFC000000) == 0x94000000:
            desc = f'BL 0x{decode_bl(instr, off):X}'
        elif (instr & 0xFC000000) == 0x14000000:
            t = decode_bl(instr, off)
            desc = f'B 0x{t:X}'
        elif (instr & 0xFF000010) == 0x54000000:
            imm19 = (instr >> 5) & 0x7FFFF
            if imm19 & 0x40000: imm19 -= 0x80000
            cond = ['EQ','NE','CS','CC','MI','PL','VS','VC','HI','LS','GE','LT','GT','LE','AL','NV'][instr & 0xF]
            desc = f'B.{cond} 0x{off + imm19*4:X}'
        elif (instr & 0x7E000000) == 0x34000000:
            imm19 = (instr >> 5) & 0x7FFFF
            if imm19 & 0x40000: imm19 -= 0x80000
            op = 'CBNZ' if (instr >> 24) & 1 else 'CBZ'
            reg = instr & 0x1F
            size = 'W' if (instr >> 31) == 0 else 'X'
            desc = f'{op} {size}{reg} -> 0x{off + imm19*4:X}'
        elif (instr & 0x9F000000) == 0x90000000:
            page = decode_adrp(instr, off)
            rd = instr & 0x1F
            desc = f'ADRP X{rd}, 0x{page:X}'
        elif (instr & 0xFF800000) == 0x91000000:
            imm12 = (instr >> 10) & 0xFFF
            desc = f'ADD X{instr&0x1F}, X{(instr>>5)&0x1F}, #0x{imm12:X}'
        elif instr == 0xD65F03C0:
            desc = 'RET'
        elif instr == 0x2A1F03E0:
            desc = 'MOV W0, WZR'
        elif instr == 0x320003E0:
            desc = 'MOV W0, #1'
        print(f'  0x{off:X}: {desc}')

# Check "unlock" strings and context
print('=== "unlock" ASCII strings ===')
idx = 0
while True:
    idx = data.find(b'unlock', idx)
    if idx < 0: break
    context = data[idx:idx+40]
    print(f'  0x{idx:X}: {context[:40]}')
    idx += 1

# Check what's around 0x6186C and 0x61882 (UTF-16 "unlock")
print('\n=== UTF-16 unlock strings context ===')
for addr in [0x6186C, 0x61882]:
    s = ''
    p = addr
    while p < 0x62000:
        w = struct.unpack_from('<H', data, p)[0]
        if w == 0: break
        if 0x20 <= w <= 0x7E: s += chr(w)
        else: s = '???'; break
        p += 2
    print(f'  0x{addr:X}: "{s}"')
    # More context
    print(f'    Before: {data[addr-16:addr].hex()}')
    print(f'    Total: {data[addr:addr+40].hex()}')

# Check FRP reading - function around 0x37D38 in more detail
# Especially: what happens to X27 (X2 arg to 0x4FD10)?
print('\n=== 0x37D38 detailed (find X27 init) ===')
disasm_range(0x37D38, 0x37D9C)

# Look at the abl_log backup for carrier unlock messages
print('\n=== ABL log search for carrier/frp/unlock ===')
try:
    log = open('/Users/xmxx/pinganhuijia/memory/KMSG.txt', 'rb').read().lower()
    for term in [b'carrier', b'frp', b'token', b'is_allow', b'1bf518']:
        idx = 0
        while True:
            i = log.find(term, idx)
            if i < 0: break
            print(f'  "{term.decode()}" at {i}: {log[i:i+100]}')
            idx = i + 1
except:
    print('  No log file')

# Check abl_log.bin
try:
    abl_log_path = None
    import os
    for f in os.listdir('edl_backup/lun0/'):
        if 'log' in f.lower() or 'abl' in f.lower():
            abl_log_path = f'edl_backup/lun0/{f}'
    if abl_log_path:
        log2 = open(abl_log_path, 'rb').read().lower()
        print(f'Found {abl_log_path}')
        for term in [b'carrier', b'frp', b'is_allow', b'token']:
            idx2 = 0
            count = 0
            while True:
                i = log2.find(term, idx2)
                if i < 0 or count > 3: break
                print(f'  "{term.decode()}" at {i}: ...{log2[max(0,i-30):i+60]}...')
                idx2 = i + 1
                count += 1
except Exception as e:
    print(f'  Log error: {e}')
