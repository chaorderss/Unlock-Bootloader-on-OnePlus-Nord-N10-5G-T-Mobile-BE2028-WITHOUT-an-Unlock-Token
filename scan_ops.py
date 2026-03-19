import sys

BLOCK = 64*1024*1024  # read in 64MB chunks

filepath = "global-oos-10-5-7/extracted/billie8_14_O.01_201121.ops"
print(f"Scanning: {filepath}")

elf_magic = b'\x7fELF'
targets = [
    b'ANDROID-BOOT!',
    b'Please flash unlock token',
    b'please flash unlock token',
    b'unlock_token',
    b'CmdTokenFlash',
]

results = {t: [] for t in targets}
elf_hits = []

offset = 0
prev_tail = b''
with open(filepath, 'rb') as f:
    while True:
        chunk = f.read(BLOCK)
        if not chunk:
            break
        buf = prev_tail + chunk
        base = offset - len(prev_tail)

        # scan ELF
        p = 0
        while True:
            idx = buf.find(elf_magic, p)
            if idx == -1:
                break
            elf_hits.append(base + idx)
            if len(elf_hits) > 30:
                break
            p = idx + 1

        # scan strings
        for t in targets:
            p = 0
            while True:
                idx = buf.find(t, p)
                if idx == -1:
                    break
                results[t].append(base + idx)
                p = idx + 1

        prev_tail = buf[-256:]
        offset += len(chunk)

print(f"\nELF headers at: {[hex(x) for x in elf_hits[:10]]}")
print()
for t, positions in results.items():
    if positions:
        print(f"[FOUND] '{t.decode('ascii','ignore')}' at: {[hex(x) for x in positions[:5]]}")
    else:
        print(f"[NOT FOUND] '{t.decode('ascii','ignore')}'")
