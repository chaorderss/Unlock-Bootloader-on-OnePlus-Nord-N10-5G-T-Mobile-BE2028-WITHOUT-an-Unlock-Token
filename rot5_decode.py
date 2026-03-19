#!/usr/bin/env python3
def rot_decode(s, n=5):
    result = []
    for c in s:
        o = ord(c)
        if 33 <= o <= 126:
            result.append(chr((o - 33 - n) % 94 + 33))
        else:
            result.append(c)
    return ''.join(result)

# ROT5 decoded, then reverse => actual command
decoded = {
    'jqtxsth':       rot_decode('jqtxsth'),
    'jqtxsthsz':     rot_decode('jqtxsthsz'),
    's|tiyzmx2yttgjw': rot_decode('s|tiyzmx2yttgjw'),
    'wjiftqyttg2yttgjw': rot_decode('wjiftqyttg2yttgjw'),
    'lsnsnfwydjhwtk': rot_decode('lsnsnfwydjhwtk'),
    'lsnsnfwydjhwtksz': rot_decode('lsnsnfwydjhwtksz'),
    'xkfyfi': rot_decode('xkfyfi'),
    'uqjm':   rot_decode('uqjm'),
    'urzi':   rot_decode('urzi'),
    'jitrdyttg': rot_decode('jitrdyttg'),
}

print("=== ROT5 解码 =>  [reversed] ===")
for enc, dec in decoded.items():
    rev = dec[::-1]
    print(f"  {enc!r:30s} => {dec!r:25s} => reversed: {rev!r}")
