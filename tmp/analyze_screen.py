#!/usr/bin/env python3
import subprocess
subprocess.run(["sudo", "mirscreencast", "-m", "/run/mir_socket", "-s", "540", "1200", "-n", "1", "-f", "/tmp/sf.rgba"], capture_output=True)
with open('/tmp/sf.rgba','rb') as f:
    data = f.read()
w, h = 540, 1200
print(f"Size: {len(data)} bytes")

print("White pixel distribution by row band:")
for bs in range(0, h, 100):
    be = min(bs + 100, h)
    wc = tc = 0
    for y in range(bs, be, 2):
        for x in range(0, w, 2):
            o = (y * w + x) * 4
            r, g, b = data[o], data[o+1], data[o+2]
            tc += 1
            if r > 200 and g > 200 and b > 200:
                wc += 1
    pct = wc*100//max(tc,1)
    bar = '#' * pct
    print(f"  y={bs:4d}-{be:4d}: {pct:2d}% {bar}")

print("\nKey pixel samples:")
for name, x, y in [("StatusL", 50, 5), ("StatusR", 490, 5), ("Clock", 270, 250),
                     ("ClockL", 150, 250), ("BelowClk", 270, 350),
                     ("AppRow1", 100, 950), ("AppRow2", 270, 950), ("AppRow3", 440, 950),
                     ("Bottom", 270, 1150), ("DockL", 100, 1100), ("DockR", 440, 1100)]:
    o = (y * w + x) * 4
    r, g, b = data[o], data[o+1], data[o+2]
    print(f"  {name:12s} ({x:3d},{y:4d}): rgb({r:3d},{g:3d},{b:3d})")

print("\nColorful regions (potential icons):")
for bs in range(800, 1200, 50):
    be = min(bs+50, h)
    colorful = tc = 0
    for y in range(bs, be, 2):
        for x in range(0, w, 4):
            o = (y*w+x)*4
            r,g,b = data[o],data[o+1],data[o+2]
            tc += 1
            mx = max(r,g,b); mn = min(r,g,b)
            if mx - mn > 80 and mx > 100:
                colorful += 1
    pct = colorful*100//max(tc,1)
    print(f"  y={bs:4d}-{be:4d}: {pct:2d}% colorful")
