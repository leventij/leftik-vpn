# Рисует иконку Leftik VPN (256x256) в build/icon.png и src/renderer/assets/icon.png
import os
from PIL import Image, ImageDraw

S = 1024
root = os.path.join(os.path.dirname(__file__), '..')

grad = Image.new('RGBA', (S, S))
px = grad.load()
a, b = (0xC6, 0xF7, 0x6B), (0x4F, 0xE0, 0xB6)
for y in range(S):
    for x in range(S):
        t = (x + y) / (2 * S)
        px[x, y] = tuple(int(a[i] + (b[i] - a[i]) * t) for i in range(3)) + (255,)

mask = Image.new('L', (S, S), 0)
ImageDraw.Draw(mask).rounded_rectangle((0, 0, S - 1, S - 1), radius=288, fill=255)
img = Image.new('RGBA', (S, S), (0, 0, 0, 0))
img.paste(grad, (0, 0), mask)

d = ImageDraw.Draw(img)
ink = (0x0B, 0x0D, 0x12, 255)
k = S / 64
d.line([(27 * k, 15 * k), (27 * k, 46 * k), (48 * k, 46 * k)], fill=ink, width=int(7 * k), joint='curve')
for (x, y) in [(27, 15), (48, 46)]:
    r = 3.5 * k
    d.ellipse((x * k - r, y * k - r, x * k + r, y * k + r), fill=ink)
d.line([(19 * k, 24 * k), (13 * k, 30 * k), (19 * k, 36 * k)], fill=ink, width=int(5 * k), joint='curve')
for (x, y) in [(19, 24), (19, 36)]:
    r = 2.5 * k
    d.ellipse((x * k - r, y * k - r, x * k + r, y * k + r), fill=ink)

out = img.resize((256, 256), Image.LANCZOS)
for p in ('build/icon.png', 'src/renderer/assets/icon.png'):
    path = os.path.join(root, p)
    os.makedirs(os.path.dirname(path), exist_ok=True)
    out.save(path)
    print('saved', path)
