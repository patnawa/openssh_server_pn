"""Render the application icon for OpenSSH Server Manager ("Key tile", final).

Concept: a Windows 11 style tile in a deep navy-to-teal gradient carrying a
white key. The key's bow is a small terminal screen with a ">_" prompt, so the
mark says "SSH keys" and "shell" in one shape.

How each size is made
  16, 20, 24, 32   hand-drawn pixel maps of the key (every stroke on the pixel
                   grid) over a tile rendered at 8x and box-filtered from a
                   whole-pixel box. The prompt is a bold 2-3 px ">" (the "_"
                   only from 24 up); the key has a single tooth at 16-24 and a
                   two-step bit from 32 up.
  40, 48, 64       hand-placed whole-pixel geometry drawn at 8x and
                   box-filtered, so straight edges stay crisp. The ">" is a
                   pixel staircase at 40 and 48.
  96, 128, 256     vector shapes drawn at 8x and downsampled with LANCZOS; the
                   straight edges are snapped to whole pixels at 96 and 128.
                   From 64 up the key outline gets small fillets, a contact
                   shadow, a recessed screen and a soft glow behind the prompt.

Every size keeps a transparent margin: 1 px at 16-32, 2-3 px (room for the
soft drop shadow) from 40 up.

Output (next to this script): icon-<size>.png for every size, app-256.png,
app.ico (all ten images) and preview.png.
Requires only Python 3 and Pillow.
"""
import io
import os
import struct

from PIL import Image, ImageChops, ImageDraw, ImageFilter, ImageFont

HERE = os.path.dirname(os.path.abspath(__file__))
SIZES = [16, 20, 24, 32, 40, 48, 64, 96, 128, 256]
SS = 8  # supersampling factor

# ---------------------------------------------------------------- palette
# Deep navy (top) to teal (bottom): its own identity next to the saturated
# Microsoft blues, and the teal ties in with the aqua prompt.
TILE_STOPS = [(0.00, (26, 58, 158)),
              (0.50, (12, 96, 180)),
              (1.00, (0, 150, 166))]
LIGHT_TINT = (120, 196, 255)   # lit (left) side of the tile
SHEEN = (178, 228, 255)        # cool light from the top
BEVEL = (190, 236, 255)        # light inner rim
EDGE_DARK = (4, 36, 84)        # dark bottom row
SHADOW = (3, 14, 40)
KEY_TOP = (255, 255, 255)
KEY_BOT = (216, 232, 247)
KEY_EDGE = (150, 182, 218)     # the key's darker bottom edge
SCREEN_TOP = (4, 14, 38)
SCREEN_BOT = (12, 34, 72)
PROMPT = (92, 236, 240)

# Pixel-map palette for the hand-drawn small sizes (RGBA, composited on tile).
PIX = {
    'W': KEY_TOP + (255,),
    'w': (226, 238, 250, 255),       # key, lower tone
    'k': (204, 222, 243, 255),       # key, darker bottom row
    'a': (255, 255, 255, 150),       # soft corner of the white key
    'b': (210, 226, 246, 120),       # soft bottom corner of the key
    'N': (7, 22, 54, 255),           # screen
    'n': (3, 11, 32, 255),           # screen, top row in shadow
    'C': PROMPT + (255,),
    's': SHADOW + (70,),             # 1-px contact shadow under the key
}


# ---------------------------------------------------------------- helpers
def mix(c1, c2, t):
    return tuple(int(round(a + (b - a) * t)) for a, b in zip(c1, c2))


def ramp(stops, t):
    t = min(1.0, max(0.0, t))
    for (p0, c0), (p1, c1) in zip(stops, stops[1:]):
        if t <= p1:
            return mix(c0, c1, (t - p0) / (p1 - p0) if p1 > p0 else 0)
    return stops[-1][1]


def ramp1(stops, t):
    """Scalar version of ramp(): stops are (t, value)."""
    t = min(1.0, max(0.0, t))
    for (p0, v0), (p1, v1) in zip(stops, stops[1:]):
        if t <= p1:
            return v0 + (v1 - v0) * ((t - p0) / (p1 - p0) if p1 > p0 else 0)
    return stops[-1][1]


def linear_gradient(w, h, stops, direction=(0.0, 1.0)):
    """Smooth multi-stop RGB gradient; computed small, then upscaled."""
    n = 96
    dx, dy = direction
    span = abs(dx) + abs(dy)
    img = Image.new('RGB', (n, n))
    px = img.load()
    for y in range(n):
        for x in range(n):
            u, v = (x + 0.5) / n - 0.5, (y + 0.5) / n - 0.5
            px[x, y] = ramp(stops, 0.5 + (u * dx + v * dy) / span)
    return img.resize((max(1, w), max(1, h)), Image.BICUBIC)


def alpha_ramp(w, h, stops, horizontal=False):
    """L image whose value follows scalar stops (0..1) along y (or x)."""
    n = 256
    line = Image.new('L', (n, 1) if horizontal else (1, n))
    for i in range(n):
        v = int(round(255 * ramp1(stops, (i + 0.5) / n)))
        line.putpixel((i, 0) if horizontal else (0, i), v)
    return line.resize((max(1, w), max(1, h)), Image.BILINEAR)


def radial_alpha(w, h, cx, cy, rx, ry, peak):
    """L-mode radial falloff (1 - d^2)^2 scaled by peak, centre in 0..1 units."""
    n = 96
    img = Image.new('L', (n, n))
    px = img.load()
    for y in range(n):
        for x in range(n):
            u = ((x + 0.5) / n - cx) / rx
            v = ((y + 0.5) / n - cy) / ry
            d = min(1.0, u * u + v * v)
            px[x, y] = int(round(255 * peak * (1 - d) ** 2))
    return img.resize((max(1, w), max(1, h)), Image.BICUBIC)


def in_box(canvas_size, box, img, fill=0):
    """Paste a box-sized image into an empty canvas-sized image of its mode."""
    x0, y0 = int(round(box[0])), int(round(box[1]))
    out = Image.new(img.mode, canvas_size, fill)
    out.paste(img, (x0, y0))
    return out


def rr_mask(size, box, r):
    """L mask of a rounded rectangle whose box is in exact pixel edges."""
    m = Image.new('L', size, 0)
    x0, y0, x1, y1 = box
    if x1 - x0 >= 1 and y1 - y0 >= 1:
        r = max(0, min(r, (x1 - x0) / 2, (y1 - y0) / 2))
        ImageDraw.Draw(m).rounded_rectangle((x0, y0, x1 - 1, y1 - 1), radius=r, fill=255)
    return m


def inset(box, d):
    return (box[0] + d, box[1] + d, box[2] - d, box[3] - d)


def fill_mask(canvas, mask, color_img_or_rgb, alpha=1.0):
    """Composite a colour (or RGB image) through an L mask onto canvas."""
    w, h = canvas.size
    if isinstance(color_img_or_rgb, tuple):
        layer = Image.new('RGBA', (w, h), color_img_or_rgb + (255,))
    else:
        layer = color_img_or_rgb.convert('RGBA')
    if alpha < 1.0:
        mask = mask.point(lambda v: int(round(v * alpha)))
    layer.putalpha(mask)
    canvas.alpha_composite(layer)


def gradient_in_box(canvas_size, box, stops, direction):
    """A canvas-sized RGB image with the gradient mapped onto box."""
    x0, y0, x1, y1 = [int(round(v)) for v in box]
    img = Image.new('RGB', canvas_size, stops[-1][1])
    img.paste(linear_gradient(x1 - x0, y1 - y0, stops, direction), (x0, y0))
    return img


mul = ImageChops.multiply
sub = ImageChops.subtract


# ---------------------------------------------------------------- tile
def draw_tile(canvas, box, radius, u, shadow=None, bevel=(1.0, 0.40, 0.18, 0.08), bottom=0.30):
    """Navy-to-teal tile with Fluent lighting.

    box and radius are in canvas (supersampled) px; u is one target pixel in
    canvas px. shadow = (blur, dy, alpha) in target px. bevel = (width in
    target px, alpha at top, middle, bottom) of the light rim on the tile's
    outer edge: it keeps the edge visible on a dark taskbar, while the deep
    body colour carries it on a light one (no dark hairline, which would sink
    into #202020). bottom = alpha of the dark bottom row.
    """
    size = canvas.size
    x0, y0, x1, y1 = box
    w, h = int(round(x1 - x0)), int(round(y1 - y0))
    mask = rr_mask(size, box, radius)

    if shadow:
        blur, dy, alpha = shadow
        sh = ImageChops.offset(mask, 0, int(round(dy * u))).filter(ImageFilter.GaussianBlur(blur * u))
        fill_mask(canvas, sh, SHADOW, alpha)

    body = Image.new('RGBA', size, (0, 0, 0, 0))
    fill_mask(body, mask, gradient_in_box(size, box, TILE_STOPS, (0.30, 1.0)))

    # lit left side and shaded right side (soft, no seam)
    lit = in_box(size, box, alpha_ramp(w, h, [(0, 1.0), (0.55, 0.0), (1, 0.0)], horizontal=True))
    fill_mask(body, mul(lit, mask), LIGHT_TINT, 0.16)
    shade = in_box(size, box, alpha_ramp(w, h, [(0, 0.0), (0.45, 0.0), (1, 1.0)], horizontal=True))
    fill_mask(body, mul(shade, mask), SHADOW, 0.15)

    # cool top sheen
    sheen = in_box(size, box, radial_alpha(w, h, 0.30, -0.05, 1.0, 0.62, 0.14))
    fill_mask(body, mul(sheen, mask), SHEEN)

    # dark bottom row: separates the tile from a light taskbar and gives it a base
    if bottom:
        bot = sub(mask, ImageChops.offset(mask, 0, -int(round(u))))
        fill_mask(body, bot, EDGE_DARK, bottom)

    # light rim (strongest at the top, faint at the bottom)
    bw, a_top, a_mid, a_bot = bevel
    inner = rr_mask(size, inset(box, bw * u), max(0, radius - bw * u))
    rim = sub(mask, inner)
    fade = in_box(size, box, alpha_ramp(w, h, [(0, a_top), (0.45, a_mid), (1, a_bot)]))
    fill_mask(body, mul(rim, fade), BEVEL)

    canvas.alpha_composite(body)


# ---------------------------------------------------------------- geometry
# Large sizes: design units on a 256 grid.
BASE = {
    'tile': (14, 13, 242, 241), 'tile_r': 34,
    'bow': (32, 72, 150, 180), 'bow_r': 30, 'bezel': 14, 'screen_r': 14,
    'shaft': (140, 112, 230, 140), 'shaft_r': 5,
    'bit': [(186, 130, 230, 160), (208, 130, 230, 176)], 'bit_r': 5,
    'chev': [(66, 106), (88, 126), (66, 146)], 'chev_w': 12,
    'under': (97, 140, 121, 152),
}
BASE_SCREEN = (46, 86, 136, 166)

# Light rim alpha at the top, middle and bottom of the tile. With the deep
# body colour this keeps the tile edge near 3-4:1 on both #F3F3F3 and #202020.
RIM_ALPHA = (0.30, 0.16, 0.10)
# Tile drop shadow (blur, dy, alpha) in px; it must fade out inside the margin.
SHADOWS = {40: (0.38, 0.35, 0.24), 48: (0.38, 0.35, 0.26), 64: (0.65, 0.7, 0.30)}

# Tile box per size (target px). 1 px margin at 16-32, 2-3 px (room for the
# shadow) from 40 up.
TILES = {16: ((1, 1, 15, 15), 2.5), 20: ((1, 1, 19, 19), 3), 24: ((1, 1, 23, 23), 3.5),
         32: ((1, 1, 31, 31), 4.5), 40: ((2, 2, 38, 38), 5.5), 48: ((2, 2, 46, 46), 6.5),
         64: ((3, 3, 61, 61), 9), 96: ((5, 4, 91, 90), 13), 128: ((7, 6, 121, 120), 17),
         256: (BASE['tile'], BASE['tile_r'])}

# Mid sizes: hand-placed whole-pixel geometry (target px).
# 'stairs' draws the ">" as a pixel staircase: rows y..y+2h, t px per row.
MID = {
    40: {'bow': (5, 11, 24, 29), 'bow_r': 4.5, 'bezel': 2, 'screen_r': 1.5,
         'shaft': (22, 18, 36, 22), 'shaft_r': 0.8,
         'bit': [(29, 21, 36, 25), (32, 21, 36, 28)], 'bit_r': 0.8,
         'stairs': {'x': 9, 'y': 16, 'h': 3, 't': 3}, 'under': (16, 21, 20, 23)},
    48: {'bow': (6, 13, 28, 35), 'bow_r': 5.5, 'bezel': 2, 'screen_r': 2,
         'shaft': (27, 21, 44, 26), 'shaft_r': 1,
         'bit': [(35, 25, 44, 30), (39, 25, 44, 34)], 'bit_r': 1,
         'stairs': {'x': 10, 'y': 19, 'h': 4, 't': 3}, 'under': (19, 26, 24, 28)},
    64: {'bow': (8, 18, 38, 47), 'bow_r': 7, 'bezel': 3, 'screen_r': 3,
         'shaft': (37, 29, 58, 36), 'shaft_r': 1.25,
         'bit': [(46, 35, 58, 41), (52, 35, 58, 45)], 'bit_r': 1.25},
}


def map_prompt(screen):
    """Map the base ">_" into a screen box (target px)."""
    bx0, by0, bx1, by1 = BASE_SCREEN
    sx0, sy0, sx1, sy1 = screen
    fx, fy = (sx1 - sx0) / (bx1 - bx0), (sy1 - sy0) / (by1 - by0)

    def p(x, y):
        return (sx0 + (x - bx0) * fx, sy0 + (y - by0) * fy)

    ux0, uy0 = p(*BASE['under'][:2])
    ux1, uy1 = p(*BASE['under'][2:])
    return [p(x, y) for x, y in BASE['chev']], BASE['chev_w'] * (fx + fy) / 2, (ux0, uy0, ux1, uy1)


def geometry(size):
    tile, tile_r = TILES[size]
    if size in MID:
        g = dict(MID[size])
    else:
        # scale the 256 design into this size's tile; snap edges below 256
        bt = BASE['tile']
        f = (tile[2] - tile[0]) / (bt[2] - bt[0])
        snap = (lambda v: float(round(v))) if size < 256 else (lambda v: v)

        def box(b):
            return (snap(tile[0] + (b[0] - bt[0]) * f), snap(tile[1] + (b[1] - bt[1]) * f),
                    snap(tile[0] + (b[2] - bt[0]) * f), snap(tile[1] + (b[3] - bt[1]) * f))

        g = {'bow': box(BASE['bow']), 'shaft': box(BASE['shaft']),
             'bit': [box(b) for b in BASE['bit']]}
        for k in ('bow_r', 'screen_r', 'shaft_r', 'bit_r'):
            g[k] = BASE[k] * f
        g['bezel'] = snap(BASE['bezel'] * f) if size < 256 else BASE['bezel']
    g['tile'], g['tile_r'] = tile, tile_r
    if size >= 64:
        g['smooth'] = size / 80.0
    g['screen'] = inset(g['bow'], g['bezel'])
    if 'stairs' not in g:
        g['chev'], g['chev_w'], g['under'] = map_prompt(g['screen'])
    return g


# ---------------------------------------------------------------- vector sizes
def key_mask(g, S):
    s = lambda b: tuple(v * SS for v in b)  # noqa: E731
    key = Image.new('L', (S, S), 0)
    d = ImageDraw.Draw(key)

    def rr(b, r):
        x0, y0, x1, y1 = b
        d.rounded_rectangle((x0, y0, x1 - 1, y1 - 1), radius=r, fill=255)

    rr(s(g['bow']), g['bow_r'] * SS)
    sx0, sy0, sx1, sy1 = s(g['shaft'])
    rr((sx0 - 4 * SS, sy0, sx1, sy1), g['shaft_r'] * SS)
    for b in g['bit']:
        bx0, by0, bx1, by1 = s(b)
        rr((bx0, by0, bx1, by1), g['bit_r'] * SS)
        d.rectangle((bx0, sy0 + 2 * SS, bx1 - 1, by0 + (by1 - by0) / 2), fill=255)  # square top
    if g.get('smooth'):
        # blur + threshold: rounds the outer corners and adds small fillets in
        # the inner ones (shaft into bow, the steps of the bit)
        key = key.filter(ImageFilter.GaussianBlur(g['smooth'] * SS)).point(lambda v: 255 if v >= 128 else 0)
    return key


def render_vector(size):
    g = geometry(size)
    S = size * SS
    u = SS
    s = lambda b: tuple(v * SS for v in b)  # noqa: E731
    canvas = Image.new('RGBA', (S, S), (0, 0, 0, 0))

    # drop shadow (blur, dy, alpha in px) sized to stay inside the margin
    shadow = SHADOWS.get(size, (size * 0.013, size * 0.010, 0.32))
    draw_tile(canvas, s(g['tile']), g['tile_r'] * SS, u, shadow=shadow,
              bevel=(max(1.0, size / 96), *RIM_ALPHA), bottom=0.18)
    tile_mask = rr_mask((S, S), s(g['tile']), g['tile_r'] * SS)

    key = key_mask(g, S)

    # soft contact shadow of the key on the tile
    off = max(1.0, size * 0.014) * u
    blur = max(0.8, size * 0.014) * u
    ksh = ImageChops.offset(key, 0, int(round(off))).filter(ImageFilter.GaussianBlur(blur))
    fill_mask(canvas, mul(ksh, tile_mask), SHADOW, 0.50 if size >= 48 else 0.35)

    # key body: white with a cool lower half, and a darker bottom edge
    kb = g['bow']
    kbox = (kb[0] * SS, kb[1] * SS, g['shaft'][2] * SS, max(b[3] for b in g['bit']) * SS)
    kbot = KEY_BOT if size >= 96 else mix(KEY_TOP, KEY_BOT, 0.6)
    fill_mask(canvas, key, gradient_in_box((S, S), kbox,
                                           [(0, KEY_TOP), (0.50, KEY_TOP), (1, kbot)], (0.2, 1)))
    edge_w = max(1.0, size / 128) * u
    kedge = sub(key, ImageChops.offset(key, 0, -int(round(edge_w))))
    fill_mask(canvas, kedge, KEY_EDGE, 0.55 if size >= 64 else 0.40)

    # terminal screen, recessed glass
    scr_box = s(g['screen'])
    scr = rr_mask((S, S), scr_box, g['screen_r'] * SS)
    fill_mask(canvas, scr, gradient_in_box((S, S), scr_box, [(0, SCREEN_TOP), (1, SCREEN_BOT)], (0.25, 1)))
    if size >= 48:
        # inner shadow from the top edge, light lip along the bottom edge
        d_in = max(1.0, size / 64) * u
        top_band = sub(scr, ImageChops.offset(scr, 0, int(round(d_in))))
        ish = mul(top_band.filter(ImageFilter.GaussianBlur(d_in)), scr)
        fill_mask(canvas, ish, (0, 0, 0), 0.65)
        lip = sub(scr, ImageChops.offset(scr, 0, -int(round(max(1.0, size / 128) * u))))
        fill_mask(canvas, lip, (120, 170, 220), 0.30)

    # prompt ">_"
    pr = Image.new('L', (S, S), 0)
    d = ImageDraw.Draw(pr)
    if 'stairs' in g:
        st = g['stairs']
        for i in range(2 * st['h'] + 1):
            x = st['x'] + st['h'] - abs(i - st['h'])
            y = st['y'] + i
            d.rectangle((x * SS, y * SS, (x + st['t']) * SS - 1, (y + 1) * SS - 1), fill=255)
        ux0, uy0, ux1, uy1 = s(g['under'])
        d.rectangle((ux0, uy0, ux1 - 1, uy1 - 1), fill=255)
    else:
        w = g['chev_w'] * SS
        pts = [(x * SS, y * SS) for x, y in g['chev']]
        d.line(pts, fill=255, width=int(round(w)), joint='curve')
        for x, y in (pts[0], pts[2]):
            d.ellipse((x - w / 2, y - w / 2, x + w / 2, y + w / 2), fill=255)
        ux0, uy0, ux1, uy1 = s(g['under'])
        d.rounded_rectangle((ux0, uy0, ux1 - 1, uy1 - 1), radius=w * 0.35, fill=255)
    if size >= 64:
        glow = pr.filter(ImageFilter.GaussianBlur(S * 0.022))
        fill_mask(canvas, mul(glow, scr), PROMPT, 0.50)
    fill_mask(canvas, pr, PROMPT)

    # faint diagonal reflection across the top-left of the glass
    if size >= 96:
        x0, y0, x1, y1 = scr_box
        refl = Image.new('L', (S, S), 0)
        ImageDraw.Draw(refl).polygon([(x0, y0), (x1, y0), (x1, y0 + (y1 - y0) * 0.10),
                                      (x0, y0 + (y1 - y0) * 0.58)], fill=255)
        refl = refl.filter(ImageFilter.GaussianBlur(S * 0.003))
        fill_mask(canvas, mul(refl, scr), (190, 225, 255), 0.07)

    # LANCZOS for the large sizes; BOX (exact coverage) keeps the
    # pixel-aligned mid sizes free of ringing.
    resample = Image.LANCZOS if size >= 96 else Image.BOX
    return canvas.resize((size, size), resample)


# ---------------------------------------------------------------- pixel maps
# '.' = tile only. Other letters: see PIX.
MAPS = {
    16: [
        "................",
        "................",
        "................",
        "..aWWWWWWa......",
        "..WnnnnnnW......",
        "..WNCCNNNW......",
        "..WNNCCNNW......",
        "..WNNNCCNWWWWW..",
        "..WNNCCNNWwwww..",
        "..WNCCNNNWssww..",
        "..WNNNNNNW..kk..",
        "..bkkkkkkb..ss..",
        "...ssssss.......",
        "................",
        "................",
        "................",
    ],
    20: [
        "....................",
        "....................",
        "....................",
        "....................",
        "....................",
        "..aWWWWWWWa.........",
        "..WnnnnnnnW.........",
        "..WNCCCNNNW.........",
        "..WNNCCCNNW.........",
        "..WNNNCCCNWWWWWWWW..",
        "..WNNCCCNNWwwwwwww..",
        "..WNCCCNNNWsssswww..",
        "..WNNNNNNNW....kkk..",
        "..bkkkkkkkb....sss..",
        "...sssssss..........",
        "....................",
        "....................",
        "....................",
        "....................",
        "....................",
    ],
    24: [
        "........................",
        "........................",
        "........................",
        "........................",
        "........................",
        "........................",
        "...aWWWWWWWWWWa.........",
        "...WWWWWWWWWWWW.........",
        "...WWnnnnnnnnWW.........",
        "...WWNCCNNNNNWW.........",
        "...WWNNCCNNNNWWWWWWWW...",
        "...WWNNNCCNNNWWWWWWWW...",
        "...WWNNCCNNNNWWwwwwww...",
        "...WWNCCNNCCNWWsssWWW...",
        "...WWNNNNNNNNWW...www...",
        "...WwwwwwwwwwwW...kkk...",
        "...bkkkkkkkkkkb...sss...",
        "....ssssssssss..........",
        "........................",
        "........................",
        "........................",
        "........................",
        "........................",
        "........................",
    ],
    32: [
        "................................",
        "................................",
        "................................",
        "................................",
        "................................",
        "................................",
        "................................",
        "................................",
        "....aWWWWWWWWWWWWWWa............",
        "....WWWWWWWWWWWWWWWW............",
        "....WWnnnnnnnnnnnnWW............",
        "....WWNNNNNNNNNNNNWW............",
        "....WWNCCCNNNNNNNNWW............",
        "....WWNNCCCNNNNNNNWW............",
        "....WWNNNCCCNNNNNNWWWWWWWWWW....",
        "....WWNNNNCCCNNNNNWWWWWWWWWW....",
        "....WWNNNCCCNNNNNNWWWWWWWWWW....",
        "....WWNNCCCNNNNNNNWWwwwwwwww....",
        "....WWNCCCNNNCCCCNWWsssWWWWW....",
        "....WWNNNNNNNNNNNNWW...kkwww....",
        "....WWNNNNNNNNNNNNWW...sswww....",
        "....WwwwwwwwwwwwwwwW.....kkk....",
        "....bkkkkkkkkkkkkkkb.....sss....",
        ".....ssssssssssssss.............",
        "................................",
        "................................",
        "................................",
        "................................",
        "................................",
        "................................",
        "................................",
        "................................",
    ],
}


def render_pixel(size):
    box, radius = TILES[size]
    S = size * SS
    canvas = Image.new('RGBA', (S, S), (0, 0, 0, 0))
    draw_tile(canvas, tuple(v * SS for v in box), radius * SS, SS, shadow=None,
              bevel=(1.0, *RIM_ALPHA), bottom=0.22)
    img = canvas.resize((size, size), Image.BOX)
    glyph = Image.new('RGBA', (size, size), (0, 0, 0, 0))
    gp = glyph.load()
    rows = MAPS[size]
    assert len(rows) == size, (size, len(rows))
    for y, row in enumerate(rows):
        assert len(row) == size, (size, y, len(row))
        for x, ch in enumerate(row):
            if ch in PIX:
                gp[x, y] = PIX[ch]
    img.alpha_composite(glyph)
    return img


def render(size):
    if size in MAPS:
        return render_pixel(size)
    return render_vector(size)


# ---------------------------------------------------------------- .ico
def ico_bytes(images):
    """Multi-size .ico: 32-bit BGRA DIB frames below 256 px, PNG at 256 px.

    Uncompressed DIB frames are the most compatible (Explorer, the Win32
    resource loader, .NET Framework's System.Drawing.Icon and its ToBitmap);
    PNG keeps the 256 px frame small, as Windows Vista and later expect.
    """
    frames = []
    for im in images:
        w, h = im.size
        if w >= 256:
            buf = io.BytesIO()
            im.save(buf, format='PNG', optimize=True)
            frames.append(buf.getvalue())
            continue
        px = im.load()
        header = struct.pack('<IiiHHIIiiII', 40, w, h * 2, 1, 32, 0, 0, 0, 0, 0, 0)
        xor = bytearray()
        for y in range(h - 1, -1, -1):          # bottom-up
            for x in range(w):
                r, g, b, a = px[x, y]
                xor += bytes((b, g, r, a))
        stride = ((w + 31) // 32) * 4
        and_mask = bytearray()
        for y in range(h - 1, -1, -1):
            row = bytearray(stride)
            for x in range(w):
                if px[x, y][3] == 0:
                    row[x // 8] |= 0x80 >> (x % 8)
            and_mask += row
        frames.append(header + bytes(xor) + bytes(and_mask))
    out = io.BytesIO()
    out.write(struct.pack('<HHH', 0, 1, len(images)))
    offset = 6 + 16 * len(images)
    for im, data in zip(images, frames):
        w, h = im.size
        out.write(struct.pack('<BBBBHHII', w % 256, h % 256, 0, 0, 1, 32, len(data), offset))
        offset += len(data)
    for data in frames:
        out.write(data)
    return out.getvalue()


# ---------------------------------------------------------------- preview
def font(px, bold=False):
    for name in (('segoeuib.ttf', 'arialbd.ttf') if bold else ('segoeui.ttf', 'arial.ttf')):
        try:
            return ImageFont.truetype(name, px)
        except OSError:
            pass
    return ImageFont.load_default()


def build_preview(icons):
    width = 1780
    pad, gap, label_h = 18, 10, 26
    lines = [[16, 20, 24, 32, 40, 48, 64], [96, 128], [256]]
    f_label, f_title = font(15), font(18, bold=True)

    def strip(bg, fg, title):
        h = 40 + sum(4 * max(line) + label_h + pad * 2 for line in lines)
        im = Image.new('RGBA', (width, h), bg + (255,))
        d = ImageDraw.Draw(im)
        d.text((pad, 10), title, font=f_title, fill=fg)
        y = 40
        for line in lines:
            x = pad
            line_h = 4 * max(line)
            for sz in line:
                ic = icons[sz]
                d.text((x, y + pad - 6), f"{sz} px", font=f_label, fill=fg)
                base = y + pad + label_h + line_h
                im.alpha_composite(ic, (x, base - sz))
                big = ic.resize((sz * 4, sz * 4), Image.NEAREST)
                im.alpha_composite(big, (x + sz + gap, base - 4 * sz))
                x += 5 * sz + gap + 2 * pad
            y += line_h + label_h + 2 * pad
        return im

    light = strip((0xF3, 0xF3, 0xF3), (40, 40, 40), 'Light taskbar  #F3F3F3   (1x and 4x nearest-neighbour)')
    dark = strip((0x20, 0x20, 0x20), (225, 225, 225), 'Dark taskbar  #202020   (1x and 4x nearest-neighbour)')
    out = Image.new('RGBA', (width, light.height + dark.height), (0, 0, 0, 255))
    out.alpha_composite(light, (0, 0))
    out.alpha_composite(dark, (0, light.height))
    return out.convert('RGB')


def main():
    icons = {}
    for sz in SIZES:
        icons[sz] = render(sz)
        assert icons[sz].size == (sz, sz) and icons[sz].mode == 'RGBA'
        icons[sz].save(os.path.join(HERE, f'icon-{sz}.png'))
    icons[256].save(os.path.join(HERE, 'app-256.png'))
    with open(os.path.join(HERE, 'app.ico'), 'wb') as fh:
        fh.write(ico_bytes([icons[s] for s in SIZES]))
    build_preview(icons).save(os.path.join(HERE, 'preview.png'), optimize=True)
    print('wrote', ', '.join(f'icon-{s}.png' for s in SIZES), 'app-256.png, app.ico and preview.png to', HERE)


if __name__ == '__main__':
    main()
