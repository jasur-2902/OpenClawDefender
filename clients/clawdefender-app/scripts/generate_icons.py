#!/usr/bin/env python3
"""Generate ClawDefender app icons, tray icon, and DMG background."""

import math
import struct
from pathlib import Path
from PIL import Image, ImageDraw, ImageFont, ImageFilter

ICONS_DIR = Path(__file__).parent.parent / "src-tauri" / "icons"

# Colors
DEEP_BLUE = (30, 64, 175)       # #1e40af
LIGHT_BLUE = (96, 165, 250)     # #60a5fa
WHITE = (255, 255, 255)
DARK_BG = (15, 23, 42)          # #0f172a


def draw_rounded_rect(draw, bbox, radius, fill):
    """Draw a rounded rectangle."""
    x0, y0, x1, y1 = bbox
    draw.rounded_rectangle(bbox, radius=radius, fill=fill)


def draw_shield(draw, cx, cy, size, fill, outline=None, outline_width=0):
    """Draw a shield shape centered at (cx, cy) with given size (height)."""
    w = size * 0.7   # width is 70% of height
    h = size

    # Shield points: top-left, top-right, right shoulder, right side,
    # bottom point, left side, left shoulder
    top = cy - h * 0.5
    bottom = cy + h * 0.5
    left = cx - w * 0.5
    right = cx + w * 0.5
    shoulder_y = top + h * 0.08  # slight curve at top

    # Build polygon points for a shield
    points = []
    # Top edge with slight curve (approximate with segments)
    steps = 12
    for i in range(steps + 1):
        t = i / steps
        x = left + t * (right - left)
        # Slight upward curve at top
        curve = -h * 0.03 * math.sin(t * math.pi)
        points.append((x, top - curve))

    # Right side tapering down to point
    side_steps = 16
    for i in range(1, side_steps + 1):
        t = i / side_steps
        # Right side curves inward toward bottom point
        x = right - (right - cx) * (t ** 1.2)
        y = top + t * (bottom - top)
        points.append((x, y))

    # Left side (mirror, going back up)
    for i in range(side_steps - 1, 0, -1):
        t = i / side_steps
        x = left + (cx - left) * (1 - t ** 1.2)
        y = top + t * (bottom - top)
        points.append((x, y))

    draw.polygon(points, fill=fill, outline=outline, width=outline_width)


def draw_shield_on_image(img, cx, cy, shield_size, fill, outline=None, outline_width=0):
    """Draw a shield on an image with anti-aliasing using supersampling."""
    # We draw on a larger image and scale down for anti-aliasing
    scale = 4
    big = Image.new("RGBA", (img.width * scale, img.height * scale), (0, 0, 0, 0))
    draw = ImageDraw.Draw(big)
    draw_shield(draw, cx * scale, cy * scale, shield_size * scale, fill, outline, outline_width * scale)
    big = big.resize((img.width, img.height), Image.LANCZOS)
    img.paste(Image.alpha_composite(img, big))
    return img


def generate_app_icon(size):
    """Generate the app icon at a given size."""
    img = Image.new("RGBA", (size, size), (0, 0, 0, 0))

    # Draw supersampled for anti-aliasing
    scale = 4
    big = Image.new("RGBA", (size * scale, size * scale), (0, 0, 0, 0))
    draw = ImageDraw.Draw(big)

    margin = size * scale * 0.05
    radius = size * scale * 0.22

    # Rounded square background (macOS style)
    draw_rounded_rect(
        draw,
        (margin, margin, size * scale - margin, size * scale - margin),
        radius=radius,
        fill=DEEP_BLUE,
    )

    # Subtle gradient overlay (lighter at top)
    overlay = Image.new("RGBA", big.size, (0, 0, 0, 0))
    odraw = ImageDraw.Draw(overlay)
    for y in range(int(margin), int(size * scale - margin)):
        t = (y - margin) / (size * scale - 2 * margin)
        alpha = int(40 * (1 - t))  # fade from semi-transparent white at top
        odraw.line([(int(margin), y), (int(size * scale - margin), y)], fill=(255, 255, 255, alpha))
    big = Image.alpha_composite(big, overlay)
    draw = ImageDraw.Draw(big)

    # Shield in center
    cx = size * scale / 2
    cy = size * scale / 2 + size * scale * 0.02  # slightly below center
    shield_h = size * scale * 0.6

    # Outer shield (light blue)
    draw_shield(draw, cx, cy, shield_h, fill=LIGHT_BLUE)

    # Inner shield (deep blue, smaller) to create border effect
    draw_shield(draw, cx, cy, shield_h * 0.82, fill=(20, 50, 140))

    # Claw/check mark inside shield — three diagonal lines suggesting a claw
    # Simple approach: draw a checkmark/claw shape
    claw_cx = cx
    claw_cy = cy + shield_h * 0.02
    claw_size = shield_h * 0.28

    # Three claw marks (diagonal lines)
    line_width = int(shield_h * 0.045)
    offsets = [-claw_size * 0.3, 0, claw_size * 0.3]
    for offset in offsets:
        x_start = claw_cx + offset - claw_size * 0.12
        y_start = claw_cy - claw_size * 0.35
        x_end = claw_cx + offset + claw_size * 0.12
        y_end = claw_cy + claw_size * 0.35
        draw.line(
            [(x_start, y_start), (x_end, y_end)],
            fill=LIGHT_BLUE,
            width=line_width,
        )
        # Add slight claw curve at bottom
        draw.line(
            [(x_end, y_end), (x_end - claw_size * 0.15, y_end + claw_size * 0.08)],
            fill=LIGHT_BLUE,
            width=line_width,
        )

    # Downscale with high-quality resampling
    img = big.resize((size, size), Image.LANCZOS)
    return img


def generate_tray_icon():
    """Generate a 22x22 shield tray icon (monochrome-ish, dark)."""
    size = 22
    scale = 8
    big = Image.new("RGBA", (size * scale, size * scale), (0, 0, 0, 0))
    draw = ImageDraw.Draw(big)

    cx = size * scale / 2
    cy = size * scale / 2 + size * scale * 0.02
    shield_h = size * scale * 0.85

    # Black shield silhouette for template usage
    draw_shield(draw, cx, cy, shield_h, fill=(0, 0, 0, 255))

    # Three claw lines inside (transparent/cut out effect)
    claw_size = shield_h * 0.25
    line_width = int(shield_h * 0.055)
    offsets = [-claw_size * 0.32, 0, claw_size * 0.32]
    for offset in offsets:
        x_start = cx + offset - claw_size * 0.1
        y_start = cy - claw_size * 0.3
        x_end = cx + offset + claw_size * 0.1
        y_end = cy + claw_size * 0.3
        draw.line(
            [(x_start, y_start), (x_end, y_end)],
            fill=(0, 0, 0, 0),
            width=line_width,
        )

    img = big.resize((size, size), Image.LANCZOS)
    return img


def generate_dmg_background():
    """Generate a 600x400 DMG background image."""
    w, h = 600, 400
    img = Image.new("RGBA", (w, h), DARK_BG)
    draw = ImageDraw.Draw(img)

    # Subtle gradient
    for y in range(h):
        t = y / h
        r = int(DARK_BG[0] + (DEEP_BLUE[0] - DARK_BG[0]) * t * 0.3)
        g = int(DARK_BG[1] + (DEEP_BLUE[1] - DARK_BG[1]) * t * 0.3)
        b = int(DARK_BG[2] + (DEEP_BLUE[2] - DARK_BG[2]) * t * 0.3)
        draw.line([(0, y), (w, y)], fill=(r, g, b, 255))

    # App icon on left (small version)
    app_icon = generate_app_icon(80)
    img.paste(app_icon, (140, 130), app_icon)

    # Arrow in center
    arrow_y = 170
    arrow_color = (148, 163, 184)  # slate-400
    # Arrow shaft
    draw.rectangle([260, arrow_y - 3, 340, arrow_y + 3], fill=arrow_color)
    # Arrow head
    draw.polygon([
        (340, arrow_y - 12),
        (360, arrow_y),
        (340, arrow_y + 12),
    ], fill=arrow_color)

    # Applications folder icon (simple folder shape)
    folder_x, folder_y = 400, 135
    folder_w, folder_h = 70, 60
    # Folder tab
    draw.rounded_rectangle(
        [folder_x, folder_y, folder_x + folder_w * 0.4, folder_y + 12],
        radius=3, fill=(59, 130, 246)
    )
    # Folder body
    draw.rounded_rectangle(
        [folder_x, folder_y + 8, folder_x + folder_w, folder_y + folder_h],
        radius=5, fill=(59, 130, 246)
    )
    # Folder front
    draw.rounded_rectangle(
        [folder_x + 2, folder_y + 18, folder_x + folder_w - 2, folder_y + folder_h - 2],
        radius=4, fill=(96, 165, 250)
    )

    # Text labels
    try:
        font_small = ImageFont.truetype("/System/Library/Fonts/SFNSMono.ttf", 12)
        font_label = ImageFont.truetype("/System/Library/Fonts/SFNSMono.ttf", 11)
    except (IOError, OSError):
        try:
            font_small = ImageFont.truetype("/System/Library/Fonts/Helvetica.ttc", 12)
            font_label = ImageFont.truetype("/System/Library/Fonts/Helvetica.ttc", 11)
        except (IOError, OSError):
            font_small = ImageFont.load_default()
            font_label = font_small

    # App name label
    draw.text((130, 220), "ClawDefender", fill=WHITE, font=font_small, anchor="la")
    # Applications label
    draw.text((400, 205), "Applications", fill=WHITE, font=font_label, anchor="la")

    # Instructions at bottom
    draw.text(
        (w / 2, 310),
        "Drag ClawDefender to Applications",
        fill=(148, 163, 184),
        font=font_small,
        anchor="ma",
    )

    return img.convert("RGB")


def create_icns(icon_512_path, output_path):
    """Create a minimal .icns file from the 512x512 PNG."""
    # Load and create multiple sizes
    img = Image.open(icon_512_path)
    sizes = {
        'ic08': 256,  # 256x256
        'ic09': 512,  # 512x512
    }

    # Build ICNS file manually
    entries = []
    for ostype, size in sizes.items():
        resized = img.resize((size, size), Image.LANCZOS)
        import io
        buf = io.BytesIO()
        resized.save(buf, format="PNG")
        png_data = buf.getvalue()
        entry_type = ostype.encode("ascii")
        entry_len = len(png_data) + 8  # 4 bytes type + 4 bytes length + data
        entries.append(struct.pack(">4sI", entry_type, entry_len) + png_data)

    body = b"".join(entries)
    total_len = len(body) + 8  # header is 4 bytes magic + 4 bytes total length
    icns_data = struct.pack(">4sI", b"icns", total_len) + body

    output_path.write_bytes(icns_data)


def create_ico(icon_path, output_path):
    """Create a .ico file from a PNG."""
    img = Image.open(icon_path)
    sizes = [(16, 16), (32, 32), (48, 48), (256, 256)]
    imgs = [img.resize(s, Image.LANCZOS) for s in sizes]
    imgs[0].save(str(output_path), format="ICO", sizes=sizes)


def main():
    ICONS_DIR.mkdir(parents=True, exist_ok=True)

    print("Generating app icons...")

    # Generate main icon sizes
    icon_configs = {
        "icon.png": 512,
        "32x32.png": 32,
        "128x128.png": 128,
        "128x128@2x.png": 256,
    }

    for filename, size in icon_configs.items():
        icon = generate_app_icon(size)
        path = ICONS_DIR / filename
        icon.save(str(path), "PNG")
        print(f"  Created {filename} ({size}x{size}) — {path.stat().st_size} bytes")

    # Generate .icns from 512x512
    print("Generating icon.icns...")
    create_icns(ICONS_DIR / "icon.png", ICONS_DIR / "icon.icns")
    print(f"  Created icon.icns — {(ICONS_DIR / 'icon.icns').stat().st_size} bytes")

    # Generate .ico
    print("Generating icon.ico...")
    create_ico(ICONS_DIR / "icon.png", ICONS_DIR / "icon.ico")
    print(f"  Created icon.ico — {(ICONS_DIR / 'icon.ico').stat().st_size} bytes")

    # Generate tray icon
    print("Generating tray icon...")
    tray = generate_tray_icon()
    tray_path = ICONS_DIR / "icon-tray.png"
    tray.save(str(tray_path), "PNG")
    print(f"  Created icon-tray.png — {tray_path.stat().st_size} bytes")

    # Generate DMG background
    print("Generating DMG background...")
    dmg = generate_dmg_background()
    dmg_path = ICONS_DIR / "dmg-background.png"
    dmg.save(str(dmg_path), "PNG")
    print(f"  Created dmg-background.png — {dmg_path.stat().st_size} bytes")

    print("\nDone! All icons generated.")


if __name__ == "__main__":
    main()
