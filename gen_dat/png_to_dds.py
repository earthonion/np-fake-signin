#!/usr/bin/env python3
"""
Convert PNG to DXT5 compressed DDS files for PS4 profile avatars.

Generates: avatar64.dds, avatar128.dds, avatar260.dds, avatar440.dds
"""

import struct
import sys
from pathlib import Path

try:
    from PIL import Image
except ImportError:
    print("Error: Pillow is required. Install with: pip install Pillow")
    sys.exit(1)

# DDS constants
DDS_MAGIC = 0x20534444  # "DDS "

# Header flags
DDSD_CAPS = 0x1
DDSD_HEIGHT = 0x2
DDSD_WIDTH = 0x4
DDSD_PITCH = 0x8
DDSD_PIXELFORMAT = 0x1000
DDSD_LINEARSIZE = 0x80000

DDPF_FOURCC = 0x4

DDSCAPS_TEXTURE = 0x1000

# Avatar sizes
AVATAR_SIZES = [64, 128, 260, 440]


def rgb_to_565(r, g, b):
    """Convert RGB888 to RGB565."""
    return ((r >> 3) << 11) | ((g >> 2) << 5) | (b >> 3)


def rgb565_to_rgb(c):
    """Convert RGB565 to RGB888."""
    r = ((c >> 11) & 0x1F) << 3
    g = ((c >> 5) & 0x3F) << 2
    b = (c & 0x1F) << 3
    return r, g, b


def color_distance(c1, c2):
    """Calculate squared color distance."""
    return sum((a - b) ** 2 for a, b in zip(c1, c2))


def compress_dxt5_block(pixels):
    """
    Compress a 4x4 block of RGBA pixels to DXT5 format.
    pixels: list of 16 (r, g, b, a) tuples
    Returns: 16 bytes of DXT5 data
    """
    # Extract alpha values
    alphas = [p[3] for p in pixels]

    # Find min/max alpha
    alpha0 = max(alphas)
    alpha1 = min(alphas)

    # Generate alpha palette (8 values)
    if alpha0 > alpha1:
        alpha_palette = [alpha0, alpha1]
        for i in range(6):
            alpha_palette.append(((6 - i) * alpha0 + (1 + i) * alpha1) // 7)
    else:
        alpha_palette = [alpha0, alpha1]
        for i in range(4):
            alpha_palette.append(((4 - i) * alpha0 + (1 + i) * alpha1) // 5)
        alpha_palette.extend([0, 255])

    # Find best alpha index for each pixel (48 bits = 16 * 3 bits)
    alpha_indices = 0
    for i, a in enumerate(alphas):
        best_idx = 0
        best_dist = abs(a - alpha_palette[0])
        for j in range(1, 8):
            dist = abs(a - alpha_palette[j])
            if dist < best_dist:
                best_dist = dist
                best_idx = j
        alpha_indices |= (best_idx << (i * 3))

    # Pack alpha block (8 bytes)
    alpha_block = struct.pack('<BB', alpha0, alpha1)
    alpha_block += struct.pack('<HHH',
        alpha_indices & 0xFFFF,
        (alpha_indices >> 16) & 0xFFFF,
        (alpha_indices >> 32) & 0xFFFF
    )

    # Extract RGB values
    colors = [(p[0], p[1], p[2]) for p in pixels]

    # Find min/max colors (simple approach - use actual min/max)
    min_color = [255, 255, 255]
    max_color = [0, 0, 0]
    for c in colors:
        for i in range(3):
            min_color[i] = min(min_color[i], c[i])
            max_color[i] = max(max_color[i], c[i])

    color0 = rgb_to_565(max_color[0], max_color[1], max_color[2])
    color1 = rgb_to_565(min_color[0], min_color[1], min_color[2])

    # Ensure color0 > color1 for 4-color mode
    if color0 < color1:
        color0, color1 = color1, color0
        max_color, min_color = min_color, max_color
    elif color0 == color1:
        color0 = min(color0 + 1, 0xFFFF)

    # Generate color palette
    c0 = rgb565_to_rgb(color0)
    c1 = rgb565_to_rgb(color1)
    palette = [
        c0,
        c1,
        tuple((2 * c0[i] + c1[i]) // 3 for i in range(3)),
        tuple((c0[i] + 2 * c1[i]) // 3 for i in range(3))
    ]

    # Find best color index for each pixel
    color_indices = 0
    for i, c in enumerate(colors):
        best_idx = 0
        best_dist = color_distance(c, palette[0])
        for j in range(1, 4):
            dist = color_distance(c, palette[j])
            if dist < best_dist:
                best_dist = dist
                best_idx = j
        color_indices |= (best_idx << (i * 2))

    # Pack color block (8 bytes)
    color_block = struct.pack('<HHI', color0, color1, color_indices)

    return alpha_block + color_block


def create_dxt5_dds(img):
    """Create DXT5 compressed DDS data from PIL Image."""
    width, height = img.size

    # Ensure RGBA
    if img.mode != 'RGBA':
        img = img.convert('RGBA')

    # Pad to multiple of 4
    pad_w = (4 - (width % 4)) % 4
    pad_h = (4 - (height % 4)) % 4
    if pad_w or pad_h:
        new_img = Image.new('RGBA', (width + pad_w, height + pad_h), (0, 0, 0, 0))
        new_img.paste(img, (0, 0))
        img = new_img
        width, height = img.size

    pixels = list(img.getdata())

    # Compress blocks
    compressed = bytearray()
    for by in range(height // 4):
        for bx in range(width // 4):
            block = []
            for py in range(4):
                for px in range(4):
                    idx = (by * 4 + py) * width + (bx * 4 + px)
                    block.append(pixels[idx])
            compressed.extend(compress_dxt5_block(block))

    # Calculate linear size
    linear_size = ((width + 3) // 4) * ((height + 3) // 4) * 16

    # Create header
    header_size = 124
    flags = DDSD_CAPS | DDSD_HEIGHT | DDSD_WIDTH | DDSD_PIXELFORMAT | DDSD_LINEARSIZE

    # Pixel format (DXT5)
    pf = struct.pack('<IIIIIIII',
        32,           # size
        DDPF_FOURCC,  # flags
        0x35545844,   # fourCC = "DXT5"
        0, 0, 0, 0, 0 # RGB bit counts/masks (unused for compressed)
    )

    header = struct.pack('<IIIIIII',
        header_size,
        flags,
        height,
        width,
        linear_size,
        0,  # depth
        0   # mipmap count
    )
    header += b'\x00' * 44  # reserved
    header += pf
    header += struct.pack('<IIIII',
        DDSCAPS_TEXTURE,  # caps1
        0, 0, 0, 0        # caps2-4, reserved
    )

    return struct.pack('<I', DDS_MAGIC) + header + bytes(compressed)


def convert_png_to_dds(png_file, out_dir):
    """Convert PNG to multiple DXT5 DDS sizes."""

    png_path = Path(png_file)
    output_dir = Path(out_dir)

    if not png_path.exists():
        print(f"Error: PNG file not found: {png_path}")
        sys.exit(1)

    output_dir.mkdir(parents=True, exist_ok=True)

    # Load source image
    img = Image.open(png_path)

    # Convert to RGBA if needed
    if img.mode != 'RGBA':
        img = img.convert('RGBA')

    print(f"Converting {png_path.name} ({img.width}x{img.height}) to DXT5")

    for size in AVATAR_SIZES:
        # Resize with high-quality resampling
        resized = img.resize((size, size), Image.Resampling.LANCZOS)

        # Create DXT5 DDS
        dds_data = create_dxt5_dds(resized)

        output_path = output_dir / f"avatar{size}.dds"
        with open(output_path, 'wb') as f:
            f.write(dds_data)

        print(f"  Created {output_path.name} ({size}x{size}, {len(dds_data)} bytes)")


if __name__ == '__main__':
    if len(sys.argv) < 3:
        print("Usage: png_to_dds.py <input.png> <output_dir>")
        print()
        print("Example:")
        print("  png_to_dds.py template/profile/avatar.png template/profile/")
        sys.exit(1)

    png_path = sys.argv[1]
    output_dir = sys.argv[2]

    convert_png_to_dds(png_path, output_dir)
    print("Done!")
