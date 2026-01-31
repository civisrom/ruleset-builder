#!/usr/bin/env python3
"""
Script to create icon for Ruleset Builder
Creates a simple icon representing network rules/routing
"""

try:
    from PIL import Image, ImageDraw, ImageFont
    PIL_AVAILABLE = True
except ImportError:
    PIL_AVAILABLE = False
    print("PIL not available, will create basic icon")

import os

def create_icon_pil():
    """Create icon using PIL"""
    # Create 256x256 image for high quality
    size = 256
    img = Image.new('RGBA', (size, size), (0, 0, 0, 0))
    draw = ImageDraw.Draw(img)

    # Background circle (gradient-like effect with multiple circles)
    center = size // 2

    # Outer glow
    draw.ellipse([10, 10, size-10, size-10], fill=(66, 135, 245, 200))
    draw.ellipse([20, 20, size-20, size-20], fill=(52, 120, 230, 255))

    # Draw document/list representation
    padding = 60
    doc_left = padding
    doc_right = size - padding
    doc_top = padding + 10
    doc_bottom = size - padding

    # White document background
    draw.rounded_rectangle(
        [doc_left, doc_top, doc_right, doc_bottom],
        radius=10,
        fill=(255, 255, 255, 250)
    )

    # Draw list lines (representing rules)
    line_color = (52, 120, 230, 255)
    line_start = doc_left + 25
    line_end = doc_right - 25

    y_positions = [90, 115, 140, 165, 190]
    for y in y_positions:
        # Bullet point
        draw.ellipse([line_start - 5, y - 3, line_start + 3, y + 3], fill=line_color)
        # Line
        draw.rectangle([line_start + 15, y - 2, line_end, y + 2], fill=line_color)

    # Add gear icon overlay (representing settings/configuration)
    gear_center_x = size - 50
    gear_center_y = 50
    gear_size = 25

    draw.ellipse(
        [gear_center_x - gear_size, gear_center_y - gear_size,
         gear_center_x + gear_size, gear_center_y + gear_size],
        fill=(100, 180, 100, 255),
        outline=(80, 160, 80, 255),
        width=3
    )

    # Inner gear circle
    inner_size = gear_size // 2
    draw.ellipse(
        [gear_center_x - inner_size, gear_center_y - inner_size,
         gear_center_x + inner_size, gear_center_y + inner_size],
        fill=(255, 255, 255, 255)
    )

    return img

def create_icon_basic():
    """Create a basic icon without PIL using raw bytes"""
    # This creates a minimal 32x32 PNG icon
    # PNG signature + IHDR + simple blue square + IEND

    import struct
    import zlib

    width, height = 32, 32

    # Create raw image data (RGBA)
    raw_data = bytearray()
    for y in range(height):
        raw_data.append(0)  # Filter byte for each scanline
        for x in range(width):
            # Create a simple gradient blue icon
            if 4 <= x < 28 and 4 <= y < 28:
                # Blue square with gradient
                intensity = int(200 - (y * 3))
                raw_data.extend([52, 120, intensity, 255])  # RGBA
            else:
                raw_data.extend([0, 0, 0, 0])  # Transparent

    # Compress the data
    compressed = zlib.compress(bytes(raw_data))

    # Build PNG file
    png = bytearray()

    # PNG signature
    png.extend(b'\x89PNG\r\n\x1a\n')

    # IHDR chunk
    ihdr_data = struct.pack('>IIBBBBB', width, height, 8, 6, 0, 0, 0)
    png.extend(struct.pack('>I', len(ihdr_data)))
    png.extend(b'IHDR')
    png.extend(ihdr_data)
    png.extend(struct.pack('>I', zlib.crc32(b'IHDR' + ihdr_data)))

    # IDAT chunk
    png.extend(struct.pack('>I', len(compressed)))
    png.extend(b'IDAT')
    png.extend(compressed)
    png.extend(struct.pack('>I', zlib.crc32(b'IDAT' + compressed)))

    # IEND chunk
    png.extend(struct.pack('>I', 0))
    png.extend(b'IEND')
    png.extend(struct.pack('>I', zlib.crc32(b'IEND')))

    return bytes(png)

def main():
    """Main function to create icon files"""

    if PIL_AVAILABLE:
        print("Creating high-quality icon with PIL...")
        img = create_icon_pil()

        # Save as PNG
        img.save('icon.png', 'PNG')
        print("✓ Created icon.png (256x256)")

        # Create ICO file with multiple sizes
        icon_sizes = [(256, 256), (128, 128), (64, 64), (48, 48), (32, 32), (16, 16)]
        img.save('icon.ico', format='ICO', sizes=icon_sizes)
        print("✓ Created icon.ico (multi-size)")

    else:
        print("Creating basic icon without PIL...")
        png_data = create_icon_basic()

        with open('icon.png', 'wb') as f:
            f.write(png_data)
        print("✓ Created icon.png (32x32)")
        print("⚠ Note: ICO file requires PIL. Install with: pip install Pillow")
        print("  For now, using PNG as icon")

    print("\nIcon files created successfully!")
    print("Location: " + os.getcwd())

if __name__ == '__main__':
    main()
