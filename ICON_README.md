# Application Icon Documentation

## Overview

Ruleset Builder uses custom application icons for all platforms:
- **icon.png** (256x256) - Used for Linux and macOS
- **icon.ico** (multi-size) - Used for Windows (contains 6 sizes)

## Design

The icon represents:
- **Blue gradient circle** - Professional, modern appearance
- **White document with list lines** - Ruleset/rules configuration
- **Green gear overlay** - Settings and configuration functionality

## File Details

### icon.png
- Format: PNG with transparency
- Size: 256x256 pixels
- Color depth: 32-bit RGBA
- File size: ~3KB

### icon.ico
- Format: Windows ICO
- Contains 6 sizes: 16x16, 32x32, 48x48, 64x64, 128x128, 256x256
- File size: ~23KB

## Regenerating the Icon

If you need to modify or recreate the icon:

### Prerequisites
```bash
pip install Pillow
```

### Generate Icon
```bash
python3 create_icon.py
```

This will create both `icon.png` and `icon.ico` files.

### Customization

Edit `create_icon.py` to customize:
- Colors (currently blue #3478F6, green for gear)
- Design elements (circles, lines, shapes)
- Sizes and proportions

## Integration

### Application Window
The icon is automatically loaded in `ruleset_builder.py`:
```python
def _set_icon(self, window):
    """Установка иконки приложения"""
    icon_path = os.path.join(os.path.dirname(os.path.abspath(__file__)), 'icon.png')
    if os.path.exists(icon_path):
        icon = tk.PhotoImage(file=icon_path)
        window.iconphoto(True, icon)
```

### PyInstaller Build
Icons are embedded in executables via `.github/workflows/build.yml`:

**Windows:**
```yaml
pyinstaller --onefile --windowed --name="RulesetBuilder" --icon=icon.ico main.py
```

**Linux/macOS:**
```yaml
pyinstaller --onefile --name="RulesetBuilder" --icon=icon.png main.py
```

## Platform-Specific Notes

### Windows
- Uses `.ico` format for best compatibility
- Icon appears in:
  - Window title bar
  - Taskbar
  - File Explorer
  - Alt+Tab switcher
  - System tray (if applicable)

### Linux
- Uses `.png` format
- Icon appears in:
  - Window title bar
  - Application launcher
  - Alt+Tab switcher

### macOS
- Uses `.png` format
- Icon appears in:
  - Dock
  - Application switcher
  - Finder

## Troubleshooting

### Icon not appearing
1. Verify icon files exist in the same directory as `ruleset_builder.py`
2. Check file permissions (should be readable)
3. For bundled executables, ensure PyInstaller included the icon

### Icon appears blurry
- Windows: Ensure `.ico` file contains all required sizes
- Linux/macOS: Use PNG at minimum 128x128 pixels

### Rebuilding without PIL
If PIL/Pillow is not available, `create_icon.py` will create a basic 32x32 icon:
```bash
python3 create_icon.py
# Creates basic icon.png
```

For production use, install PIL for best quality:
```bash
pip install Pillow
python3 create_icon.py
```

## Version History

- **v3.0.2** - Initial icon implementation
  - Blue gradient design with document representation
  - Multi-size ICO for Windows
  - Cross-platform PNG support
