# OpenAccess EID - Icon Requirements

This document describes all icons required for the OpenAccess EID project.

## Icon Format Specifications

### Application Icons (.ico files)
All Windows application icons should be provided as `.ico` files containing multiple resolutions:
- **16x16** - Small icons (taskbar, title bar, list views)
- **32x32** - Standard size (desktop shortcuts, file explorer)
- **48x48** - Large icons (control panel, some dialogs)
- **256x256** - Extra large (Vista+ high DPI, detailed views)

Recommended: Use 32-bit PNG-compressed format for 256x256, standard BMP for smaller sizes.

### Credential Provider Tile Image (.bmp file)
**CRITICAL: Special format requirement for Windows Credential Provider!**

The credential provider tile image requires a specific BMP format that Windows expects for logon screen display. Many image editors create incompatible BMPs.

**Technical Specifications:**

| Property | Required Value | Notes |
|----------|----------------|-------|
| Dimensions | **128x128 pixels** | Scaled by Windows as needed |
| Bit depth | **32-bit BGRA** | Full color with alpha channel |
| Compression | **BI_BITFIELDS (3)** | CRITICAL - not BI_RGB! |
| Color masks | **Present (12 bytes)** | Required after BITMAPINFOHEADER |
| Resolution | 2834 x 2834 px/m (72 DPI) | Standard DPI |
| File size | ~65 KB (65592 bytes typical) | Header + pixel data |

**BMP Header Structure:**
```
Offset  Size  Field                Value
------  ----  -----               -----
0x00    2     Magic               "BM"
0x02    4     File size           0x000138 (65592 bytes)
0x0A    4     Pixel data offset   0x36 (54 bytes)
0x0E    4     Header size         40 (BITMAPINFOHEADER)
0x12    4     Width               128
0x16    4     Height              128
0x1A    2     Planes              1
0x1C    2     Bits per pixel      32
0x1E    4     Compression         3 (BI_BITFIELDS) ← CRITICAL
0x22    4     Image size          65538 bytes
0x26    4     X pixels per meter  2834 (72 DPI)
0x2A    4     Y pixels per meter  2834 (72 DPI)
0x36    12    Color masks         (see below) ← CRITICAL
```

**Color Mask Table (at offset 0x36):**
```
Mask        Value          Meaning
----------  -------------  ---------------------------
Red         0x00FF0000     Red channel (bits 16-23)
Green       0x0000FF00     Green channel (bits 8-15)
Blue        0x000000FF     Blue channel (bits 0-7)
Alpha       0xFF000000     Alpha channel (bits 24-31)
```

**Why BI_BITFIELDS is required:**
Windows Credential Providers expect 32-bit BMPs to explicitly define the RGBA bit positions using BI_BITFIELDS compression. Without the color mask table, Windows cannot interpret the pixel format correctly, resulting in a blank/missing tile image on the logon screen.

**Creating a Compatible BMP:**

1. **Use the reference file:** Copy `EIDCredentialProvider\SmartcardCredentialProvider.bmp` as a template
2. **Modify pixel data only:** Do not change header structure
3. **Avoid modern image editors:** Many tools (Photoshop, GIMP) save BMPs without BI_BITFIELDS
4. **Test before deploying:** The bitmap must render correctly on logon screen

**If you need to create a new tile image:**
- Start with the existing working BMP as a template
- Use a hex editor or BMP tool that preserves BI_BITFIELDS
- Or use Python with PIL/Pillow ensuring compression=3 and explicit masks

```python
# Example: Create compatible BMP with Pillow
from PIL import Image
import struct

# Load your design (PNG source)
img = Image.open("your_design.png").convert("RGBA")

# Save as BMP - NOTE: Pillow may not set BI_BITFIELDS correctly
# You may need to post-process the file to add the color masks
img.save("cred_tile_image.bmp", format="BMP")

# Then use a hex editor or script to:
# 1. Set compression field at 0x1E to 0x03 00 00 00
# 2. Insert color masks at 0x36
```

**Current status:** Working BMP exists in repo (restored from original)

---

## Transparency and Rounded Corners

The credential provider tile image supports **alpha channel transparency** (32-bit BGRA format). This allows for:

1. **Transparent backgrounds** - Black/dark corners can be made fully transparent
2. **Rounded corners** - Anti-aliased rounded corners with smooth transparency gradients

### Available Scripts

Four PowerShell scripts are provided in the `icons/` directory for image processing:

#### 1. `RoundedTransparent.ps1` (Recommended)
Creates smooth anti-aliased rounded corners with transparency.

```powershell
cd icons
.\RoundedTransparent.ps1 -OutputSize 512 -CornerRadius 64
```

**Parameters:**
- `-SourceFile` - Input BMP (default: `cred_tile_image.bmp`)
- `-OutputFile` - Output BMP (default: `cred_tile_image_rounded_transparent.bmp`)
- `-OutputSize` - Size in pixels (default: 512)
- `-CornerRadius` - Corner radius in pixels (default: 64)

**Output:** `cred_tile_image_rounded_transparent.bmp` - 512x512 with BI_BITFIELDS format

#### 2. `ConvertBmpToIco.ps1`
Converts BMP to multi-resolution ICO file for DisplayIcon in installed programs.

```powershell
cd icons
.\ConvertBmpToIco.ps1 -SourceBmp "cred_tile_image_rounded_transparent.bmp" -OutputIco "cred_provider.ico"
```

**Parameters:**
- `-SourceBmp` - Input BMP file (default: `cred_tile_image_rounded_transparent.bmp`)
- `-OutputIco` - Output ICO file (default: `cred_provider.ico`)

**Output:** Multi-resolution ICO with 16x16, 32x32, 48x48, and 256x256 sizes

**Use:** Regenerate `cred_provider.ico` when updating the credential provider tile image

### Windows Version Compatibility

| Windows Version | Transparency Support |
|-----------------|---------------------|
| Windows 10/11 | **Full support** - corners are properly transparent |
| Windows 7/8 | **Limited** - may show transparent areas as black/white |

### Current Tile Image Files

| File | Size | Description |
|------|------|-------------|
| `cred_tile_image.bmp` | 512x512 | Original source image |
| `cred_tile_image_rounded_transparent.bmp` | 512x512 | **Active** - Rounded corners with transparency |
| `cred_provider.ico` | Multi-size (16/32/48/256) | **Installed Programs** Display Icon |

### Applying Transparency to Your Design

1. **Start with your source image** at any size (PNG, BMP, etc.)
2. **Run the rounded corners script:**
   ```powershell
   cd icons
   .\RoundedTransparent.ps1 -SourceFile "your_source.bmp" -OutputSize 512 -CornerRadius 64
   ```
3. **Copy to credential provider:**
   ```powershell
   copy cred_tile_image_rounded_transparent.bmp ..\EIDCredentialProvider\SmartcardCredentialProvider.bmp
   ```
4. **Rebuild:**
   ```powershell
   cd ..
   .\build.ps1
   ```

---

## Application Icons (Window & Executable Icons)

These icons are embedded in the executable and displayed in:
- Window title bars
- Taskbar
- Task Manager
- Alt+Tab switcher
- File Explorer

### 1. EIDConfigurationWizard Icon
- **Filename:** `app_configuration_wizard.ico`
- **Used by:**
  - `EIDConfigurationWizard.exe`
  - `EIDConfigurationWizardElevated.exe`
- **Description:** Main configuration wizard for OpenAccess EID
- **Design suggestion:** Shield/gear combination, blue color scheme
- **Current status:** Not implemented (using default Windows icon)

### 2. EIDLogManager Icon
- **Filename:** `app_log_manager.ico`
- **Used by:** `EIDLogManager.exe`
- **Description:** Log viewer and management tool
- **Design suggestion:** Document/list icon with magnifying glass
- **Current status:** Has `EIDLogManager.ico` and `small.ico` (needs review)

### 3. EIDMigrate (CLI) Icon
- **Filename:** `app_migrate_cli.ico`
- **Used by:** `EIDMigrate.exe`
- **Description:** Command-line credential migration tool
- **Design suggestion:** Terminal/console icon with arrow
- **Current status:** Not implemented

### 4. EIDMigrateUI Icon
- **Filename:** `app_migrate_gui.ico`
- **Used by:** `EIDMigrateUI.exe`
- **Description:** GUI wizard for credential migration
- **Design suggestion:** Two computers with arrow between them, or document with export/import arrows
- **Current status:** Not implemented

### 5. EIDTraceConsumer Icon
- **Filename:** `app_trace_consumer.ico`
- **Used by:** `EIDTraceConsumer.exe`
- **Description:** ETW trace consumer utility
- **Design suggestion:** Pulse line or waveform icon
- **Current status:** Not implemented

### 6. Installer Icon
- **Filename:** `app_installer.ico`
- **Used by:** `EIDInstallx64.exe`
- **Description:** Main installer executable
- **Design suggestion:** Package/box icon, green color scheme to indicate installation
- **Current status:** Not implemented (using default NSIS icon)

---

## Credential Provider Icons

These icons appear on the Windows logon/lock screen.

### 7. Credential Provider Tile Image
- **Filename:** `cred_tile_image.bmp` (or `.png` with conversion)
- **Used by:** `EIDCredentialProvider.dll`
- **Resource ID:** `IDB_TILE_IMAGE` (101)
- **Current file:** `EIDCredentialProvider\SmartcardCredentialProvider.bmp`
- **Active source:** `icons/cred_tile_image_rounded_transparent.bmp` (512x512 with rounded corners)
- **Size:** 512x512 pixels (scaled by Windows as needed for logon screen display)
- **Description:** The icon displayed next to the OpenAccess EID credential tile on the Windows logon screen, lock screen, and UAC prompts
- **Design suggestion:** Smart card icon with user silhouette or badge - should be immediately recognizable as a smart card login method
- **Important:** This is the PRIMARY user-facing icon - users see this every time they log in!
- **CRITICAL:** See "Credential Provider Tile Image (.bmp file)" section above for exact format requirements
- **Format note:** Must be a 32-bit BMP with BI_BITFIELDS compression. Standard PNG/BMP conversions will NOT work - the tile will appear blank on logon screen.
- **Transparency:** Supports alpha channel - use `RoundedTransparent.ps1` to add rounded corners with transparency

### 8. Installed Programs Display Icon
- **Filename:** `cred_provider.ico`
- **Used by:** Windows "Installed Programs" list (Apps & Features in Settings)
- **Registry:** `HKLM\Software\Microsoft\Windows\CurrentVersion\Uninstall\OpenAccessEID\DisplayIcon`
- **Source:** Generated from `cred_tile_image_rounded_transparent.bmp` via `ConvertBmpToIco.ps1`
- **Sizes:** 16x16, 32x32, 48x48, 256x256 (multi-resolution ICO)
- **Description:** Icon displayed next to "OpenAccess EID" entry in Windows installed programs list, Add/Remove Programs, and uninstaller
- **Current status:** Implemented (matches credential provider tile branding)
- **Note:** Created by running `.\icons\ConvertBmpToIco.ps1` - regenerates ICO from current BMP source

---

## UI Element Icons

These icons are displayed within the application UI dialogs.

### 9. Shield Icon (UAC/Security)
- **Filename:** `ui_shield.ico`
- **Used in:**
  - EIDConfigurationWizard pages (IDC_06SHIELD, IDC_07SHIELD)
  - EIDMigrateUI pages (IDC_03_SHIELD, IDC_05_SHIELD, IDC_08_SHIELD, IDC_10_SHIELD)
- **Size:** 32x32 (displayed at 20x20 in dialogs)
- **Description:** Security indicator for administrative/sensitive operations
- **Design suggestion:** Standard Windows UAC shield icon (can reference system icon or include custom)
- **Current status:** Loading from system resources (empty path in RC files)

---

## Branding Icons

### 10. OpenAccess EID Brand Icon
- **Filename:** `brand_main.ico`
- **Used by:**
  - Start Menu folder icon
  - Uninstaller
  - About dialogs (future)
- **Description:** Main brand icon for OpenAccess EID suite
- **Design suggestion:** Smart card with lock, professional blue/gold color scheme
- **Current status:** Not implemented

---

## File Location

All icons should be placed in:
```
C:\Users\user\Documents\OpenAccessEID\icons\
```

---

## Automatic Icon Integration (build.ps1)

The `build.ps1` script **automatically copies icons** from the `icons/` folder to the appropriate project directories during the build process.

### How It Works

1. Place your icon files in the `icons/` directory with the correct filenames
2. Run `build.ps1`
3. Icons are automatically copied to their target locations
4. Projects are compiled with the new icons embedded

### Icon Mappings

| Source File (in icons/) | Destination | Project |
|------------------------|-------------|---------|
| `cred_tile_image_rounded_transparent.bmp` | `EIDCredentialProvider\SmartcardCredentialProvider.bmp` | Credential Provider (✓ active) |
| `cred_tile_image.bmp` | `EIDCredentialProvider\SmartcardCredentialProvider.bmp` | Credential Provider (original source) |
| `cred_provider.ico` | `Installer\cred_provider.ico` | Installed Programs Display Icon |
| `app_configuration_wizard.ico` | `EIDConfigurationWizard\app.ico` | Config Wizard |
| `app_log_manager.ico` | `EIDLogManager\EIDLogManager.ico` | Log Manager |
| `app_migrate_cli.ico` | `EIDMigrate\app.ico` | Migrate CLI |
| `app_migrate_gui.ico` | `EIDMigrateUI\app.ico` | Migrate GUI |
| `app_installer.ico` | `Installer\installer.ico` | Installer |

### Graceful Degradation

If an icon file is **not found** in the `icons/` directory:
- The build continues without errors
- The application uses default Windows icons (via `SetIcon()` fallback in EIDCardLibrary)
- A warning is displayed showing which icons were skipped

### Building

```powershell
# Standard build - copies any available icons
.\build.ps1

# Icons are copied before compilation
# See the "Processing Icons" section in build output
```

---

## Implementation Notes

### Icon Resource Implementation

All projects use a standardized icon resource ID:

```cpp
#define IDI_APP_ICON 101  // Consistent across all projects
```

The `SetIcon()` function in `EIDCardLibrary\Package.cpp` follows this priority:
1. Try loading `IDI_APP_ICON` (101) from the application's resources
2. Fall back to Windows system icon (imageres.dll, resource 58)

### Adding Icons to Projects (Manual Method)

To add an icon to a Visual C++ project:

1. **Add icon resource to .rc file:**
   ```rc
   // Replace existing or add new icon resource
   IDI_MAIN_ICON ICON "icons/app_configuration_wizard.ico"
   ```

2. **Add to resource.h:**
   ```cpp
   #define IDI_MAIN_ICON  101
   ```

3. **In WinMain or window creation:**
   ```cpp
   // Set window class icon
   wc.hIcon = LoadIcon(hInstance, MAKEINTRESOURCE(IDI_MAIN_ICON));
   wc.hIconSm = LoadIcon(hInstance, MAKEINTRESOURCE(IDI_MAIN_ICON));
   ```

### Project Files Requiring Updates

| Project | Resource File | Icon Resource ID | Status |
|---------|--------------|------------------|--------|
| EIDCredentialProvider | EIDCredentialProvider.rc | IDB_TILE_IMAGE (101) | Implemented |
| EIDConfigurationWizard | EIDConfigurationWizard.rc | IDI_APP_ICON (101) | Implemented |
| EIDLogManager | EIDLogManager.rc | IDI_APP_ICON (101) | Implemented |
| EIDMigrate | EIDMigrate.rc | IDI_APP_ICON (101) | Implemented |
| EIDMigrateUI | EIDMigrateUI.rc | IDI_APP_ICON (101) | Implemented |
| Installer | Installerx64.nsi | `Icon "installer.ico"` | Implemented |
| EIDTraceConsumer | (needs .rc file) | (needs adding) | Not implemented |

---

## Priority Order

1. **CRITICAL Priority:**
   - cred_tile_image.bmp (Windows logon screen - EVERY user sees this daily)

2. **High Priority:**
   - app_configuration_wizard.ico (main user-facing app)
   - app_migrate_gui.ico (migration wizard)
   - brand_main.ico (overall branding)

3. **Medium Priority:**
   - app_log_manager.ico (has existing, needs update)
   - app_migrate_cli.ico (CLI tool)
   - ui_shield.ico (security indicator)

4. **Low Priority:**
   - app_installer.ico (installer, seen briefly)
   - app_trace_consumer.ico (utility tool)

---

## Design Guidelines

- **Color Scheme:** Professional blue (#0078D4 Windows blue) as primary
- **Style:** Flat, modern Windows 11 style
- **Background:** Transparent for all sizes except 256x256 (can use PNG transparency)
- **Corners:** Use rounded corners with transparency for tile images - see `RoundedTransparent.ps1`
- **Contrast:** Ensure visibility at 16x16 scale
- **Consistency:** All app icons should share visual elements (color, shape language)

---

## References

For design inspiration, refer to:
- Windows 11 Fluent Design System icons
- Existing Windows Security icons
- Smart card/eID industry standards
