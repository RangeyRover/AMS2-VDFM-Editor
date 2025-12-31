# AMS2-VDFM-Editor
Editor for AMS2 VDFM files
![VDFM Editor screenshot] (VDFM-Editor.png)
# VDFM Editor – Project CARS / Project CARS 2 / AMS2

A standalone, binary-safe editor for **VDFM** vehicle definition files used by  
**Project CARS**, **Project CARS 2**, and **Automobilista 2 (AMS2)**.

This tool is designed for **engineering-grade inspection and controlled modification**
of VDFM files while preserving the game’s internal structural rules.

---

## ✨ Key Features

### Header-Driven File Parsing
- Fully decodes the VDFM header and uses it as the **single source of truth**
- All sections are sliced dynamically:
  - DATA
  - STRING DATA
  - DATA MAP
  - END
  - padding bytes
- No hard-coded assumptions about string or map locations

---

### Module Management (Major Feature)

The editor understands VDFM **Data Map records** and exposes modules explicitly.

You can:
- ✅ **View all modules** (present + missing)
- ➕ **Add a module**
  - Inserts an 8-byte Data Map record
  - Writes the correct DATA pointer
  - Adds a filename string (append-only)
  - Updates header lengths
- ➖ **Remove a module**
  - Removes the Data Map record
  - Zeros the DATA pointer
  - Leaves unrelated strings untouched

Supported modules include (when present in the Data Map):

| Code | Module |
|----|----|
| `0x08` | Chassis (*.CDFBIN) |
| `0x18` | Engine (*.EDFBIN) |
| `0x20` | Clutches (*.CBFBIN) |
| `0x28` | Turbo (*.TBFBIN) |
| `0x40` | Gearbox (*.GDFBIN) |
| `0x48` | Suspension (*.SDFBIN) |
| `0x50` | Collision (*.XML) |
| `0x58` | Tyres (*.HDTBIN) |
| `0xB8` | KERS / DRS / Hybrid (*.BBFBIN) |
| `0xC0` | Push-to-Pass |

Unknown Data Map codes are **preserved and visible**, but not modified.

---

### Safe String Editing

- Strings are treated as **latin-1 byte data**
- You can:
  - Edit existing strings (safe resize)
  - Append new strings
  - Reuse existing strings when adding modules
- All pointer shifts are handled automatically
- Header `string_len` is recalculated every time

⚠️ **Important design rule**  
New strings are **always appended** to avoid breaking existing pointers.  
No automatic string compaction is performed.

---

### In-Place Float Editing

- Edit known float values directly in the DATA section
- Includes:
  - Wheel/tyre offsets
  - Tyre dimensions
  - Brake disc glow parameters
  - Backfire frequency values
- Floats are displayed **without scientific notation**
- Changes are strictly **in-place** (no file resize)

---

### Hex Viewer (Read-Only)

- Full-file hex view with ASCII side panel
- Jump to offsets instantly
- Used for verification and reverse-engineering

---

### Validation & Safety

- Structural validation on:
  - File open
  - Save / Save As
- Ensures:
  - Section lengths do not exceed file size
  - Data Map length is a multiple of 8
  - All pointers reference valid NUL-terminated strings
- Invalid states are reported via **copyable error dialogs**
- Structural issues do **not silently corrupt files**

---

## 🧠 Design Philosophy

- **Header-driven**
- **Append-only strings** to preserve pointer integrity
- Compatible with DougNY’s original VDFM translation
- AMS2-aware offsets and modules included


