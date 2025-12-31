#!/usr/bin/env python3
# vdfm_editor.py
# Project CARS / Project CARS 2 / AMS2 – VDFM Standalone Editor
#
# COMPLETE DROP-IN VERSION (adds):
# - Header-driven section slicing (data/string/map/end + pads)
# - Data Map decoding (8-byte records) -> determines which pointer fields are present
# - AMS2-correct pointer locations (incl. clutches, tyre at 0x088, push-to-pass at 0x0F0, etc.)
# - String editor with SAFE resize (existing behavior)
# - Scalar editor (in-place floats) (existing behavior)
# - Hex viewer shows entire file + 00..0F header row (existing behavior)
#
# NEW (implements SR-2/SR-3/SR-4/SR-5 + supporting SR-6..SR-9):
# - MODULES manager: shows PRESENT + MISSING modules in the tree (for all known MAP_PTR_DEFS)
# - Add missing module:
#     - inserts Data Map record (8-byte)
#     - inserts module filename string
#     - writes pointer in DATA
#     - updates header lengths (string_len/map_len)
#     - compacts module string table (no orphan module strings)
# - Remove present module:
#     - removes Data Map record (8-byte)
#     - removes its module filename string
#     - zeros pointer in DATA
#     - updates header lengths
#     - compacts module string table (no orphan module strings)
# - Canonical ordering for module strings + map records: ascending map_code
# - Validation after structural edits:
#     - pointers point to valid NUL-terminated strings within string section
#
# Notes:
# - Strings are latin-1 (byte-preserving)
# - Structural add/remove WILL change file size (by design)
# - Float edits remain strictly in-place (no size change)

from __future__ import annotations

import struct
from dataclasses import dataclass
from typing import Dict, List, Optional, Tuple, Set

import tkinter as tk
from tkinter import ttk, filedialog, messagebox
from tkinter import simpledialog

# ----------------------------
# DPI fix (Windows)
# ----------------------------
try:
    import ctypes
    ctypes.windll.shcore.SetProcessDpiAwareness(1)
except Exception:
    pass

# ----------------------------
# Helpers
# ----------------------------
def u32(blob: bytes, off: int) -> int:
    return struct.unpack_from("<I", blob, off)[0]

def f32(blob: bytes, off: int) -> float:
    return struct.unpack_from("<f", blob, off)[0]

def write_u32(buf: bytearray, off: int, v: int) -> None:
    buf[off:off+4] = struct.pack("<I", int(v) & 0xFFFFFFFF)

def write_f32(buf: bytearray, off: int, v: float) -> None:
    buf[off:off+4] = struct.pack("<f", float(v))

def is_printable(b: int) -> bool:
    return 32 <= b <= 126

def format_hex_lines(blob: bytes, start: int, nbytes: int, bytes_per_line: int = 16) -> str:
    end = min(len(blob), start + nbytes)
    out_lines: List[str] = []

    cols = " ".join(f"{i:02X}" for i in range(bytes_per_line))
    out_lines.append(f"{'':8}  {cols}")

    for off in range(start, end, bytes_per_line):
        chunk = blob[off:off+bytes_per_line]
        hex_part = " ".join(f"{x:02X}" for x in chunk)
        hex_part = hex_part.ljust(bytes_per_line * 3 - 1)
        ascii_part = "".join(chr(x) if is_printable(x) else "." for x in chunk)
        out_lines.append(f"{off:08X}  {hex_part}  |{ascii_part}|")

    return "\n".join(out_lines) + ("\n" if out_lines else "")

def clamp(n: int, lo: int, hi: int) -> int:
    return max(lo, min(hi, n))

def to_hex(off: int) -> str:
    return f"0x{off:08X}"

def fmt_float_no_sci(v: float, dp: int = 9) -> str:
    """
    Format float without scientific notation.
    dp = max decimal places; trims trailing zeros/dot.
    """
    s = f"{v:.{dp}f}"
    s = s.rstrip("0").rstrip(".")
    return s if s else "0"

def safe_decode_latin1(b: bytes) -> str:
    return b.decode("latin-1", errors="replace")

# ----------------------------
# VDFM Header
# ----------------------------
@dataclass
class VdfmHeader:
    data_len: int
    data_pad: int
    string_len: int
    string_pad: int
    map_len: int
    map_pad: int
    end_len: int
    end_pad: int

    @classmethod
    def parse(cls, blob: bytes) -> "VdfmHeader":
        return cls(
            data_len   = u32(blob, 0x010),
            data_pad   = blob[0x015],
            string_len = u32(blob, 0x018),
            string_pad = blob[0x01D],
            map_len    = u32(blob, 0x020),
            map_pad    = blob[0x025],
            end_len    = u32(blob, 0x028),
            end_pad    = blob[0x02D],
        )

    def write_back(self, buf: bytearray) -> None:
        write_u32(buf, 0x010, self.data_len)
        buf[0x015] = self.data_pad & 0xFF
        write_u32(buf, 0x018, self.string_len)
        buf[0x01D] = self.string_pad & 0xFF
        write_u32(buf, 0x020, self.map_len)
        buf[0x025] = self.map_pad & 0xFF
        write_u32(buf, 0x028, self.end_len)
        buf[0x02D] = self.end_pad & 0xFF

# ----------------------------
# Data Map -> pointer fields (AMS2-correct)
# ----------------------------
@dataclass(frozen=True)
class VdfmMapPtrDef:
    map_code: int
    data_offset: int      # absolute file offset where u32 pointer lives
    name: str

MAP_PTR_DEFS: Dict[int, VdfmMapPtrDef] = {
    0x08: VdfmMapPtrDef(0x08, 0x038, "Chassis filename (*.CDFBIN)"),
    0x18: VdfmMapPtrDef(0x18, 0x048, "Engine filename (*.EDFBIN)"),
    0x20: VdfmMapPtrDef(0x20, 0x050, "Clutches filename (*.CBFBIN)"),
    0x28: VdfmMapPtrDef(0x28, 0x058, "Turbo filename (*.TBFBIN)"),
    0x38: VdfmMapPtrDef(0x38, 0x068, "Failure model filename (*.GDFBIN)"),
    0x40: VdfmMapPtrDef(0x40, 0x070, "Gearbox filename (*.GDFBIN)"),
    0x48: VdfmMapPtrDef(0x48, 0x078, "Suspension filename (*.SDFBIN)"),
    0x50: VdfmMapPtrDef(0x50, 0x080, "Collision filename (*.XML)"),
    0x58: VdfmMapPtrDef(0x58, 0x088, "Tyre filename (*.HDTBIN)"),
    0xB8: VdfmMapPtrDef(0xB8, 0x0E8, "KERS/DRS/Hybrid (*.BBFBIN)"),
    0xC0: VdfmMapPtrDef(0xC0, 0x0F0, "Push-to-pass filename (string)"),
}

def parse_data_map_offsets(map_bytes: bytes) -> List[int]:
    """
    Data map appears as 8-byte records:
      u32 code (little-endian), then usually 4 bytes of 0.
    """
    out: List[int] = []
    for i in range(0, len(map_bytes), 8):
        if i + 4 > len(map_bytes):
            break
        code = struct.unpack_from("<I", map_bytes, i)[0]
        if code == 0:
            continue
        if 0 <= code <= 0xFFFF_FFFF:
            out.append(code)
    return out

def build_data_map_bytes(codes: List[int]) -> bytes:
    # Canonical: unique + sorted by code, 8 bytes each.
    uniq = sorted(set(codes))
    out = bytearray()
    for c in uniq:
        out += struct.pack("<I", c)
        out += b"\x00\x00\x00\x00"
    return bytes(out)

# ----------------------------
# Scalar fields (in-place float edits)
# ----------------------------
@dataclass(frozen=True)
class VdfmScalarField:
    name: str
    abs_off: int
    scalar_type: str
    notes: str = ""

VDFM_FLOAT_FIELDS: List[VdfmScalarField] = [
    VdfmScalarField("FL Wheel/Tyre lateral offset (m)",  0x088, "f32"),
    VdfmScalarField("FL Wheel/Tyre vertical offset (m)", 0x08C, "f32"),
    VdfmScalarField("FL Wheel/Tyre fore/aft offset (m)", 0x090, "f32"),

    VdfmScalarField("FR Wheel/Tyre lateral offset (m)",  0x094, "f32"),
    VdfmScalarField("FR Wheel/Tyre vertical offset (m)", 0x098, "f32"),
    VdfmScalarField("FR Wheel/Tyre fore/aft offset (m)", 0x09C, "f32"),

    VdfmScalarField("RL Wheel/Tyre lateral offset (m)",  0x0A0, "f32"),
    VdfmScalarField("RL Wheel/Tyre vertical offset (m)", 0x0A4, "f32"),
    VdfmScalarField("RL Wheel/Tyre fore/aft offset (m)", 0x0A8, "f32"),

    VdfmScalarField("RR Wheel/Tyre lateral offset (m)",  0x0AC, "f32"),
    VdfmScalarField("RR Wheel/Tyre vertical offset (m)", 0x0B0, "f32"),
    VdfmScalarField("RR Wheel/Tyre fore/aft offset (m)", 0x0B4, "f32"),

    VdfmScalarField("FL Tyre width (m)",  0x0B8, "f32"),
    VdfmScalarField("FL Tyre height (m)", 0x0BC, "f32"),
    VdfmScalarField("FR Tyre width (m)",  0x0C0, "f32"),
    VdfmScalarField("FR Tyre height (m)", 0x0C4, "f32"),
    VdfmScalarField("RL Tyre width (m)",  0x0C8, "f32"),
    VdfmScalarField("RL Tyre height (m)", 0x0CC, "f32"),
    VdfmScalarField("RR Tyre width (m)",  0x0D0, "f32"),
    VdfmScalarField("RR Tyre height (m)", 0x0D4, "f32"),

    VdfmScalarField("Brake Disc Glow Min", 0x138, "f32"),
    VdfmScalarField("Brake Disc Glow Max", 0x13C, "f32"),

    VdfmScalarField("Backfire: left exhaust frequency",  0x1CC, "f32", "Typically 0.1..0.5"),
    VdfmScalarField("Backfire: right exhaust frequency", 0x1D0, "f32", "Typically 0.1..0.5"),
]

# ----------------------------
# String Section parsing
# ----------------------------
@dataclass
class StringEntry:
    rel_off: int
    text: str
    raw: bytes  # includes trailing NUL

def parse_string_section(sec: bytes) -> List[StringEntry]:
    entries: List[StringEntry] = []
    i = 0
    n = len(sec)

    while i < n:
        j = sec.find(b"\x00", i)
        if j == -1:
            raw = sec[i:]
            txt = safe_decode_latin1(raw)
            entries.append(StringEntry(rel_off=i, text=txt, raw=raw))
            break

        raw = sec[i:j+1]
        payload = raw[:-1]

        # Stop if empty string and rest are all zeros (padding)
        if len(payload) == 0 and all(b == 0 for b in sec[j+1:]):
            break

        txt = safe_decode_latin1(payload)
        entries.append(StringEntry(rel_off=i, text=txt, raw=raw))
        i = j + 1

    return entries

def build_string_section(entries: List[StringEntry]) -> bytes:
    return b"".join(e.raw for e in entries)

# ----------------------------
# Section slicing (header-driven)
# ----------------------------
@dataclass
class VdfmSections:
    header_bytes: bytes
    data_bytes: bytes
    data_pad: bytes
    string_bytes: bytes
    string_pad: bytes
    map_bytes: bytes
    map_pad: bytes
    end_bytes: bytes
    end_pad: bytes
    trailing: bytes

def validate_header_and_sections(blob: bytes) -> Tuple[bool, List[str]]:
    """
    Single source of truth for VDFM structural validation:
    - header fields readable
    - section lengths/pads do not run past EOF
    - map_len is multiple of 8 (data map records)
    """
    problems: List[str] = []

    if len(blob) < 0x30:
        return False, [f"File too small ({len(blob)} bytes). Needs at least 0x30 bytes for header."]

    try:
        hdr = VdfmHeader.parse(blob)
    except Exception as e:
        return False, [f"Header parse failed: {e}"]

    base = 0x30
    total = (
        base +
        hdr.data_len + hdr.data_pad +
        hdr.string_len + hdr.string_pad +
        hdr.map_len + hdr.map_pad +
        hdr.end_len + hdr.end_pad
    )

    if total > len(blob):
        problems.append(
            "Header section sizes exceed file length:\n"
            f"- computed end = {to_hex(total)} ({total} bytes)\n"
            f"- file length  = {to_hex(len(blob))} ({len(blob)} bytes)"
        )

    # Very cheap sanity checks (safe + useful)
    if hdr.map_len % 8 != 0:
        problems.append(f"Map length not multiple of 8: map_len={hdr.map_len} (expected 8-byte records).")

    # Pads are stored as u8 already; nothing to do, but keep a guard anyway.
    for name, v in (("data_pad", hdr.data_pad), ("string_pad", hdr.string_pad), ("map_pad", hdr.map_pad), ("end_pad", hdr.end_pad)):
        if not (0 <= v <= 255):
            problems.append(f"{name} out of range: {v}")

    return (len(problems) == 0), problems


def slice_sections(blob: bytes, hdr: VdfmHeader) -> VdfmSections:
    base = 0x030
    header_bytes = blob[:base]

    p = base
    data_bytes = blob[p:p+hdr.data_len]; p += hdr.data_len
    data_pad = blob[p:p+hdr.data_pad]; p += hdr.data_pad

    string_bytes = blob[p:p+hdr.string_len]; p += hdr.string_len
    string_pad = blob[p:p+hdr.string_pad]; p += hdr.string_pad

    map_bytes = blob[p:p+hdr.map_len]; p += hdr.map_len
    map_pad = blob[p:p+hdr.map_pad]; p += hdr.map_pad

    end_bytes = blob[p:p+hdr.end_len]; p += hdr.end_len
    end_pad = blob[p:p+hdr.end_pad]; p += hdr.end_pad

    trailing = blob[p:] if p < len(blob) else b""

    return VdfmSections(
        header_bytes=header_bytes,
        data_bytes=data_bytes,
        data_pad=data_pad,
        string_bytes=string_bytes,
        string_pad=string_pad,
        map_bytes=map_bytes,
        map_pad=map_pad,
        end_bytes=end_bytes,
        end_pad=end_pad,
        trailing=trailing,
    )

def rebuild_blob(hdr: VdfmHeader, sec: VdfmSections) -> bytes:
    hb = bytearray(sec.header_bytes)
    hdr.write_back(hb)
    return b"".join([
        bytes(hb),
        sec.data_bytes,
        sec.data_pad,
        sec.string_bytes,
        sec.string_pad,
        sec.map_bytes,
        sec.map_pad,
        sec.end_bytes,
        sec.end_pad,
        sec.trailing,
    ])

# ----------------------------
# Structural edit helpers (Add/Remove module)
# ----------------------------
def read_cstr_from_string_section(string_bytes: bytes, rel_off: int) -> str:
    if rel_off < 0 or rel_off >= len(string_bytes):
        return ""
    end = string_bytes.find(b"\x00", rel_off)
    if end == -1:
        end = len(string_bytes)
    return safe_decode_latin1(string_bytes[rel_off:end])

def validate_pointers(string_bytes: bytes, rel_offsets: Dict[int, int]) -> Tuple[bool, List[str]]:
    """
    Ensure each rel offset points to a valid NUL-terminated string start.
    """
    problems: List[str] = []
    for code, rel in rel_offsets.items():
        if rel < 0 or rel >= len(string_bytes):
            problems.append(f"0x{code:02X}: rel {rel} out of bounds (string_len={len(string_bytes)})")
            continue
        # must find a NUL terminator after rel
        end = string_bytes.find(b"\x00", rel)
        if end == -1:
            problems.append(f"0x{code:02X}: rel {rel} has no NUL terminator")
            continue
        # rel should be at start of a string: either rel==0 or prev byte is NUL
        if rel != 0 and string_bytes[rel-1] != 0x00:
            problems.append(f"0x{code:02X}: rel {rel} is not aligned to a string start (prev byte != NUL)")
    return (len(problems) == 0), problems

def canonical_codes_present(map_codes: List[int]) -> List[int]:
    return sorted(set(map_codes))

def find_existing_string_rel(string_bytes: bytes, target: str) -> Optional[int]:
    """
    Return rel_off of the first exact-match string entry, else None.
    Exact-match = bytes(target) followed by NUL, and aligned to a string start.
    """
    try:
        needle = target.encode("latin-1", errors="strict") + b"\x00"
    except Exception:
        return None

    i = 0
    n = len(string_bytes)
    while i < n:
        j = string_bytes.find(b"\x00", i)
        if j == -1:
            break
        raw = string_bytes[i:j+1]
        if raw == needle:
            return i
        # stop on padding region (empty string followed by all zeros)
        if raw == b"\x00" and all(b == 0 for b in string_bytes[j+1:]):
            break
        i = j + 1
    return None

def append_string(string_bytes: bytes, text: str) -> Tuple[bytes, int]:
    """
    Append a new NUL-terminated string to the end of the string section.
    Returns (new_string_bytes, rel_off_of_new_string).
    """
    payload = text.encode("latin-1", errors="strict")
    if b"\x00" in payload:
        raise ValueError("Filename cannot contain NUL.")
    rel = len(string_bytes)
    return (string_bytes + payload + b"\x00", rel)


# ----------------------------
# App
# ----------------------------
class VdfmEditorApp(tk.Tk):
    def __init__(self):
        super().__init__()
        self.title("VDFM Editor – Modules Add/Remove + Strings + Floats")
        self.geometry("1500x900")

        # data
        self.file_path: Optional[str] = None
        self.original_blob: Optional[bytes] = None
        self.working_blob: Optional[bytes] = None
        self.hdr: Optional[VdfmHeader] = None
        self.sec: Optional[VdfmSections] = None

        # parsed
        self.string_entries: List[StringEntry] = []
        self.map_codes: List[int] = []
        self.active_ptr_defs: List[VdfmMapPtrDef] = []
        self.ptr_values: Dict[int, int] = {}  # abs_off -> u32 pointer (rel string off)

        # module view
        self.module_codes_present: List[int] = []
        self.unknown_codes_present: List[int] = []
        self.module_filename_by_code: Dict[int, str] = {}  # from pointers + string section

        # selection state
        self._selected_string_index: Optional[int] = None
        self._selected_float_off: Optional[int] = None
        self._selected_module_code: Optional[int] = None

        self._build_ui()

    # ----------------------------
    # UI
    # ----------------------------
    def _build_ui(self):
        style = ttk.Style(self)
        style.configure("Treeview", rowheight=34)

        paned = ttk.Panedwindow(self, orient="horizontal")
        paned.pack(fill="both", expand=True)

        left = ttk.Frame(paned, padding=8)
        right = ttk.Frame(paned, padding=8)
        paned.add(left, weight=3)
        paned.add(right, weight=2)

        # Menu
        menubar = tk.Menu(self)
        fm = tk.Menu(menubar, tearoff=0)
        fm.add_command(label="Open…", command=self.open_file)
        fm.add_command(label="Save", command=self.save_file, state="disabled")
        fm.add_command(label="Save As…", command=self.save_as, state="disabled")
        fm.add_separator()
        fm.add_command(label="Exit", command=self.destroy)
        menubar.add_cascade(label="File", menu=fm)
        self.file_menu = fm
        self.config(menu=menubar)

        # Left: Tree + hex
        self.status_var = tk.StringVar(value="Open a .vdfm file to begin.")
        ttk.Label(left, textvariable=self.status_var).pack(fill="x", pady=(0, 6))

        self.tree = ttk.Treeview(left, columns=("offset", "value", "type"), show="tree headings", selectmode="browse")
        self.tree.heading("#0", text="Item")
        self.tree.heading("offset", text="Offset")
        self.tree.heading("value", text="Value")
        self.tree.heading("type", text="Type")
        self.tree.column("#0", width=520)
        self.tree.column("offset", width=160, anchor="e")
        self.tree.column("value", width=420)
        self.tree.column("type", width=160)

        ysb = ttk.Scrollbar(left, orient="vertical", command=self.tree.yview)
        self.tree.configure(yscrollcommand=ysb.set)
        self.tree.pack(side="left", fill="both", expand=True)
        ysb.pack(side="right", fill="y")

        self.tree.bind("<<TreeviewSelect>>", self._on_select)

        # Hex viewer
        hex_frame = ttk.LabelFrame(left, text="Hex view (read-only)")
        hex_frame.pack(fill="both", expand=False, pady=(8, 0))

        hex_top = ttk.Frame(hex_frame)
        hex_top.pack(fill="x", padx=6, pady=6)

        ttk.Label(hex_top, text="Jump to offset (hex):").pack(side="left")
        self.hex_jump_var = tk.StringVar(value="0x00000000")
        ttk.Entry(hex_top, textvariable=self.hex_jump_var, width=14).pack(side="left", padx=6)
        ttk.Button(hex_top, text="Go", command=self.hex_jump).pack(side="left")

        self.hex_info_var = tk.StringVar(value="")
        ttk.Label(hex_top, textvariable=self.hex_info_var).pack(side="right")

        self.hex_text = tk.Text(hex_frame, height=40, wrap="none", font=("Consolas", 10))
        self.hex_text.configure(state="disabled")
        self.hex_text.pack(fill="both", expand=True, padx=6, pady=(0, 6))

        # Right: editors
        ttk.Label(right, text="Editors", font=("Segoe UI", 12, "bold")).pack(anchor="w")

        self.sel_var = tk.StringVar(value="(select an item in the tree)")
        ttk.Label(right, textvariable=self.sel_var, wraplength=560).pack(anchor="w", pady=(6, 10))

        nb = ttk.Notebook(right)
        nb.pack(fill="both", expand=True)

        # --- Modules tab ---
        self.tab_modules = ttk.Frame(nb, padding=8)
        nb.add(self.tab_modules, text="Modules")

        ttk.Label(self.tab_modules, text="Selected module:").pack(anchor="w")
        self.module_sel_var = tk.StringVar(value="(none)")
        ttk.Label(self.tab_modules, textvariable=self.module_sel_var, font=("Segoe UI", 11, "bold")).pack(anchor="w", pady=(4, 10))

        mbtns = ttk.Frame(self.tab_modules)
        mbtns.pack(fill="x", pady=(0, 10))

        self.btn_add_module = ttk.Button(mbtns, text="Add / Insert Module", command=self.add_module, state="disabled")
        self.btn_add_module.pack(side="left")

        self.btn_remove_module = ttk.Button(mbtns, text="Delete / Remove Module", command=self.remove_module, state="disabled")
        self.btn_remove_module.pack(side="left", padx=8)

        self.module_warn_var = tk.StringVar(value="")
        ttk.Label(self.tab_modules, textvariable=self.module_warn_var, foreground="#a33", wraplength=520).pack(anchor="w")

        # --- String editor tab ---
        self.tab_strings = ttk.Frame(nb, padding=8)
        nb.add(self.tab_strings, text="Strings")

        ttk.Label(self.tab_strings, text="Current text:").pack(anchor="w")
        self.current_text = tk.Text(self.tab_strings, height=4, wrap="word")
        self.current_text.configure(state="disabled")
        self.current_text.pack(fill="x", pady=(4, 10))

        ttk.Label(self.tab_strings, text="New text (ASCII/latin-1):").pack(anchor="w")
        self.new_text_var = tk.StringVar(value="")
        ttk.Entry(self.tab_strings, textvariable=self.new_text_var).pack(fill="x", pady=(4, 10))

        btns = ttk.Frame(self.tab_strings)
        btns.pack(fill="x", pady=(0, 12))
        self.apply_string_btn = ttk.Button(btns, text="Apply String Edit (safe resize)", command=self.apply_string_edit, state="disabled")
        self.apply_string_btn.pack(side="left")

        self.revert_btn = ttk.Button(btns, text="Revert to Opened File", command=self.revert_all, state="disabled")
        self.revert_btn.pack(side="left", padx=8)

        self.string_warn_var = tk.StringVar(value="")
        ttk.Label(self.tab_strings, textvariable=self.string_warn_var, foreground="#a33", wraplength=520).pack(anchor="w", pady=(6, 0))

        # --- Float editor tab ---
        self.tab_floats = ttk.Frame(nb, padding=8)
        nb.add(self.tab_floats, text="Floats")

        ttk.Label(self.tab_floats, text="Current value:").pack(anchor="w")
        self.float_current_var = tk.StringVar(value="(none)")
        ttk.Label(self.tab_floats, textvariable=self.float_current_var, font=("Segoe UI", 11, "bold")).pack(anchor="w", pady=(4, 10))

        ttk.Label(self.tab_floats, text="New value:").pack(anchor="w")
        self.float_new_var = tk.StringVar(value="")
        ttk.Entry(self.tab_floats, textvariable=self.float_new_var).pack(fill="x", pady=(4, 10))

        fbtns = ttk.Frame(self.tab_floats)
        fbtns.pack(fill="x")
        self.apply_float_btn = ttk.Button(fbtns, text="Apply Float Edit (in-place)", command=self.apply_float_edit, state="disabled")
        self.apply_float_btn.pack(side="left")

        self.float_note_var = tk.StringVar(value="")
        ttk.Label(self.tab_floats, textvariable=self.float_note_var, wraplength=520).pack(anchor="w", pady=(10, 0))

        ttk.Separator(right).pack(fill="x", pady=10)

        self.hdr_text = tk.Text(right, height=14, wrap="word")
        self.hdr_text.configure(state="disabled")
        self.hdr_text.pack(fill="both", expand=False)

    # ----------------------------
    # File ops
    # ----------------------------
    def open_file(self):
        path = filedialog.askopenfilename(
            title="Open VDFM file",
            filetypes=[("VDFM files", "*.vdfm"), ("All files", "*.*")]
        )
        if not path:
            return
        try:
            with open(path, "rb") as f:
                blob = f.read()

        except Exception as e:
            messagebox.showerror("Open failed", str(e))
            return
        
        ok, probs = validate_header_and_sections(blob)
        if not ok:
            messagebox.showerror("Open failed (invalid VDFM)", "\n\n".join(probs))
            return

        self.file_path = path
        self.original_blob = blob
        self.working_blob = blob
        self._parse_all()

        self.file_menu.entryconfig("Save", state="normal")
        self.file_menu.entryconfig("Save As…", state="normal")
        self.revert_btn.configure(state="normal")

    def save_file(self):
        if not self.file_path or self.working_blob is None:
            return
        ok, probs = validate_header_and_sections(self.working_blob)
        if not ok:
            messagebox.showerror("Save blocked (invalid VDFM)", "\n\n".join(probs))
            return

        try:
            with open(self.file_path, "wb") as f:
                f.write(self.working_blob)
        except Exception as e:
            messagebox.showerror("Save failed", str(e))
            return
        messagebox.showinfo("Saved", "File saved successfully.")

    def save_as(self):
        if self.working_blob is None:
            return
        ok, probs = validate_header_and_sections(self.working_blob)
        if not ok:
            messagebox.showerror("Save As blocked (invalid VDFM)", "\n\n".join(probs))
            return

        path = filedialog.asksaveasfilename(
            title="Save As",
            defaultextension=".vdfm",
            filetypes=[("VDFM files", "*.vdfm"), ("All files", "*.*")]
        )
        if not path:
            return
        try:
            with open(path, "wb") as f:
                f.write(self.working_blob)
        except Exception as e:
            messagebox.showerror("Save As failed", str(e))
            return
        self.file_path = path
        messagebox.showinfo("Saved", "File saved successfully.")

    def revert_all(self):
        if self.original_blob is None:
            return
        if not messagebox.askyesno("Revert", "Revert ALL changes back to the file as opened?"):
            return
        self.working_blob = self.original_blob
        self._parse_all()

    # ----------------------------
    # Parsing / view rebuild
    # ----------------------------
    def _parse_all(self):
        
        if self.working_blob is None:
            return
        ok, probs = validate_header_and_sections(self.working_blob)
        if not ok:
            messagebox.showerror("Validation failed", "\n\n".join(probs))
            return
        try:
            self.hdr = VdfmHeader.parse(self.working_blob)
            self.sec = slice_sections(self.working_blob, self.hdr)

            # Strings
            self.string_entries = parse_string_section(self.sec.string_bytes)

            # Data map -> which pointer fields exist
            self.map_codes = parse_data_map_offsets(self.sec.map_bytes)
            self.module_codes_present = canonical_codes_present(self.map_codes)
            # Unknown codes present in this file (not mapped in MAP_PTR_DEFS)
            self.unknown_codes_present = sorted(set(c for c in self.module_codes_present if c not in MAP_PTR_DEFS))

            # Active pointer defs (only those present per map)
            self.active_ptr_defs = [MAP_PTR_DEFS[c] for c in self.module_codes_present if c in MAP_PTR_DEFS]

            # Read pointers
            self.ptr_values = self._read_pointer_fields_dynamic(self.active_ptr_defs)

            # Derive module filenames (from pointers into string section)            
            self.module_filename_by_code = {}
            for c in self.module_codes_present:
                d = MAP_PTR_DEFS.get(c)
                if not d:
                    continue
                if d.data_offset + 4 > len(self.working_blob):
                    continue
                ptr = u32(self.working_blob, d.data_offset)
                self.module_filename_by_code[c] = read_cstr_from_string_section(self.sec.string_bytes, ptr)

        except Exception as e:
            messagebox.showerror("Parse failed", str(e))
            return

        self._populate_tree()
        self._render_header_text()

        self.status_var.set(
            f"Loaded: {self.file_path or '(unsaved)'}  |  "
            f"Strings: {len(self.string_entries)}  |  "
            f"Map codes: {len(self.map_codes)}  |  "
            f"File size: {len(self.working_blob)} bytes"
        )
        self.hex_info_var.set(f"Size {len(self.working_blob)} bytes")
        self._set_hex_view(0)

        # Reset selection state
        self._selected_string_index = None
        self._selected_float_off = None
        self._selected_module_code = None

        self.sel_var.set("(select an item in the tree)")
        self.module_sel_var.set("(none)")
        self.module_warn_var.set("")
        self.btn_add_module.configure(state="disabled")
        self.btn_remove_module.configure(state="disabled")

        self._set_current_text("")
        self.new_text_var.set("")
        self.apply_string_btn.configure(state="disabled")
        self.string_warn_var.set("")

        self.float_current_var.set("(none)")
        self.float_new_var.set("")
        self.float_note_var.set("")
        self.apply_float_btn.configure(state="disabled")

    def _read_pointer_fields_dynamic(self, defs: List[VdfmMapPtrDef]) -> Dict[int, int]:
        out: Dict[int, int] = {}
        assert self.working_blob is not None
        for d in defs:
            if d.data_offset + 4 <= len(self.working_blob):
                out[d.data_offset] = u32(self.working_blob, d.data_offset)
        return out

    def _populate_tree(self):
        self.tree.delete(*self.tree.get_children())
        assert self.hdr is not None
        assert self.sec is not None

        # Header
        hid = self.tree.insert("", "end", text="HEADER", open=True)
        h = self.hdr
        self.tree.insert(hid, "end", text="Data length",   values=(to_hex(0x010), h.data_len, "u32"))
        self.tree.insert(hid, "end", text="Data pad",      values=(to_hex(0x015), h.data_pad, "u8"))
        self.tree.insert(hid, "end", text="String length", values=(to_hex(0x018), h.string_len, "u32"))
        self.tree.insert(hid, "end", text="String pad",    values=(to_hex(0x01D), h.string_pad, "u8"))
        self.tree.insert(hid, "end", text="Map length",    values=(to_hex(0x020), h.map_len, "u32"))
        self.tree.insert(hid, "end", text="Map pad",       values=(to_hex(0x025), h.map_pad, "u8"))
        self.tree.insert(hid, "end", text="End length",    values=(to_hex(0x028), h.end_len, "u32"))
        self.tree.insert(hid, "end", text="End pad",       values=(to_hex(0x02D), h.end_pad, "u8"))

        # Modules (present + missing)
        mid2 = self.tree.insert("", "end", text="MODULES (present + missing)", open=True)
        for code in sorted(MAP_PTR_DEFS.keys()):
            d = MAP_PTR_DEFS[code]
            present = code in set(self.module_codes_present)
            status = "PRESENT" if present else "MISSING"
            filename = self.module_filename_by_code.get(code, "")
            val = filename if (present and filename) else ("(missing)" if not present else "(pointer=0)")
            self.tree.insert(
                mid2, "end",
                text=f"{d.name}",
                values=(f"0x{code:02X}", val, "module")
            )

        # Unknown modules present (map codes not in MAP_PTR_DEFS)
        if getattr(self, "unknown_codes_present", []):
            umid = self.tree.insert(mid2, "end", text="UNKNOWN MODULE CODES (present)", open=True)
            for code in self.unknown_codes_present:
                # We don't know the pointer field, only that the map record exists.
                self.tree.insert(
                    umid, "end",
                    text=f"Unknown module code 0x{code:02X}",
                    values=(f"0x{code:02X}", "(unknown mapping)", "module_unknown")
                )

        # Data map decoded (raw)
        mid = self.tree.insert("", "end", text="DATA MAP OFFSETS (decoded raw)", open=True)
        for c in self.map_codes:
            meaning = MAP_PTR_DEFS[c].name if c in MAP_PTR_DEFS else "(unknown/unmapped)"
            self.tree.insert(mid, "end", text=meaning, values=(f"0x{c:02X}", "", "map_code"))

        # Pointer fields (present per map)
        pid = self.tree.insert("", "end", text="STRING POINTER FIELDS (present per Data Map)", open=True)
        for d in self.active_ptr_defs:
            ptr = self.ptr_values.get(d.data_offset, 0)
            self.tree.insert(pid, "end", text=d.name, values=(to_hex(d.data_offset), ptr, "ptr_u32"))

        # Float fields (in-place)
        fid = self.tree.insert("", "end", text="FLOAT FIELDS (in-place)", open=True)
        by_group: Dict[str, List[VdfmScalarField]] = {
            "Wheel/Tyre track offsets": [],
            "Tyre dimensions": [],
            "Brake disc glow": [],
            "Backfire frequency": [],
        }
        for f in VDFM_FLOAT_FIELDS:
            if 0x088 <= f.abs_off <= 0x0B4:
                by_group["Wheel/Tyre track offsets"].append(f)
            elif 0x0B8 <= f.abs_off <= 0x0D4:
                by_group["Tyre dimensions"].append(f)
            elif f.abs_off in (0x138, 0x13C):
                by_group["Brake disc glow"].append(f)
            elif f.abs_off in (0x1CC, 0x1D0):
                by_group["Backfire frequency"].append(f)
            else:
                by_group.setdefault("Other", []).append(f)

        for gname, items in by_group.items():
            if not items:
                continue
            gid = self.tree.insert(fid, "end", text=gname, open=True)
            for sf in items:
                val = ""
                if self.working_blob and sf.abs_off + 4 <= len(self.working_blob):
                    try:
                        val = fmt_float_no_sci(f32(self.working_blob, sf.abs_off), dp=9)
                    except Exception:
                        val = "(read error)"
                self.tree.insert(gid, "end", text=sf.name, values=(to_hex(sf.abs_off), val, "f32"))

        # String entries (raw)
        sid = self.tree.insert("", "end", text="STRING DATA ENTRIES (raw)", open=True)
        for idx, e in enumerate(self.string_entries):
            label = f"[{idx}] @{to_hex(e.rel_off)}  {e.text}"
            self.tree.insert(sid, "end", text=label, values=(to_hex(self._string_abs_off(e.rel_off)), e.text, "string"))

    def _render_header_text(self):
        assert self.hdr and self.sec
        h = self.hdr
        s = self.sec

        layout = []
        layout.append("Section layout (header-driven):\n\n")
        layout.append("HEADER:      0x00000000 .. 0x0000002F\n")
        p = 0x30
        layout.append(f"DATA:        {to_hex(p)} .. {to_hex(p + h.data_len - 1)}  (len={h.data_len})\n")
        p += h.data_len
        layout.append(f"DATA PAD:    {to_hex(p)} .. {to_hex(p + h.data_pad - 1)}  (pad={h.data_pad})\n")
        p += h.data_pad
        layout.append(f"STRINGS:     {to_hex(p)} .. {to_hex(p + h.string_len - 1)}  (len={h.string_len})\n")
        p += h.string_len
        layout.append(f"STRING PAD:  {to_hex(p)} .. {to_hex(p + h.string_pad - 1)}  (pad={h.string_pad})\n")
        p += h.string_pad
        layout.append(f"DATA MAP:    {to_hex(p)} .. {to_hex(p + h.map_len - 1)}  (len={h.map_len})\n")
        p += h.map_len
        layout.append(f"MAP PAD:     {to_hex(p)} .. {to_hex(p + h.map_pad - 1)}  (pad={h.map_pad})\n")
        p += h.map_pad
        layout.append(f"END:         {to_hex(p)} .. {to_hex(p + h.end_len - 1)}  (len={h.end_len})\n")
        p += h.end_len
        layout.append(f"END PAD:     {to_hex(p)} .. {to_hex(p + h.end_pad - 1)}  (pad={h.end_pad})\n")
        p += h.end_pad
        if s.trailing:
            layout.append(f"TRAILING:    {to_hex(p)} .. {to_hex(p + len(s.trailing) - 1)}  (len={len(s.trailing)})\n")

        self.hdr_text.configure(state="normal")
        self.hdr_text.delete("1.0", "end")
        self.hdr_text.insert("1.0", "".join(layout))
        self.hdr_text.configure(state="disabled")

    # ----------------------------
    # Selection handling
    # ----------------------------
    def _on_select(self, _evt):
        if self.working_blob is None:
            return

        sel = self.tree.selection()
        if not sel:
            return

        iid = sel[0]
        item_text = self.tree.item(iid, "text")
        vals = self.tree.item(iid, "values")

        # Reset selection state
        self._selected_string_index = None
        self._selected_float_off = None
        self._selected_module_code = None

        self.apply_string_btn.configure(state="disabled")
        self.apply_float_btn.configure(state="disabled")
        self.string_warn_var.set("")
        self.float_note_var.set("")

        self.btn_add_module.configure(state="disabled")
        self.btn_remove_module.configure(state="disabled")
        self.module_warn_var.set("")
        self.module_sel_var.set("(none)")

        if not vals:
            return

        typ = vals[2] if len(vals) >= 3 else ""

        # MODULE selected
        if typ == "module":
            try:
                code = int(vals[0], 16)
            except Exception:
                return
            self._selected_module_code = code
            d = MAP_PTR_DEFS.get(code)
            present = code in set(self.module_codes_present)
            fn = self.module_filename_by_code.get(code, "")
            self.module_sel_var.set(f"{d.name if d else 'Module'}  (code 0x{code:02X})  [{ 'PRESENT' if present else 'MISSING' }]")
            if present:
                self.module_sel_var.set(self.module_sel_var.get() + (f"\nCurrent: {fn}" if fn else "\nCurrent: (pointer=0)"))
                self.btn_remove_module.configure(state="normal")
                self.btn_add_module.configure(state="disabled")
            else:
                self.module_sel_var.set(self.module_sel_var.get() + "\nCurrent: (missing)")
                self.btn_add_module.configure(state="normal")
                self.btn_remove_module.configure(state="disabled")
            self.sel_var.set(f"Module: 0x{code:02X}")
            return
        
        # UNKNOWN MODULE selected (present in map, but unmapped)
        if typ == "module_unknown":
            try:
                code = int(vals[0], 16)
            except Exception:
                return

            self._selected_module_code = code
            self.module_sel_var.set(f"Unknown module (code 0x{code:02X})  [PRESENT]\nCurrent: (no known pointer mapping)")
            self.sel_var.set(f"Unknown Module: 0x{code:02X}")

            # Allow removal (safe), but adding via filename is not supported for unknowns
            self.btn_remove_module.configure(state="normal")
            self.btn_add_module.configure(state="disabled")

            self.module_warn_var.set(
                "This code exists in the Data Map, but the editor does not know its pointer field.\n"
                "You can remove the map record safely, but adding/editing a filename pointer requires a mapping."
            )
            return

        # STRING entry selected
        if typ == "string":
            idx = None
            if item_text.startswith("["):
                try:
                    idx = int(item_text.split("]")[0][1:])
                except Exception:
                    idx = None
            if idx is None or idx < 0 or idx >= len(self.string_entries):
                return

            self._selected_string_index = idx
            e = self.string_entries[idx]
            self.sel_var.set(f"String entry [{idx}] rel {to_hex(e.rel_off)} (abs {to_hex(self._string_abs_off(e.rel_off))})")
            self._set_current_text(e.text)
            self.new_text_var.set(e.text)
            self.apply_string_btn.configure(state="normal")
            self._set_hex_view(self._string_abs_off(e.rel_off))
            return

        # FLOAT field selected
        if typ == "f32":
            try:
                off = int(vals[0], 16)
            except Exception:
                return
            if off + 4 > len(self.working_blob):
                return

            self._selected_float_off = off
            cur = f32(self.working_blob, off)
            shown = fmt_float_no_sci(cur, dp=9)
            self.float_current_var.set(shown)
            self.float_new_var.set(shown)

            note = ""
            for sf in VDFM_FLOAT_FIELDS:
                if sf.abs_off == off:
                    note = sf.notes or ""
                    self.sel_var.set(f"Float field: {sf.name} @ {to_hex(off)}")
                    break
            if note:
                self.float_note_var.set(note)

            self.apply_float_btn.configure(state="normal")
            self._set_hex_view(off)
            return

        # Pointer field: jump
        if typ in ("ptr_u32", "u32", "u8", "map_code"):
            try:
                off_str = vals[0]
                off = int(off_str, 16)
                self._set_hex_view(off)
                self.sel_var.set(f"{item_text} @ {off_str}")
            except Exception:
                pass
            return

        # fallback jump
        try:
            off_str = vals[0]
            off = int(off_str, 16)
            self._set_hex_view(off)
        except Exception:
            pass

    def _set_current_text(self, s: str):
        self.current_text.configure(state="normal")
        self.current_text.delete("1.0", "end")
        self.current_text.insert("1.0", s)
        self.current_text.configure(state="disabled")

    # ----------------------------
    # Hex view
    # ----------------------------
    def _set_hex_view(self, off: int):
        if self.working_blob is None:
            return
        off = clamp(off, 0, max(0, len(self.working_blob) - 1))
        text = format_hex_lines(self.working_blob, 0, len(self.working_blob), 16)
        self.hex_text.configure(state="normal")
        self.hex_text.delete("1.0", "end")
        self.hex_text.insert("1.0", text)
        self.hex_text.configure(state="disabled")
        self.hex_jump_var.set(to_hex(off))

    def hex_jump(self):
        if self.working_blob is None:
            return
        s = self.hex_jump_var.get().strip()
        try:
            off = int(s, 16)
        except Exception:
            messagebox.showerror("Jump failed", "Enter a hex offset like 0x1D0 or 1D0.")
            return
        self._set_hex_view(off)

    # ----------------------------
    # Offsets
    # ----------------------------
    def _string_abs_off(self, rel: int) -> int:
        assert self.hdr is not None
        base = 0x30 + self.hdr.data_len + self.hdr.data_pad
        return base + rel

    # ----------------------------
    # MODULE STRUCTURAL OPS
    # ----------------------------
    def _pick_or_enter_string(self, title: str, prompt: str, initial: str = "") -> Optional[Tuple[str, str]]:
        """
        Minimal modal dialog:
        - lets user select an existing string (combobox) -> mode="existing"
        - or enter a new one -> mode="new"
        Returns (string, mode), or None if cancelled.
        """
        if self.sec is None:
            return None

        # Build list of existing strings (unique, non-empty)
        existing: List[str] = []
        seen: Set[str] = set()
        for e in self.string_entries:
            t = (e.text or "").strip()
            if not t:
                continue
            if t in seen:
                continue
            seen.add(t)
            existing.append(t)
        existing.sort()

        dlg = tk.Toplevel(self)
        dlg.title(title)
        dlg.transient(self)
        dlg.grab_set()
        dlg.resizable(False, False)

        frm = ttk.Frame(dlg, padding=12)
        frm.pack(fill="both", expand=True)

        ttk.Label(frm, text=prompt, justify="left", wraplength=520).pack(anchor="w", pady=(0, 10))

        ttk.Label(frm, text="Reuse existing string:").pack(anchor="w")
        picked_var = tk.StringVar(value="")
        cb = ttk.Combobox(frm, textvariable=picked_var, values=existing, state="readonly", width=70)
        cb.pack(fill="x", pady=(4, 10))
        if existing:
            cb.current(0)

        ttk.Label(frm, text="…or enter a new string:").pack(anchor="w")
        entered_var = tk.StringVar(value=initial or "")
        ent = ttk.Entry(frm, textvariable=entered_var, width=72)
        ent.pack(fill="x", pady=(4, 12))

        result: Dict[str, Optional[Tuple[str, str]]] = {"value": None}

        btns = ttk.Frame(frm)
        btns.pack(fill="x")

        def use_selected():
            v = (picked_var.get() or "").strip()
            if not v:
                messagebox.showerror("Select a string", "No existing string selected.", parent=dlg)
                return
            result["value"] = (v, "existing")
            dlg.destroy()

        def enter_new():
            v = (entered_var.get() or "").strip()
            if not v:
                messagebox.showerror("Enter a string", "New string cannot be empty.", parent=dlg)
                return
            result["value"] = (v, "new")
            dlg.destroy()

        def cancel():
            result["value"] = None
            dlg.destroy()

        ttk.Button(btns, text="Use Selected", command=use_selected).pack(side="left")
        ttk.Button(btns, text="Enter New", command=enter_new).pack(side="left", padx=8)
        ttk.Button(btns, text="Cancel", command=cancel).pack(side="right")

        ent.focus_set()
        dlg.wait_window()
        return result["value"]

    
    
    def add_module(self):
        """
        SR-2: Insert Data Map record + insert module string + write pointer + recalc header.
        """
        if self.working_blob is None or self.hdr is None or self.sec is None:
            return
        if self._selected_module_code is None:
            return

        code = self._selected_module_code
        d = MAP_PTR_DEFS.get(code)
        if not d:
            messagebox.showerror("Add module", f"Unknown module code 0x{code:02X}.")
            return
        if code in set(self.module_codes_present):
            messagebox.showinfo("Add module", "Module is already present.")
            return

        # Ask: reuse existing or enter new
        picked = self._pick_or_enter_string(
            title="Add Module",
            prompt=f"Choose an existing string to reuse, or enter a new filename for:\n\n{d.name}\n(code 0x{code:02X})",
            initial=""
        )
        if picked is None:
            return
        new_fn, mode = picked
        new_fn = new_fn.strip()
        if not new_fn:
            messagebox.showerror("Add module", "Filename cannot be empty.")
            return

        # Perform structural rebuild (mode controls reuse vs append)
        try:
            self._structural_rebuild(
                add_codes={code},
                remove_codes=set(),
                set_filename={code: new_fn},
                add_mode={code: mode},
            )
        except Exception as e:
            messagebox.showerror("Add module failed", str(e))
            return

        messagebox.showinfo("Added", f"Module 0x{code:02X} inserted.\nPointers + header updated.\nModule strings compacted.")
        self._parse_all()

    def remove_module(self):
        """
        Remove Data Map record. If mapped, also zero pointer.
        If unknown, only removes the map record (safe).
        """
        if self.working_blob is None or self.hdr is None or self.sec is None:
            return
        if self._selected_module_code is None:
            return

        code = self._selected_module_code
        present = code in set(self.module_codes_present)
        if not present:
            messagebox.showinfo("Remove module", "Module is already missing.")
            return

        d = MAP_PTR_DEFS.get(code)
        name = d.name if d else f"Unknown module code 0x{code:02X}"

        msg = (
            f"Delete / remove:\n{name}\n(code 0x{code:02X})\n\n"
            "This will remove the Data Map record."
        )
        if d:
            msg += "\nIt will also zero the pointer field in DATA."
        else:
            msg += "\n\nNOTE: Unknown code: pointer field is not known, so no pointer will be edited."

        if not messagebox.askyesno("Delete Module", msg, parent=self):
            return

        try:
            self._structural_rebuild(add_codes=set(), remove_codes={code}, set_filename={})
        except Exception as e:
            messagebox.showerror("Remove module failed", str(e))
            return

        messagebox.showinfo("Removed", f"Module 0x{code:02X} removed from Data Map.")
        self._parse_all()


    def _structural_rebuild(
        self,
        add_codes: Set[int],
        remove_codes: Set[int],
        set_filename: Dict[int, str],
        add_mode: Optional[Dict[int, str]] = None,
    ) -> None:
        if add_mode is None:
            add_mode = {}

        """
        Structural edit:

        - Map bytes become canonical sorted unique codes.
        - String section is preserved (except optional append for new module filenames).
        - On add:
            - if add_mode[code] == "existing": reuse existing string if found, else append
            - if add_mode[code] == "new": always append at end (even if identical exists)
        - On remove:
            - remove map record
            - if code is mapped, zero its pointer field in DATA
        - Header string_len/map_len updated. Pads preserved.
        """
        assert self.working_blob is not None
        assert self.hdr is not None
        assert self.sec is not None

        # --- Figure out which map codes are currently present (including unknowns) ---
        present: Set[int] = set(self.module_codes_present)

        # Apply edits (keep unknown codes unless explicitly removed)
        new_present: Set[int] = (present | set(add_codes)) - set(remove_codes)
        new_codes_sorted: List[int] = sorted(new_present)

        # --- Start from existing sections ---
        new_string_bytes: bytes = self.sec.string_bytes
        out_data = bytearray(self.sec.data_bytes)  # DATA section only (offset base = 0x30)

        # For known (mapped) modules, determine the rel string offset to write
        rel_by_code: Dict[int, int] = {}

        for c in new_codes_sorted:
            d = MAP_PTR_DEFS.get(c)
            if not d:
                # unknown code: we keep the map record, but do not touch any pointers
                continue

            if c in add_codes:
                fn = (set_filename.get(c) or "").strip()
                if not fn:
                    raise ValueError(f"Module 0x{c:02X} ({d.name}) needs a filename.")

                mode = add_mode.get(c, "new")
                if mode == "existing":
                    rel = find_existing_string_rel(new_string_bytes, fn)
                    if rel is None:
                        new_string_bytes, rel = append_string(new_string_bytes, fn)
                else:
                    # "new": ALWAYS append
                    new_string_bytes, rel = append_string(new_string_bytes, fn)

                rel_by_code[c] = rel
            else:
                # Existing mapped module: preserve its current pointer (even if 0)
                if d.data_offset + 4 <= len(self.working_blob):
                    rel_by_code[c] = u32(self.working_blob, d.data_offset)
                else:
                    rel_by_code[c] = 0

        # --- Rebuild MAP section (canonical 8-byte records) ---
        new_map_bytes = build_data_map_bytes(new_codes_sorted)

        # --- Update DATA pointer fields for mapped modules ---
        for c, defn in MAP_PTR_DEFS.items():
            within = defn.data_offset - 0x30  # convert absolute file offset -> DATA-relative
            if within < 0 or within + 4 > len(out_data):
                continue

            if c in new_present:
                write_u32(out_data, within, rel_by_code.get(c, 0))
            else:
                # not present -> pointer must be 0
                write_u32(out_data, within, 0)

        # --- Validate pointers for newly-added mapped codes only (light, safe) ---
        to_validate = {c: rel_by_code[c] for c in add_codes if c in rel_by_code}
        ok, problems = validate_pointers(new_string_bytes, to_validate)
        if not ok:
            raise ValueError("Pointer validation failed:\n" + "\n".join(problems))

        # --- Update header lengths ---
        self.hdr.string_len = len(new_string_bytes)
        self.hdr.map_len = len(new_map_bytes)

        # --- Rebuild final blob ---
        new_sec = VdfmSections(
            header_bytes=self.sec.header_bytes,
            data_bytes=bytes(out_data),
            data_pad=self.sec.data_pad,
            string_bytes=new_string_bytes,
            string_pad=self.sec.string_pad,
            map_bytes=new_map_bytes,
            map_pad=self.sec.map_pad,
            end_bytes=self.sec.end_bytes,
            end_pad=self.sec.end_pad,
            trailing=self.sec.trailing,
        )
        self.working_blob = rebuild_blob(self.hdr, new_sec)

    # ----------------------------
    # Apply float edit (in-place)
    # ----------------------------
    def apply_float_edit(self):
        if self.working_blob is None or self._selected_float_off is None:
            return
        off = self._selected_float_off
        if off + 4 > len(self.working_blob):
            return

        s = self.float_new_var.get().strip()
        try:
            v = float(s)
        except Exception:
            messagebox.showerror("Invalid value", "Enter a valid number (float).")
            return

        buf = bytearray(self.working_blob)
        write_f32(buf, off, v)
        self.working_blob = bytes(buf)

        self._parse_all()
        messagebox.showinfo("Applied", "Float updated (in-place).")

    # ----------------------------
    # Apply string edit (safe resize) [existing behavior]
    # ----------------------------
    def apply_string_edit(self):
        if self.working_blob is None or self.hdr is None or self.sec is None:
            return
        if self._selected_string_index is None:
            return

        idx = self._selected_string_index
        if idx < 0 or idx >= len(self.string_entries):
            return

        new_txt = self.new_text_var.get()

        try:
            new_payload = new_txt.encode("latin-1", errors="strict")
        except Exception as e:
            messagebox.showerror("Invalid text", f"Text could not be encoded as latin-1: {e}")
            return
        if b"\x00" in new_payload:
            messagebox.showerror("Invalid text", "NUL byte not allowed inside a string entry.")
            return

        old_entry = self.string_entries[idx]
        old_len = len(old_entry.raw)
        new_raw = new_payload + b"\x00"
        new_len = len(new_raw)
        delta = new_len - old_len

        old_start = old_entry.rel_off
        old_end = old_start + old_len  # exclusive

        entries = list(self.string_entries)
        entries[idx] = StringEntry(rel_off=old_entry.rel_off, text=new_txt, raw=new_raw)

        rebuilt: List[StringEntry] = []
        rel = 0
        for e in entries:
            rebuilt.append(StringEntry(rel_off=rel, text=e.text, raw=e.raw))
            rel += len(e.raw)

        new_string_bytes = build_string_section(rebuilt)
        self.hdr.string_len = len(new_string_bytes)

        out_data = bytearray(self.sec.data_bytes)
        inside_pointer_hits: List[Tuple[str, int]] = []

        # Shift only active pointers (map-present) by delta beyond edited string
        for d in self.active_ptr_defs:
            abs_off = d.data_offset
            if abs_off + 4 > len(self.working_blob):
                continue
            old_ptr = u32(self.working_blob, abs_off)
            if old_ptr == 0:
                continue

            if old_ptr >= old_end:
                new_ptr = old_ptr + delta
            elif old_ptr >= old_start and old_ptr < old_end:
                new_ptr = old_ptr
                inside_pointer_hits.append((d.name, old_ptr))
            else:
                new_ptr = old_ptr

            within = abs_off - 0x30
            if 0 <= within <= len(out_data) - 4:
                write_u32(out_data, within, new_ptr)

        new_sec = VdfmSections(
            header_bytes=self.sec.header_bytes,
            data_bytes=bytes(out_data),
            data_pad=self.sec.data_pad,
            string_bytes=new_string_bytes,
            string_pad=self.sec.string_pad,
            map_bytes=self.sec.map_bytes,
            map_pad=self.sec.map_pad,
            end_bytes=self.sec.end_bytes,
            end_pad=self.sec.end_pad,
            trailing=self.sec.trailing,
        )

        self.working_blob = rebuild_blob(self.hdr, new_sec)
        self._parse_all()

        if inside_pointer_hits:
            msg = "Applied, but WARNING:\n\nOne or more pointer fields pointed inside the edited string span.\nThey were left unchanged:\n\n"
            msg += "\n".join(f"- {name}: ptr={ptr}" for name, ptr in inside_pointer_hits)
            self.string_warn_var.set("Warning: some pointers pointed inside the edited string span (left unchanged).")
            messagebox.showwarning("Applied with warning", msg)
        else:
            messagebox.showinfo("Applied", "String updated (safe resize + header + pointer shifts).")

# ----------------------------
# Main
# ----------------------------
if __name__ == "__main__":
    app = VdfmEditorApp()
    app.mainloop()
