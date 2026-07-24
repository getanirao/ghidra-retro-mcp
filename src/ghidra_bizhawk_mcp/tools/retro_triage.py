import os
from typing import Tuple


def detect_retro_platform(rom_path: str) -> Tuple[str, str, str]:
    """
    Scans raw file header offsets to extract magic signatures for retro
    console platforms.  Returns (Platform Name, Ghidra Language ID,
    Target Loader Name).
    """
    if not os.path.exists(rom_path):
        raise FileNotFoundError(f"Binary source path invalid: {rom_path}")

    with open(rom_path, "rb") as f:
        header = f.read(0x200)

    file_size = os.path.getsize(rom_path)

    # ── Nintendo ─────────────────────────────────────────────────────────

    # 1. NES iNES Header
    if header[0:4] == b"NES\x1a":
        return "Nintendo Entertainment System (NES)", "6502:LE:16:default", "iNES Loader"

    # 2. Game Boy Advance — Nintendo logo at 0x04, fixed 0x96 at 0xB2
    if (
        file_size >= 0xC0
        and len(header) >= 0xB3
        and header[0x04:0x08] == b"\x24\xFF\xAE\x51"
        and header[0xB2] == 0x96
    ):
        return "Game Boy Advance (GBA)", "ARM:LE:32:v4t", "GBA ROM Loader"

    # 3. Nintendo DS
    if file_size >= 0x20 and (header[0x12:0x15] == b"NTR" or header[0x12:0x15] == b"TWL"):
        return "Nintendo DS (NDS)", "ARM:LE:32:v5t", "NDS Cartridge Loader"

    # 4. Nintendo Switch
    if header[0:4] in [b"NSO0", b"NCA3", b"MOD0"]:
        return "Nintendo Switch", "AARCH64:LE:64:v8A", "Switch NSO/NCA Loader"

    # 5. Super Nintendo (SNES)
    if file_size % 1024 == 512:
        header = header[512:]
    if file_size >= 0x8000:
        title_chunk = header[0x7FC0:0x7FD0]
        if any(b in title_chunk for b in [b"SUPER", b"MARIO", b"ZELDA"]):
            return "Super Nintendo (SNES)", "65816:LE:24:default", "SNES ROM Loader"

    # ── Sony ──────────────────────────────────────────────────────────────

    # 6. PlayStation 1 (PSX) Executable
    if header[0:8] == b"PS-X EXE":
        return "Sony PlayStation 1 (PSX)", "MIPS:LE:32:default", "PSX Executable Loader"

    # ── Sega ──────────────────────────────────────────────────────────────

    # 7. Sega Genesis / Mega Drive
    if len(header) >= 0x110 and header[0x100:0x104] == b"SEGA":
        return "Sega Genesis / Mega Drive", "68000:BE:32:default", "Genesis ROM Image"

    # 8. Sega Master System / Game Gear
    if b"TMR SEGA" in header:
        return "Sega Master System / Game Gear", "Z80:16:default", "SMS ROM Loader"

    # 9. Sega Dreamcast
    if len(header) >= 0x20 and header[0x10:0x20].startswith(b"SEGA ENTERPRISES"):
        return "Sega Dreamcast", "SuperH4:LE:32:default", "Dreamcast Binary Profile"

    return "Unknown/Generic Retro Binary Profile", "Auto-Detect", "Default Object Loader"
