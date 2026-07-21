## Summary

<!-- One-sentence description of what this PR adds or fixes. -->

Closes #<!-- issue number if applicable -->

---

## Console Platform

<!-- Which retro platform(s) does this PR affect? Delete rows that don't apply. -->

- [ ] Nintendo Entertainment System (NES)
- [ ] Super Nintendo (SNES)
- [ ] Game Boy Advance (GBA)
- [ ] Nintendo DS (NDS)
- [ ] Nintendo Switch
- [ ] PlayStation 1 (PSX)
- [ ] Sega Genesis / Mega Drive
- [ ] Sega Master System / Game Gear
- [ ] Sega Dreamcast
- [ ] Other / Cross-platform

---

## Changes

### Header detection (`retro_triage.py`)

<!-- Describe any new magic bytes, signature offsets, or architecture tags added. -->

| Platform | Magic bytes | Offset | Ghidra Language ID |
|---|---|---|---|
| ... | ... | ... | ... |

### Tools / bridge (`server.py`, `ghidra_bridge.py`)

<!-- List any new MCP tools or modifications to existing session logic. -->

### Loader dependencies (`Dockerfile`)

<!-- List new `wget` stanzas added for third-party Ghidra extensions. -->

---

## Testing matrix

<!-- Which ROMs or binaries were used to verify the changes? Include hash if possible. -->

| ROM / Binary | Platform | Detected? | Loaded? | Emulation OK? |
|---|---|---|---|---|
| `example.nes` | NES | Yes | Yes | Yes |
| ... | ... | ... | ... | ... |

- [ ] Tested with `MOCK_MODE=1` (CI-safe)
- [ ] Tested with real Ghidra 11.2 + pyhidra

---

## Docker verification

- [ ] `docker build -t ghidra-retro-mcp .` succeeds
- [ ] Container starts with `docker run -i --rm ghidra-retro-mcp`

---

## Checklist

- [ ] Python syntax passes: `python -m py_compile src/ghidra_retro_mcp/...`
- [ ] No stale references to old package or tool names
- [ ] README updated if user-facing behaviour changed
- [ ] PR targets `main` branch
