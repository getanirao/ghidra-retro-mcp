import logging

logger = logging.getLogger(__name__)


def build_workspace_report(program) -> str:
    """Generate a Markdown summary of the current workspace session."""
    fm = program.getFunctionManager()
    sym_table = program.getSymbolTable()
    dtm = program.getDataTypeManager()
    listing = program.getListing()

    # ── Custom annotations (USER_DEFINED symbols) ────────────────────
    user_symbols = []
    for sym in sym_table.getDefinedSymbols():
        try:
            if sym.getSource().toString() == "USER_DEFINED":
                user_symbols.append(
                    f"- **{sym.getName()}** at `{sym.getAddress()}`"
                )
        except Exception:
            pass

    # ── Recovered structures ─────────────────────────────────────────
    custom_structs = []
    for dt in dtm.getAllDataTypes():
        try:
            if "Structure" in type(dt).__name__:
                fields = dt.getComponents()
                field_lines = []
                for f in fields:
                    field_lines.append(
                        f"  - `+0x{f.getOffset():04x}` {f.getDataType().getName()} `{f.getFieldName()}`"
                    )
                custom_structs.append(
                    f"- **{dt.getName()}** ({dt.getLength()} bytes)\n"
                    + "\n".join(field_lines)
                )
        except Exception:
            pass

    # ── Entry-point summary ──────────────────────────────────────────
    entry_lines = []
    try:
        fmt, md5 = program.getExecutableFormat(), program.getExecutableMD5()
        entry_lines.append(f"- **Format:** `{fmt}`")
        entry_lines.append(f"- **MD5:** `{md5}`")
    except Exception:
        pass

    # ── Function overview ────────────────────────────────────────────
    total_funcs = 0
    with_body = 0
    for f in fm.getFunctions(True):
        total_funcs += 1
        if f.getBody().getNumAddresses() > 1:
            with_body += 1

    # ── Renamed functions (non-default names) ────────────────────────
    renamed = []
    for f in fm.getFunctions(True):
        try:
            src = f.getSymbol().getSource().toString()
            if src == "USER_DEFINED":
                renamed.append(f"- **{f.getName()}** at `{f.getEntryPoint()}`")
        except Exception:
            pass

    # ── Comments count ───────────────────────────────────────────────
    comment_count = 0
    for f in fm.getFunctions(True):
        body = f.getBody()
        addr_iter = listing.getCodeUnits(body, False)
        while addr_iter.hasNext():
            cu = addr_iter.next()
            if cu.getComment(0) is not None:
                comment_count += 1

    # ── Assemble report ──────────────────────────────────────────────
    lines = [
        "# Ghidra Retro MCP — Workspace Report",
        "",
        f"**Program:** `{program.getName()}`",
        f"**Architecture:** `{program.getLanguage().getLanguageID()}`",
        f"**Compiler:** `{program.getCompilerSpec().getCompilerSpecID().getIdAsString()}`",
        f"**Image base:** `{program.getImageBase()}`",
        "",
        "---",
        f"## Analysis Overview",
        f"- **Total functions:** {total_funcs} ({with_body} with body)",
        f"- **Entry points:** {len(entry_lines)}",
        f"- **User-defined symbols:** {len(user_symbols)}",
        f"- **Custom structures:** {len(custom_structs)}",
        f"- **Renamed functions:** {len(renamed)}",
        f"- **Code units with comments:** {comment_count}",
        "",
    ]

    if entry_lines:
        lines.append("### Entry Points")
        lines.extend(entry_lines)
        lines.append("")

    if renamed:
        lines.append(f"## Renamed Functions ({len(renamed)})")
        lines.extend(renamed)
        lines.append("")

    if user_symbols:
        lines.append(f"## Custom Symbols ({len(user_symbols)})")
        lines.extend(user_symbols)
        lines.append("")

    if custom_structs:
        lines.append(f"## Recovered Structures ({len(custom_structs)})")
        lines.extend(custom_structs)
        lines.append("")

    lines.append(
        "---\n"
        "*Report compiled over process stdio — no GUI required.*"
    )

    return "\n".join(lines)
