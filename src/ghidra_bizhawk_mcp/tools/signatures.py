import hashlib
import logging
from typing import Optional

from ghidra.program.model.listing import Function, FunctionManager
from ghidra.program.model.symbol import SourceType

logger = logging.getLogger(__name__)


def fingerprint_function(func, program) -> dict:
    """Build a behavior-based fingerprint for a single function.

    The fingerprint uses structural features that survive compiler
    shuffling: AST shape, called imports, embedded constants, and
    referenced strings.
    """
    fm: FunctionManager = program.getFunctionManager()

    # ── Structural features ─────────────────────────────────────────
    local_var_count = len(func.getLocalVariables())
    parameter_count = func.getParameterCount()
    body_size = func.getBody().getNumAddresses()

    # ── Called functions (imports / internal) ───────────────────────
    called = set()
    called_funcs = func.getCalledFunctions(None)
    for cf in called_funcs:
        called.add(cf.getName())

    # ── String constants referenced in the function body ────────────
    strings = _collect_strings(func, program)

    # ── Magic / numeric constants ───────────────────────────────────
    constants = _collect_constants(func, program)

    # ── Branch / loop count (structural complexity) ─────────────────
    branches = _count_branches(func, program)

    # ── Assemble signature payload ──────────────────────────────────
    parts = [
        f"vars:{local_var_count}",
        f"params:{parameter_count}",
        f"size:{body_size}",
        f"branches:{branches}",
    ]
    if called:
        parts.append(f"calls:{','.join(sorted(called))}")
    if strings:
        parts.append(f"strs:{'|'.join(sorted(strings))}")
    if constants:
        parts.append(f"nums:{','.join(str(c) for c in sorted(constants)[:20])}")

    payload = "|".join(parts)
    digest = hashlib.sha256(payload.encode("utf-8")).hexdigest()[:16]

    return {
        "function_name": func.getName(),
        "address": str(func.getEntryPoint()),
        "behavior_hash": digest,
        "signature_payload": payload,
        "details": {
            "local_vars": local_var_count,
            "parameters": parameter_count,
            "body_size": body_size,
            "branches": branches,
            "called_functions": sorted(called),
            "strings": strings[:10],
            "constants": constants[:20],
        },
    }


def export_signature_map(program) -> dict:
    """Generate a full signature map for every function in the program.

    Returns a dict keyed by behavior hash → function metadata.
    """
    fm: FunctionManager = program.getFunctionManager()
    sig_map = {}
    for func in fm.getFunctions(True):
        fp = fingerprint_function(func, program)
        sig_map[fp["behavior_hash"]] = {
            "name": func.getName(),
            "address": str(func.getEntryPoint()),
            "signature_payload": fp["signature_payload"],
        }
    return sig_map


def apply_signature_map(program, sig_map: dict) -> int:
    """Scan all functions in *program*, match against *sig_map*, and
    rename hits to the stored name.  Returns the count of matches."""
    fm: FunctionManager = program.getFunctionManager()
    matched = 0
    for func in fm.getFunctions(True):
        fp = fingerprint_function(func, program)
        entry = sig_map.get(fp["behavior_hash"])
        if entry is None:
            continue
        desired = entry["name"]
        current = func.getName()
        if current == desired:
            continue
        func.setName(desired, SourceType.USER_DEFINED)
        matched += 1
    return matched


# ── Internal helpers ─────────────────────────────────────────────────


def _collect_strings(func, program) -> list[str]:
    """Extract string constants referenced inside a function body."""
    from ghidra.program.model.listing import Data
    strings = set()
    body = func.getBody()
    listing = program.getListing()
    ref_mgr = program.getReferenceManager()
    addr_iter = listing.getCodeUnits(body, True)

    while addr_iter.hasNext():
        cu = addr_iter.next()
        addr = cu.getMinAddress()
        refs = ref_mgr.getReferencesFrom(addr)
        for ref in refs:
            to_addr = ref.getToAddress()
            if not body.contains(to_addr):
                data = listing.getDefinedDataAt(to_addr)
                if data is not None and data.isString():
                    try:
                        val = data.getDefaultValueRepresentation()
                        if val and len(val) > 1:
                            strings.add(val[:80])
                    except Exception:
                        pass
    return sorted(strings)


def _collect_constants(func, program) -> list[int]:
    """Extract interesting numeric constants from instructions."""
    constants = set()
    body = func.getBody()
    listing = program.getListing()
    from ghidra.program.model.listing import Instruction
    addr_iter = listing.getCodeUnits(body, True)

    while addr_iter.hasNext():
        cu = addr_iter.next()
        if not isinstance(cu, Instruction):
            continue
        for i in range(cu.getNumOperands()):
            for j in range(cu.getNumOperands()):
                try:
                    val = cu.getInt(i)
                    if val is not None and (val < -1 or val > 255):
                        constants.add(val)
                except Exception:
                    pass
                try:
                    val = cu.getScalar(i)
                    if val is not None:
                        v = val.getValue()
                        if isinstance(v, int) and (v < -1 or v > 255):
                            constants.add(v)
                except Exception:
                    pass
    return sorted(constants)


def _count_branches(func, program) -> int:
    """Count conditional branches / jumps in the function body."""
    count = 0
    body = func.getBody()
    listing = program.getListing()
    from ghidra.program.model.listing import Instruction
    from ghidra.program.model.lang import FlowType
    addr_iter = listing.getCodeUnits(body, True)

    while addr_iter.hasNext():
        cu = addr_iter.next()
        if isinstance(cu, Instruction):
            ft = cu.getFlowType()
            if ft.isConditional():
                count += 1
    return count
