import os
import json
import hashlib
import logging
from pathlib import Path

from .signatures import export_signature_map, apply_signature_map

logger = logging.getLogger(__name__)

CACHE_DIR = os.path.join(os.path.expanduser("~"), ".ghidra_headless_mcp", "signatures")


def _ensure_cache():
    os.makedirs(CACHE_DIR, exist_ok=True)


def _binary_hash(program) -> str:
    """Return the SHA-256 hex digest of the binary's first 4 KB (fast
    content fingerprint for automatic cache lookup)."""
    mem = program.getMemory()
    min_addr = program.getMinAddress()
    size = min(4096, int(program.getMaxAddress().subtract(min_addr)))
    try:
        bb = mem.getBytes(min_addr, size)
        return hashlib.sha256(bytes(b & 0xFF for b in bb)).hexdigest()[:16]
    except Exception:
        return ""


def _stash_path(lineage_group_id: str) -> str:
    _ensure_cache()
    return os.path.join(CACHE_DIR, f"{lineage_group_id}.json")


def save_signature_stash(program, lineage_group_id: str) -> dict:
    """Fingerprint every function in *program* and cache the map under
    *lineage_group_id*."""
    sig_map = export_signature_map(program)
    path = _stash_path(lineage_group_id)
    with open(path, "w") as f:
        json.dump(sig_map, f, indent=2)
    return {
        "lineage_group_id": lineage_group_id,
        "cached_path": path,
        "function_count": len(sig_map),
    }


def restore_signature_stash(program, lineage_group_id: str) -> dict:
    """Load a previously cached map and apply it to *program*."""
    path = _stash_path(lineage_group_id)
    if not os.path.exists(path):
        return {"lineage_group_id": lineage_group_id, "matched": 0, "error": "not found"}
    with open(path, "r") as f:
        sig_map = json.load(f)
    count = apply_signature_map(program, sig_map)
    return {
        "lineage_group_id": lineage_group_id,
        "matched": count,
        "cached_path": path,
    }


def auto_stash_current_binary(program) -> dict:
    """Compute a content hash of the loaded binary, stash a signature
    map under that hash, and return the hash so the caller knows what
    ID was used."""
    h = _binary_hash(program)
    if not h:
        return {"lineage_group_id": "", "error": "could not hash binary"}
    return save_signature_stash(program, h)


def auto_restore_current_binary(program) -> dict:
    """Compute the content hash and attempt a restore.  Returns hit
    count (0 if no previous stash exists)."""
    h = _binary_hash(program)
    if not h:
        return {"lineage_group_id": "", "matched": 0, "error": "could not hash binary"}
    return restore_signature_stash(program, h)


def list_stashed_groups() -> list[dict]:
    _ensure_cache()
    results = []
    for entry in sorted(os.listdir(CACHE_DIR)):
        if entry.endswith(".json"):
            path = os.path.join(CACHE_DIR, entry)
            group = entry[:-5]
            size = os.path.getsize(path)
            results.append({
                "lineage_group_id": group,
                "cached_path": path,
                "size_bytes": size,
            })
    return results
