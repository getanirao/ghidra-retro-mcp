import time
import logging
from pathlib import Path
from typing import Optional

import pyhidra

from ghidra.program.model.listing import FunctionManager
from ghidra.program.model.symbol import ReferenceManager
from ghidra.app.decompiler import DecompInterface
from ghidra.util.task import ConsoleTaskMonitor

logger = logging.getLogger(__name__)


class GhidraSession:
    def __init__(self, ghidra_dir: Optional[str] = None):
        self._launcher = None
        self._current_program = None
        self._current_flat_api = None
        self._current_binary_path = None
        self._ghidra_dir = ghidra_dir

    def start(self):
        kwargs = {}
        if self._ghidra_dir:
            kwargs["ghidra_dir"] = self._ghidra_dir
        pyhidra.start(verbose=True, **kwargs)
        logger.info("pyhidra started")

    def _close_program(self):
        if self._launcher is not None:
            try:
                self._launcher.close()
            except Exception:
                pass
            self._launcher = None
            self._current_program = None
            self._current_flat_api = None
            self._current_binary_path = None

    def analyze_binary(self, binary_path: str, project_dir: Optional[str] = None) -> dict:
        binary_path = Path(binary_path).resolve()
        if not binary_path.exists():
            raise FileNotFoundError(f"Binary not found: {binary_path}")

        self._close_program()

        project_dir = Path(project_dir or binary_path.parent).resolve()
        project_name = f"_{binary_path.stem}_mcp_{int(time.time())}"

        self._launcher = pyhidra.Launcher(
            project_dir=str(project_dir),
            project_name=project_name,
            binary_path=str(binary_path),
        )
        self._launcher.open_program()
        self._current_flat_api = self._launcher.flat_api
        self._current_program = self._launcher.program
        self._current_binary_path = str(binary_path)

        listing = self._current_program.getListing()

        return {
            "binary": str(binary_path),
            "project": project_name,
            "language": self._current_program.getLanguageID().getIdAsString(),
            "compiler": self._current_program.getCompilerSpec().getCompilerSpecID().getIdAsString(),
            "image_base": str(self._current_program.getImageBase()),
            "min_address": str(self._current_program.getMinAddress()),
            "max_address": str(self._current_program.getMaxAddress()),
            "num_functions": len(list(listing.getFunctions(True))),
        }

    def _require_session(self):
        if self._current_program is None:
            raise RuntimeError("No binary loaded. Call analyze_binary first.")

    def decompile_function(self, function_name: str) -> dict:
        self._require_session()
        flat = self._current_flat_api
        program = self._current_program

        listing = program.getListing()
        func = _find_function(listing, function_name)
        if func is None:
            raise ValueError(f"Function '{function_name}' not found")

        decompiler = DecompInterface()
        decompiler.openProgram(program)
        monitor = ConsoleTaskMonitor()
        result = decompiler.decompileFunction(func, 0, monitor)

        if not result or not result.decompileCompleted():
            raise RuntimeError(f"Decompilation failed for '{function_name}'")

        return {
            "name": func.getName(),
            "address": str(func.getEntryPoint()),
            "signature": func.getSignature(),
            "decompiled": result.getDecompiledFunction().getC(),
        }

    def get_data_types(self) -> list[dict]:
        self._require_session()
        program = self._current_program
        dtm = program.getDataTypeManager()
        types = []

        for dt in dtm.getAllDataTypes():
            try:
                types.append({
                    "name": dt.getName(),
                    "path": dt.getPathName(),
                    "category": dt.getCategory().getCategoryPath().getPath(),
                    "size": dt.getLength(),
                    "type": dt.getClass().getSimpleName(),
                })
            except Exception:
                pass

        return types

    def get_cross_references(self, address: str, max_results: int = 100) -> dict:
        self._require_session()
        program = self._current_program
        addr = program.getAddressFactory().getAddress(address)
        if addr is None:
            raise ValueError(f"Invalid address: {address}")

        ref_mgr: ReferenceManager = program.getReferenceManager()
        refs_to = ref_mgr.getReferencesTo(addr)
        refs_from = ref_mgr.getReferencesFrom(addr)

        to_list = []
        from_list = []
        for r in refs_to:
            to_list.append({
                "from_address": str(r.getFromAddress()),
                "ref_type": str(r.getReferenceType().getName()),
            })
            if len(to_list) >= max_results:
                break

        for r in refs_from:
            from_list.append({
                "to_address": str(r.getToAddress()),
                "ref_type": str(r.getReferenceType().getName()),
            })
            if len(from_list) >= max_results:
                break

        return {
            "address": address,
            "references_to": to_list,
            "references_from": from_list,
        }

    def get_call_graph(self, function_name: str, max_depth: int = 3) -> dict:
        self._require_session()
        listing = self._current_program.getListing()
        func = _find_function(listing, function_name)
        if func is None:
            raise ValueError(f"Function '{function_name}' not found")

        calls_from = _resolve_calls(func, self._current_program, max_depth)

        calls_to = {}
        fm: FunctionManager = self._current_program.getFunctionManager()
        for caller in fm.getFunctions(True):
            if caller == func:
                continue
            called_set = _resolve_calls(caller, self._current_program, 1)
            if func.getName() in called_set or str(func.getEntryPoint()) in called_set:
                calls_to[caller.getName()] = str(caller.getEntryPoint())

        return {
            "function": function_name,
            "address": str(func.getEntryPoint()),
            "calls": calls_from,
            "called_by": calls_to,
        }


def _find_function(listing, name_or_addr: str):
    fm = listing.getFunctionManager()
    func = fm.getFunctionAt(listing.getProgram().getAddressFactory().getAddress(name_or_addr))
    if func is not None:
        return func
    for f in fm.getFunctions(True):
        if f.getName() == name_or_addr:
            return f
    return None


def _resolve_calls(func, program, depth: int) -> dict:
    if depth <= 0:
        return {}
    listing = program.getListing()
    fm = program.getFunctionManager()
    result = {}
    body = func.getBody()
    addr_iter = listing.getCodeUnits(body, True)
    seen = set()

    while addr_iter.hasNext():
        cu = addr_iter.next()
        refs = cu.getOperandReferences(0)
        for ref in refs:
            if ref.getReferenceType().toString() != "UNCONDITIONAL_CALL":
                continue
            target_addr = ref.getToAddress()
            target_key = str(target_addr)
            if target_key in seen:
                continue
            seen.add(target_key)
            target_func = fm.getFunctionAt(target_addr)
            if target_func:
                name = target_func.getName()
                if target_key not in result:
                    result[target_key] = {"name": name, "address": target_key}
                    if depth > 1:
                        nested = _resolve_calls(target_func, program, depth - 1)
                        if nested:
                            result[target_key]["calls"] = nested

    return {k: v for k, v in sorted(result.items())}
