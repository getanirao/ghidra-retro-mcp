import logging
from typing import Optional

from ghidra.app.emulator import EmulatorHelper
from ghidra.util.task import ConsoleTaskMonitor
from ghidra.program.model.listing import Instruction

logger = logging.getLogger(__name__)


def emulate_instruction_slice(
    program,
    start_address,
    instruction_count: int,
    initial_registers: dict[str, int],
    track_registers: Optional[list[str]] = None,
) -> dict:
    """Step through *instruction_count* instructions from *start_address*
    using Ghidra's headless P-code emulator.

    Parameters
    ----------
    program : Ghidra Program
    start_address : Ghidra Address
    instruction_count : int
    initial_registers : dict
        e.g. {"r0": 5, "r1": 0x41424344, "pc": 0x1000}
    track_registers : list[str] or None
        Subset of registers to log after each step.  If None, all
        initialised registers are tracked plus the program counter.

    Returns
    -------
    dict with keys:
        success        : bool
        steps          : list of step records
        final_registers : dict of last-seen register values
        error          : str if a step failed
    """
    emu = EmulatorHelper(program)
    monitor = ConsoleTaskMonitor()
    addr_factory = program.getAddressFactory()

    # ── Seed initial register state ──────────────────────────────────
    for reg_name, reg_val in initial_registers.items():
        try:
            emu.writeRegister(reg_name.upper(), reg_val)
        except Exception as exc:
            emu.dispose()
            raise ValueError(
                f"Cannot write register '{reg_name}': {exc}"
            ) from exc

    # Determine which registers to log at each step
    if track_registers is None:
        tracked = set(k.upper() for k in initial_registers)
        tracked.add("PC")
    else:
        tracked = set(r.upper() for r in track_registers)

    # ── Step loop ────────────────────────────────────────────────────
    steps = []
    current_addr = start_address
    error = None

    for step_index in range(instruction_count):
        pc_offset = emu.readRegister("PC")
        pc_addr = addr_factory.getAddress(pc_offset)

        # Fetch the instruction about to execute
        cu = program.getListing().getCodeUnitAt(pc_addr)
        if cu is None or not isinstance(cu, Instruction):
            steps.append({
                "step": step_index,
                "address": str(pc_addr),
                "instruction": "<not-an-instruction>",
                "error": "Hit non-instruction memory — stopping",
            })
            break

        instr_str = f"{cu.getMnemonicString()} {cu.getDefaultOperandRepresentation()}"

        # Single-step
        ok = emu.step(monitor)
        if not ok:
            error = emu.getLastError()
            steps.append({
                "step": step_index,
                "address": str(pc_addr),
                "instruction": instr_str,
                "error": error,
            })
            break

        # Snapshot tracked registers
        reg_snapshot = {}
        for reg in tracked:
            try:
                reg_snapshot[reg.lower()] = emu.readRegister(reg)
            except Exception:
                pass

        steps.append({
            "step": step_index,
            "address": str(pc_addr),
            "instruction": instr_str,
            "registers": reg_snapshot,
        })

    # ── Final register state ─────────────────────────────────────────
    final_regs = {}
    for reg in tracked:
        try:
            final_regs[reg.lower()] = emu.readRegister(reg)
        except Exception:
            pass

    emu.dispose()

    return {
        "success": error is None,
        "steps": steps,
        "final_registers": final_regs,
        "error": error,
    }


def emulate_slice_with_taint(
    program,
    start_address,
    instruction_count: int,
    initial_registers: dict[str, int],
    taint_register: str,
) -> dict:
    """Step through instructions tracking data lineage of *taint_register*.

    After each step, reports:
      - whether the taint register was modified / overwritten
      - whether the taint value propagated to any other tracked register
    """
    emu = EmulatorHelper(program)
    monitor = ConsoleTaskMonitor()
    addr_factory = program.getAddressFactory()

    for rn, rv in initial_registers.items():
        try:
            emu.writeRegister(rn.upper(), rv)
        except Exception as exc:
            emu.dispose()
            raise ValueError(f"Cannot write register '{rn}': {exc}") from exc

    tracked = set(k.upper() for k in initial_registers)
    tracked.add("PC")
    taint_name = taint_register.upper()
    tracked.add(taint_name)

    taint_value = emu.readRegister(taint_name)
    steps = []
    error = None

    for step_index in range(instruction_count):
        pc_offset = emu.readRegister("PC")
        pc_addr = addr_factory.getAddress(pc_offset)

        cu = program.getListing().getCodeUnitAt(pc_addr)
        if cu is None or not isinstance(cu, Instruction):
            steps.append({
                "step": step_index, "address": str(pc_addr),
                "instruction": "<non-instruction>",
                "error": "Hit non-instruction memory — stopping",
            })
            break

        instr_str = f"{cu.getMnemonicString()} {cu.getDefaultOperandRepresentation()}"

        ok = emu.step(monitor)
        if not ok:
            error = emu.getLastError()
            steps.append({
                "step": step_index, "address": str(pc_addr),
                "instruction": instr_str, "error": error,
            })
            break

        reg_snapshot = {}
        for reg in tracked:
            try:
                reg_snapshot[reg.lower()] = emu.readRegister(reg)
            except Exception:
                pass

        new_taint_val = reg_snapshot.get(taint_name.lower())

        if new_taint_val != taint_value:
            taint_status = "Taint Modified"
        else:
            spread = [
                r for r, v in reg_snapshot.items()
                if v == taint_value and r.lower() != taint_name.lower()
            ]
            taint_status = f"Taint Propagated to {', '.join(spread)}" if spread else "Clean"

        steps.append({
            "step": step_index,
            "address": str(pc_addr),
            "instruction": instr_str,
            "registers": reg_snapshot,
            "taint": {
                "register": taint_name.lower(),
                "value": new_taint_val,
                "status": taint_status,
            },
        })

    final_regs = {}
    for reg in tracked:
        try:
            final_regs[reg.lower()] = emu.readRegister(reg)
        except Exception:
            pass

    emu.dispose()

    return {
        "success": error is None,
        "taint_register": taint_name.lower(),
        "taint_initial_value": taint_value,
        "steps": steps,
        "final_registers": final_regs,
        "error": error,
    }


def emulate_slice_with_breakpoints(
    program,
    start_address,
    instruction_count: int,
    initial_registers: dict[str, int],
    break_condition: str,
) -> dict:
    """Step through instructions until *break_condition* is met or the
    instruction limit is reached.

    *break_condition* is a simple expression evaluated after each step.
    Supported patterns:
        "R0 == 0"       — stop when register equals value
        "R1 > 0xFF"     — stop when register exceeds value
        "R2 != R3"      — stop when two registers differ
        "PC == 0x1234"  — stop at a specific address
    """
    emu = EmulatorHelper(program)
    monitor = ConsoleTaskMonitor()
    addr_factory = program.getAddressFactory()

    for rn, rv in initial_registers.items():
        try:
            emu.writeRegister(rn.upper(), rv)
        except Exception as exc:
            emu.dispose()
            raise ValueError(f"Cannot write register '{rn}': {exc}") from exc

    tracked = set(k.upper() for k in initial_registers)
    tracked.add("PC")
    steps = []
    error = None
    stopped_by_break = False

    for step_index in range(instruction_count):
        pc_offset = emu.readRegister("PC")
        pc_addr = addr_factory.getAddress(pc_offset)

        cu = program.getListing().getCodeUnitAt(pc_addr)
        if cu is None or not isinstance(cu, Instruction):
            steps.append({
                "step": step_index, "address": str(pc_addr),
                "instruction": "<non-instruction>",
                "error": "Hit non-instruction memory — stopping",
            })
            break

        instr_str = f"{cu.getMnemonicString()} {cu.getDefaultOperandRepresentation()}"

        # Check break condition BEFORE stepping (we're about to execute this instruction)
        regs_before = {}
        for reg in tracked:
            try:
                regs_before[reg.lower()] = emu.readRegister(reg)
            except Exception:
                pass
        if _eval_break(break_condition, regs_before):
            steps.append({
                "step": step_index,
                "address": str(pc_addr),
                "instruction": instr_str,
                "registers": regs_before,
                "break_triggered": True,
                "reason": f"Condition met before execution: {break_condition}",
            })
            stopped_by_break = True
            break

        ok = emu.step(monitor)
        if not ok:
            error = emu.getLastError()
            steps.append({
                "step": step_index, "address": str(pc_addr),
                "instruction": instr_str, "error": error,
            })
            break

        reg_snapshot = {}
        for reg in tracked:
            try:
                reg_snapshot[reg.lower()] = emu.readRegister(reg)
            except Exception:
                pass

        if _eval_break(break_condition, reg_snapshot):
            steps.append({
                "step": step_index,
                "address": str(pc_addr),
                "instruction": instr_str,
                "registers": reg_snapshot,
                "break_triggered": True,
                "reason": f"Condition met after execution: {break_condition}",
            })
            stopped_by_break = True
            break

        steps.append({
            "step": step_index,
            "address": str(pc_addr),
            "instruction": instr_str,
            "registers": reg_snapshot,
            "break_triggered": False,
        })

    final_regs = {}
    for reg in tracked:
        try:
            final_regs[reg.lower()] = emu.readRegister(reg)
        except Exception:
            pass

    emu.dispose()

    return {
        "success": error is None,
        "stopped_by_break": stopped_by_break,
        "break_condition": break_condition,
        "steps": steps,
        "final_registers": final_regs,
        "error": error,
    }


def _eval_break(condition: str, regs: dict[str, int]) -> bool:
    """Evaluate a simple break condition against register state.

    Supports patterns: REG == VAL, REG != VAL, REG > VAL, REG < VAL,
    REG == REG, REG != REG, PC == ADDR.
    """
    cond = condition.strip()
    import re as _re

    m = _re.match(r"^(\w+)\s*(==|!=|>|<|>=|<=)\s*(\w+)$", cond)
    if not m:
        return False

    left, op, right = m.group(1), m.group(2), m.group(3)
    left_lower = left.lower()
    right_lower = right.lower()

    lv = regs.get(left_lower)
    if lv is None:
        try:
            lv = int(left, 0)
        except ValueError:
            return False

    rv = regs.get(right_lower)
    if rv is None:
        try:
            rv = int(right, 0)
        except ValueError:
            return False

    if op == "==":
        return lv == rv
    elif op == "!=":
        return lv != rv
    elif op == ">":
        return lv > rv
    elif op == "<":
        return lv < rv
    elif op == ">=":
        return lv >= rv
    elif op == "<=":
        return lv <= rv
    return False
