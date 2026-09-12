"""Embed angr pseudocode for trace-observed functions into an EMTR v3 file."""

from __future__ import annotations

import argparse
import hashlib
import io
import logging
import sys
from pathlib import Path

from architectures import ARCH, ARCHITECTURES
from emu_tracer import TraceReader

DECOMPILATION_VERSION = 1
MAX_FUNCTIONS = 256
ANGR_ARCHES = {
    ARCH.ARM16: "ARMEL",
    ARCH.ARM32: "ARMEL",
    ARCH.ARM64: "AARCH64",
    ARCH.X86: "X86",
    ARCH.X86_64: "AMD64",
    ARCH.MIPS: "MIPS32",
    ARCH.MIPSEL: "MIPS32EL",
    ARCH.MIPS64: "MIPS64",
    ARCH.MIPS64EL: "MIPS64EL",
    ARCH.PPC: "PPC32",
    ARCH.PPC64: "PPC64",
    ARCH.RISCV64: "RISCV64",
    ARCH.S390X: "S390X",
    ARCH.ARM16BE: "ARMEB",
    ARCH.ARM32BE: "ARMEB",
    ARCH.ARM_MCLASS: "ARMCortexM",
}


def parse_address(value):
    try:
        address = int(value, 0)
    except ValueError as exc:
        raise argparse.ArgumentTypeError(f"invalid address: {value}") from exc
    if not 0 <= address < 1 << 64:
        raise argparse.ArgumentTypeError("address must fit in an unsigned 64-bit integer")
    return address


def _sha256(path):
    digest = hashlib.sha256()
    with path.open("rb") as stream:
        for chunk in iter(lambda: stream.read(1024 * 1024), b""):
            digest.update(chunk)
    return digest.hexdigest()


def _trace_project(angr, trace):
    arch = ANGR_ARCHES.get(trace.arch)
    if arch is None:
        family = ARCHITECTURES[trace.arch].name
        raise ValueError(f"angr has no native architecture mapping for {family} trace bytes")
    memory = {}
    for frame in trace.frames:
        for offset, value in enumerate(frame["opcode"]):
            address = frame["address"] + offset
            previous = memory.setdefault(address, value)
            if previous != value:
                raise ValueError(
                    f"code changes at {address:#x}; supply the original executable instead"
                )
    if not memory:
        raise ValueError("Cannot decompile an empty trace")
    image = bytearray()
    segments = []
    addresses = sorted(memory)
    start = addresses[0]
    run = bytearray([memory[start]])
    previous = start
    for address in addresses[1:]:
        if address == previous + 1:
            run.append(memory[address])
        else:
            segments.append((len(image), start, len(run)))
            image.extend(run)
            start = address
            run = bytearray([memory[address]])
        previous = address
    segments.append((len(image), start, len(run)))
    image.extend(run)
    entry = trace.frames[0]["address"]
    if trace.arch in (ARCH.ARM16, ARCH.ARM16BE, ARCH.ARM_MCLASS):
        entry |= 1
    options = {
        "backend": "blob",
        "arch": arch,
        "base_addr": addresses[0],
        "entry_point": entry,
        "segments": segments,
    }
    data = bytes(image)
    project = angr.Project(io.BytesIO(data), main_opts=options, auto_load_libs=False)
    return project, {
        "name": "trace instruction bytes",
        "sha256": hashlib.sha256(data).hexdigest(),
        "source": "trace",
    }


def _load_project(angr, binary, trace, *, blob, base_address, entry_point):
    if binary is None:
        if blob or base_address is not None or entry_point is not None:
            raise ValueError("--blob, --base-address, and --entry-point require a binary")
        return _trace_project(angr, trace)
    if not blob:
        if base_address is not None or entry_point is not None:
            raise ValueError("--base-address and --entry-point require --blob")
        return angr.Project(str(binary), auto_load_libs=False), {
            "name": binary.name,
            "sha256": _sha256(binary),
            "source": "binary",
        }
    if base_address is None:
        raise ValueError("--blob requires --base-address")
    arch = ANGR_ARCHES.get(trace.arch)
    if arch is None:
        family = ARCHITECTURES[trace.arch].name
        raise ValueError(f"angr has no native architecture mapping for {family} raw blobs")
    options = {
        "backend": "blob",
        "arch": arch,
        "base_addr": base_address,
        "entry_point": base_address if entry_point is None else entry_point,
    }
    return angr.Project(str(binary), main_opts=options, auto_load_libs=False), {
        "name": binary.name,
        "sha256": _sha256(binary),
        "source": "binary",
    }


def _analysis_address(frame, default_arch, mapped_base, runtime_base):
    address = frame["address"]
    if runtime_base is not None:
        if address < runtime_base:
            return None
        address = address - runtime_base + mapped_base
    # angr represents Thumb code with bit zero set. Unicorn code hooks report
    # the aligned instruction address, so try both forms during CFG lookup.
    thumb = frame.get("arch", default_arch) in (ARCH.ARM16, ARCH.ARM16BE, ARCH.ARM_MCLASS)
    return address, thumb


def _runtime_address(address, mapped_base, runtime_base):
    if runtime_base is None:
        return address
    return address - mapped_base + runtime_base


def build_decompilation(
    trace,
    binary=None,
    *,
    blob=False,
    base_address=None,
    entry_point=None,
    runtime_base=None,
    max_functions=MAX_FUNCTIONS,
):
    """Run angr and return bounded, viewer-ready decompilation metadata."""
    try:
        import angr
    except ImportError as exc:
        raise RuntimeError(
            "angr is not installed; use Python 3.12+ and install requirements-decompiler.txt"
        ) from exc

    logging.getLogger().setLevel(logging.ERROR)
    project, binary_info = _load_project(
        angr,
        binary,
        trace,
        blob=blob,
        base_address=base_address,
        entry_point=entry_point,
    )
    cfg = project.analyses.CFGFast(normalize=True)
    mapped_base = project.loader.main_object.mapped_base
    if binary is None and runtime_base is not None:
        raise ValueError(
            "--runtime-base requires a binary; trace bytes already use runtime addresses"
        )
    matches = {}
    unmapped = []
    for frame in trace.frames:
        translated = _analysis_address(frame, trace.arch, mapped_base, runtime_base)
        if translated is None:
            unmapped.append(frame["address"])
            continue
        address, thumb = translated
        node = cfg.model.get_any_node(address | int(thumb), anyaddr=True)
        if node is None and thumb:
            node = cfg.model.get_any_node(address, anyaddr=True)
        if node is None or node.function_address is None:
            unmapped.append(frame["address"])
            continue
        matches.setdefault(node.function_address, set()).add(frame["address"])
    if not matches:
        hint = (
            " Check --runtime-base if Unicorn rebased the executable."
            if binary is not None and not blob
            else ""
        )
        raise ValueError(f"No traced instruction belongs to a function recovered by angr.{hint}")
    if len(matches) > max_functions:
        raise ValueError(
            f"Trace reaches {len(matches)} functions; increase --max-functions above {max_functions}"
        )

    functions = []
    failures = []
    for function_address in sorted(matches):
        function = cfg.kb.functions.get_by_addr(function_address)
        observed = [hex(address) for address in sorted(matches[function_address])]
        runtime_address = _runtime_address(function_address, mapped_base, runtime_base)
        if function is None:
            failures.append(
                {
                    "address": hex(runtime_address),
                    "name": f"sub_{runtime_address:x}",
                    "observed_addresses": observed,
                    "reason": "angr recovered a CFG node without a function",
                }
            )
            continue
        name = function.name or f"sub_{runtime_address:x}"
        try:
            result = project.analyses.Decompiler(function, cfg=cfg.model)
            pseudocode = result.codegen.text if result.codegen is not None else ""
            if not pseudocode.strip():
                raise RuntimeError("angr produced no pseudocode")
            functions.append(
                {
                    "address": hex(runtime_address),
                    "analysis_address": hex(function_address),
                    "name": name,
                    "observed_addresses": observed,
                    "pseudocode": pseudocode,
                }
            )
        except Exception as exc:  # angr failures should not discard other functions.
            failures.append(
                {
                    "address": hex(runtime_address),
                    "name": name,
                    "observed_addresses": observed,
                    "reason": str(exc) or type(exc).__name__,
                }
            )
    return {
        "version": DECOMPILATION_VERSION,
        "engine": {"name": "angr", "version": getattr(angr, "__version__", "unknown")},
        "binary": {
            **binary_info,
            "architecture": project.arch.name,
            "mapped_base": hex(mapped_base),
            "runtime_base": hex(runtime_base) if runtime_base is not None else None,
        },
        "functions": functions,
        "failures": failures,
        "unmapped_addresses": [hex(address) for address in sorted(set(unmapped))],
    }


def enrich_trace(
    trace_path,
    output_path,
    *,
    binary_path=None,
    force=False,
    **options,
):
    trace_path = Path(trace_path)
    binary_path = Path(binary_path) if binary_path is not None else None
    output_path = Path(output_path)
    if not trace_path.is_file():
        raise ValueError(f"Trace does not exist: {trace_path}")
    if binary_path is not None and not binary_path.is_file():
        raise ValueError(f"Binary does not exist: {binary_path}")
    protected = {trace_path.resolve()}
    if binary_path is not None:
        protected.add(binary_path.resolve())
    if output_path.resolve() in protected:
        raise ValueError("Output must be a new file")
    if output_path.exists() and not force:
        raise ValueError(f"Output already exists: {output_path} (use --force to replace it)")
    trace = TraceReader().load(trace_path)
    decompilation = build_decompilation(trace, binary_path, **options)
    metadata = dict(trace.metadata)
    metadata["decompilation"] = decompilation
    output_path.write_bytes(trace.dump(version=3, metadata=metadata))
    return decompilation


def main(argv=None):
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("trace", type=Path, help="Input .emtr trace")
    parser.add_argument(
        "binary",
        nargs="?",
        type=Path,
        help="Optional executable or raw code image; trace instruction bytes are used when omitted",
    )
    parser.add_argument(
        "-o",
        "--output",
        type=Path,
        help="Output path (default: TRACE.decompiled.emtr)",
    )
    parser.add_argument(
        "--runtime-base", type=parse_address, help="Address where Unicorn loaded the image"
    )
    parser.add_argument("--blob", action="store_true", help="Treat BINARY as a raw code image")
    parser.add_argument(
        "--base-address", type=parse_address, help="Address represented by byte zero of a blob"
    )
    parser.add_argument("--entry-point", type=parse_address, help="Entry address for a blob")
    parser.add_argument("--max-functions", type=int, default=MAX_FUNCTIONS)
    parser.add_argument("--force", action="store_true", help="Replace an existing output file")
    args = parser.parse_args(argv)
    if not 1 <= args.max_functions <= 4096:
        parser.error("--max-functions must be between 1 and 4096")
    output = args.output or args.trace.with_name(f"{args.trace.stem}.decompiled.emtr")
    try:
        result = enrich_trace(
            args.trace,
            output,
            binary_path=args.binary,
            force=args.force,
            blob=args.blob,
            base_address=args.base_address,
            entry_point=args.entry_point,
            runtime_base=args.runtime_base,
            max_functions=args.max_functions,
        )
    except (OSError, RuntimeError, ValueError) as exc:
        parser.exit(1, f"emu_decompiler: {exc}\n")
    print(
        f"Embedded {len(result['functions'])} function(s) from {result['binary']['name']} → {output}"
    )
    if result["failures"]:
        print(
            f"angr could not decompile {len(result['failures'])} mapped function(s).",
            file=sys.stderr,
        )
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
