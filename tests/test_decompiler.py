import importlib.util

import pytest

from architectures import ARCH
from emu_decompiler import enrich_trace
from emu_tracer import TraceReader
from example_trace import SAMPLES, make_trace


@pytest.mark.skipif(importlib.util.find_spec("angr") is None, reason="optional angr dependency")
def test_angr_decompilation_is_embedded_and_maps_trace_addresses(tmp_path):
    trace_path = tmp_path / "input.emtr"
    binary_path = tmp_path / "sample.bin"
    output_path = tmp_path / "output.emtr"
    trace_path.write_bytes(make_trace().dump())
    binary_path.write_bytes(SAMPLES[ARCH.X86_64])

    result = enrich_trace(
        trace_path,
        output_path,
        binary_path=binary_path,
        blob=True,
        base_address=0x10000,
        entry_point=0x10000,
    )

    assert result["engine"]["name"] == "angr"
    assert result["binary"]["name"] == "sample.bin"
    assert result["binary"]["source"] == "binary"
    assert result["failures"] == []
    assert len(result["functions"]) == 1
    function = result["functions"][0]
    assert function["address"] == "0x10000"
    assert "while" in function["pseudocode"]
    assert "0x10017" in function["observed_addresses"]

    enriched = TraceReader().load(output_path)
    original = TraceReader().load(trace_path)
    assert enriched.version == 3
    assert enriched.frames == original.frames
    assert enriched.metadata["decompilation"] == result
    with pytest.raises(ValueError, match="already exists"):
        enrich_trace(
            trace_path,
            output_path,
            binary_path=binary_path,
            blob=True,
            base_address=0x10000,
        )

    trace_only_path = tmp_path / "trace-only.emtr"
    trace_only = enrich_trace(trace_path, trace_only_path)
    assert trace_only["binary"]["source"] == "trace"
    assert "while" in trace_only["functions"][0]["pseudocode"]
