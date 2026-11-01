"""Mutation fuzzing of the capture pipeline.

Default: ~300 cases (a few seconds). ``FAULTLINE_FUZZ_CASES=5000`` for a long
run, ``FAULTLINE_FUZZ_SEED`` to reproduce a run. The only exception allowed to
escape the pipeline is ``CaptureError``; each case must finish in bounded time.
"""

from __future__ import annotations

import os
import random

import pytest

from faultline.capture.reader import CaptureError
from tests import fuzzing

CASES = int(os.environ.get("FAULTLINE_FUZZ_CASES", "300"))
SEED = int(os.environ.get("FAULTLINE_FUZZ_SEED", "20261101"))
MAX_SECONDS_PER_CASE = 3.0


@pytest.fixture(scope="module")
def seeds():
    return fuzzing.seed_captures()


def test_seeds_are_valid_captures(tmp_path, seeds):
    """Sanity: every seed parses cleanly, otherwise the fuzzer would be fuzzing garbage."""
    for s in seeds:
        p = tmp_path / s.name
        p.write_bytes(s.data)
        res = fuzzing.run_case(str(p), s.name, "none", run_engine=False)
        assert res.ok, (s.name, repr(res.crash))
        assert res.capture_error is None
        assert res.packets >= 4, s.name
        if fuzzing.stages_available()["decode"]:
            assert res.decoded == res.packets
            # a hand-made valid capture should decode (almost) without malformed layers
            assert res.malformed <= 2, (s.name, res.malformed)


def _run(tmp_path, seeds, cases: int, run_engine: bool):
    rng = random.Random(SEED)
    crashes = []
    slow = []
    for i in range(cases):
        seed = seeds[i % len(seeds)]
        kind, data = fuzzing.mutate(seed.data, rng)
        p = tmp_path / f"case{i}.bin"
        p.write_bytes(data)
        res = fuzzing.run_case(str(p), seed.name, kind, run_engine=run_engine)
        if not res.ok:
            crashes.append((i, seed.name, kind, res.stage, repr(res.crash)))
            (tmp_path / f"crash{i}.bin").write_bytes(data)
        if res.seconds > MAX_SECONDS_PER_CASE:
            slow.append((i, seed.name, kind, res.seconds))
        p.unlink()
    assert not crashes, f"{len(crashes)} crash(es), first: {crashes[:3]} (seed={SEED}; crash files in {tmp_path})"
    assert not slow, f"cases over {MAX_SECONDS_PER_CASE}s: {slow[:5]}"


def test_fuzz_reader_and_decoder(tmp_path, seeds):
    _run(tmp_path, seeds, CASES, run_engine=False)


def test_fuzz_full_pipeline_with_engine(tmp_path, seeds):
    if not fuzzing.stages_available()["engine"]:
        pytest.skip("faultline.engine.analyze not available yet")
    _run(tmp_path, seeds, max(20, CASES // 5), run_engine=True)


def test_decode_handles_every_truncation_of_each_seed_frame(seeds):
    """Deterministic complement to the random fuzzer: feed every prefix of every frame."""
    decode = pytest.importorskip("faultline.capture.decode").decode
    from faultline.capture.reader import Frame

    frames = fuzzing.seed_frames() + fuzzing.sll_frames()
    for no, (ts, raw) in enumerate(frames, 1):
        linktype = 113 if no > len(fuzzing.seed_frames()) else 1
        for cut in range(len(raw) + 1):
            pkt = decode(Frame(no, ts, len(raw), linktype, raw[:cut]))
            assert pkt is None or pkt.no == no
            if pkt is not None and hasattr(pkt, "summary"):
                pkt.summary()


def test_capture_error_is_the_only_allowed_exception_type():
    assert issubclass(CaptureError, Exception) and not issubclass(CaptureError, (ValueError, OSError))
