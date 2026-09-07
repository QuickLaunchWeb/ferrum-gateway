#!/usr/bin/env python3
"""Preserve RR benchmark binaries and provenance; never execute a process."""
from __future__ import annotations

import argparse
import hashlib
import json
import os
import shutil
from pathlib import Path


def digest(path: Path) -> str:
    result = hashlib.sha256()
    with path.open("rb") as stream:
        for chunk in iter(lambda: stream.read(1024 * 1024), b""):
            result.update(chunk)
    return result.hexdigest()


def build_artifacts(records: list[dict], source: Path) -> tuple[dict, dict]:
    """Reject output from the original checkout or an unintended source tree."""
    selected = []
    for name, manifest in (("rr_selection", source / "tests/performance/mesh/Cargo.toml"),
                           ("ferrum_edge", source / "Cargo.toml")):
        matches = [row for row in records if row.get("reason") == "compiler-artifact"
                   and row.get("target", {}).get("name") == name
                   and (row.get("executable") if name == "rr_selection"
                        else row.get("target", {}).get("kind") == ["lib"])]
        if len(matches) != 1 or Path(matches[0]["manifest_path"]) != manifest:
            raise ValueError(f"expected exactly one {name} artifact from {manifest}")
        selected.append(matches[0])
    return selected[0], selected[1]


def self_test() -> int:
    source = Path("/runner/comparison/source")
    bench = {"reason": "compiler-artifact", "target": {"name": "rr_selection"},
             "executable": "/runner/target/rr", "manifest_path": str(source / "tests/performance/mesh/Cargo.toml")}
    library = {"reason": "compiler-artifact", "target": {"name": "ferrum_edge", "kind": ["lib"]},
               "manifest_path": str(source / "Cargo.toml")}
    assert build_artifacts([bench, library], source) == (bench, library)
    for records in ([bench], [bench, bench, library],
                    [dict(bench, manifest_path="/wrong/Cargo.toml"), library],
                    [bench, dict(library, manifest_path="/wrong/Cargo.toml")]):
        try:
            build_artifacts(records, source)
        except ValueError:
            pass
        else:
            raise AssertionError("missing, duplicate or foreign build evidence must fail")
    print("RR build source identity self-tests passed")
    return 0


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("mode", choices=("record-build", "record-round", "self-test"))
    args = parser.parse_args()
    if args.mode == "self-test":
        return self_test()
    root = Path(os.environ["RR_COMPARISON_ROOT"])
    output = Path(os.environ["RR_COMPARISON_OUTPUT"])
    work = Path(os.environ["RR_COMPARISON_WORK"])
    role = os.environ["RR_COMPARISON_ROLE"]
    if role not in ("baseline", "candidate"):
        raise ValueError("invalid comparison role")
    provenance_path = output / "provenance.json"
    if provenance_path.exists():
        provenance = json.loads(provenance_path.read_text())
    else:
        provenance = {
            "baseline_sha": os.environ["RR_BASE_SHA"],
            "candidate_sha": os.environ["RR_CANDIDATE_SHA"],
            "harness_sha256": digest(root / "tests/performance/mesh/benches/rr_selection.rs"),
            "binaries": {}, "order": [],
        }
    if args.mode == "record-build":
        records = [json.loads(line) for line in (output / f"{role}-compile.jsonl").read_text().splitlines()]
        source = Path(os.environ["RR_COMPARISON_SOURCE"])
        artifact, library = build_artifacts(records, source)
        binary = work / role
        shutil.copy2(Path(artifact["executable"]), binary)
        provenance["binaries"][role] = {
            "binary_sha256": digest(binary),
            "source_path": str(source),
            "benchmark_package_id": artifact["package_id"],
            "library_package_id": library["package_id"],
            "library_filenames": library["filenames"],
            "compile_seconds": float((output / f"{role}-compile.time").read_text()),
        }
    else:
        round_number = int(os.environ["RR_COMPARISON_ROUND"])
        if round_number not in (1, 2, 3):
            raise ValueError("invalid comparison round")
        provenance["order"].append({"role": role, "round": round_number})
    provenance_path.write_text(json.dumps(provenance, indent=2) + "\n")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
