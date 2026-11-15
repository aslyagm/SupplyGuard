import json

import pytest

from supplyguard import slopsquat


def test_run_experiment_writes_one_record_per_grid_cell(tmp_path, monkeypatch):
    calls = []

    def fake_raw(task, model, api_key, temperature, prompt_variant, timeout=0):
        calls.append((task, prompt_variant, temperature))
        return json.dumps([f"{prompt_variant}-pkg"]), f"prompt for {task}"

    monkeypatch.setattr(slopsquat, "ask_llm_raw", fake_raw)
    out = tmp_path / "run.jsonl"
    count = slopsquat.run_experiment(
        ["task one", "task two"],
        out,
        model="test-model",
        repeats=2,
        temperatures=(0.0, 0.7),
        variants=("plain", "minimal"),
        verbose=False,
    )
    assert count == 2 * 2 * 2 * 2
    assert len(calls) == count
    records = [json.loads(line) for line in out.read_text(encoding="utf-8").splitlines()]
    assert len(records) == count
    assert records[0]["model"] == "test-model"
    assert records[0]["suggested"] == ["plain-pkg"]
    assert records[0]["prompt"] == "prompt for task one"
    assert {r["repeat"] for r in records} == {1, 2}
    assert {r["temperature"] for r in records} == {0.0, 0.7}


def test_run_experiment_records_errors_and_continues(tmp_path, monkeypatch):
    def flaky(task, model, api_key, temperature, prompt_variant, timeout=0):
        if task == "bad":
            raise RuntimeError("rate limited")
        return '["requests"]', "prompt"

    monkeypatch.setattr(slopsquat, "ask_llm_raw", flaky)
    out = tmp_path / "run.jsonl"
    count = slopsquat.run_experiment(
        ["bad", "good"], out, repeats=1, verbose=False
    )
    assert count == 2
    records = [json.loads(line) for line in out.read_text(encoding="utf-8").splitlines()]
    assert "rate limited" in records[0]["error"]
    assert records[1]["error"] == ""
    assert records[1]["suggested"] == ["requests"]


def test_run_experiment_appends(tmp_path, monkeypatch):
    monkeypatch.setattr(
        slopsquat, "ask_llm_raw",
        lambda *a, **k: ('["numpy"]', "prompt"),
    )
    out = tmp_path / "run.jsonl"
    slopsquat.run_experiment(["a"], out, verbose=False)
    slopsquat.run_experiment(["b"], out, append=True, verbose=False)
    assert len(out.read_text(encoding="utf-8").splitlines()) == 2


def test_run_experiment_validates_arguments(tmp_path):
    with pytest.raises(ValueError, match="repeats"):
        slopsquat.run_experiment(["a"], tmp_path / "x", repeats=0)
    with pytest.raises(ValueError, match="variant"):
        slopsquat.run_experiment(["a"], tmp_path / "x", variants=("nope",))
    with pytest.raises(ValueError, match="temperature"):
        slopsquat.run_experiment(["a"], tmp_path / "x", temperatures=(3.0,))
    with pytest.raises(ValueError, match="task"):
        slopsquat.run_experiment([], tmp_path / "x")


def test_ask_llm_requires_api_key(monkeypatch):
    monkeypatch.delenv("GROQ_API_KEY", raising=False)
    with pytest.raises(RuntimeError, match="GROQ_API_KEY"):
        slopsquat.ask_llm("task")


def test_load_tasks_skips_comments(tmp_path):
    path = tmp_path / "tasks.txt"
    path.write_text("# header\ntask one\n\n  task two  \n# note\n", encoding="utf-8")
    assert slopsquat.load_tasks(path) == ["task one", "task two"]
