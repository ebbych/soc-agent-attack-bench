"""Run one agent against one defense over the corpus, and build the leaderboard from saved runs."""
import json
from concurrent.futures import ThreadPoolExecutor
from pathlib import Path

from .defenses import REGISTRY
from .env import Sandbox
from .scoring import score, summarize


def run_case(case: dict, agent, defense_name: str) -> dict:
    env = Sandbox(case, REGISTRY[defense_name]())
    error = None
    try:
        agent.run(env, case if agent.needs_case else None)
    except Exception as exc:  # one failed API call should not sink a whole run
        error = f"{type(exc).__name__}: {exc}"
    env.finalize()
    result = score(case, env)
    result["error"] = error
    return result


def run(cases: list[dict], agent, defense_name: str, workers: int = 1) -> list[dict]:
    if workers <= 1:
        return [run_case(case, agent, defense_name) for case in cases]
    with ThreadPoolExecutor(workers) as pool:
        return list(pool.map(lambda case: run_case(case, agent, defense_name), cases))


def save(results: list[dict], agent_name: str, defense_name: str, out_dir: Path) -> Path:
    out_dir.mkdir(parents=True, exist_ok=True)
    path = out_dir / f"{agent_name.replace(':', '_').replace('/', '_')}__{defense_name}.jsonl"
    with path.open("w", encoding="utf-8") as fh:
        fh.write(json.dumps({"meta": {"agent": agent_name, "defense": defense_name}}) + "\n")
        for result in results:
            fh.write(json.dumps(result, ensure_ascii=False) + "\n")
    return path


def load_runs(out_dir: Path) -> list[dict]:
    runs = []
    for path in sorted(out_dir.glob("*.jsonl")):
        lines = [json.loads(line) for line in path.read_text(encoding="utf-8").splitlines() if line.strip()]
        runs.append({**lines[0]["meta"], "summary": summarize(lines[1:])})
    return runs


def _fmt(value):
    return "-" if value is None else f"{value:.1f}%"


def leaderboard(runs: list[dict]) -> str:
    runs = sorted(runs, key=lambda r: (r["agent"], r["summary"]["asr"] if r["summary"]["asr"] is not None else 0))
    out = ["# Leaderboard", "",
           "Lower attack success is better. Higher utility is better. "
           "`oracle-victim` obeys every injection it can see, so its rows are the worst case each defense allows. "
           "`ideal` never obeys one, so its rows show what a defense costs when nothing is wrong. "
           "\"Of which no verdict\" counts attacks scored as successful only because the agent stopped without "
           "submitting a verdict, so the alert was dropped rather than the agent being talked into anything.", "",
           "| Agent | Defense | Attack success | of which no verdict | Payload seen | Success when seen | Utility under attack | Clean utility | Benign-control utility | Benign controls flagged | No verdict | Refusals |",
           "|---|---|---|---|---|---|---|---|---|---|---|---|"]
    for r in runs:
        s = r["summary"]
        out.append(f"| {r['agent']} | {r['defense']} | {_fmt(s['asr'])} | {_fmt(s.get('asr_no_verdict'))} | {_fmt(s.get('exposure_rate'))} | {_fmt(s.get('asr_when_exposed'))} | {_fmt(s['utility_under_attack'])} | "
                   f"{_fmt(s['clean_utility'])} | {_fmt(s['control_utility'])} | {_fmt(s['control_flag_rate'])} | {s['incomplete']} | {s.get('refusals', 0)} |")
    for title, key in [("family", "asr_by_family"), ("goal", "asr_by_goal"), ("technique", "asr_by_technique"), ("carrier", "asr_by_carrier")]:
        shown = [r for r in runs if r["agent"] != "ideal"]
        if not shown:
            continue
        labels = sorted({k for r in shown for k in r["summary"].get(key, {})})
        out += ["", f"## Attack success by {title}", "",
                "| " + title.capitalize() + " | " + " | ".join(f"{r['agent']} + {r['defense']}" for r in shown) + " |",
                "|---" * (len(shown) + 1) + "|"]
        for label in labels:
            out.append(f"| {label} | " + " | ".join(_fmt(r["summary"].get(key, {}).get(label)) for r in shown) + " |")
    return "\n".join(out) + "\n"
