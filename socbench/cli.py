"""Command line: socbench generate | run | report."""
import argparse
import json
import re
from pathlib import Path

from .agents import make_agent
from .attacks import generate
from .defenses import REGISTRY
from .runner import leaderboard, load_runs, run, save
from .scoring import summarize


def _load_cases(path: Path) -> list[dict]:
    return [json.loads(line) for line in path.read_text(encoding="utf-8").splitlines() if line.strip()]


def main(argv=None):
    parser = argparse.ArgumentParser(prog="socbench", description="Prompt-injection benchmark for SOC triage agents.")
    sub = parser.add_subparsers(dest="command", required=True)

    g = sub.add_parser("generate", help="write the attack corpus")
    g.add_argument("--out", default="data/cases.jsonl")
    g.add_argument("--per-combo", type=int, default=1, help="scenarios per goal/technique/carrier combination")

    r = sub.add_parser("run", help="run an agent against a defense")
    r.add_argument("--agent", required=True, help="ideal | oracle-victim | anthropic:<model> | openai:<model>[@base_url]")
    r.add_argument("--defense", default="none", help="one of: all, " + ", ".join(REGISTRY))
    r.add_argument("--cases", default="data/cases.jsonl")
    r.add_argument("--runs", default="runs")
    r.add_argument("--workers", type=int, default=1)
    r.add_argument("--only", help="comma-separated case ids to rerun, e.g. 0099,0241. Prints how each run ended and saves under runs/debug")
    r.add_argument("--family", choices=["instruction", "evidence", "refusal_bait"], help="only run attacks of this family")
    r.add_argument("--limit", type=int, help="run an evenly spread sample of N cases (cheap smoke test)")

    p = sub.add_parser("report", help="build the leaderboard from saved runs")
    p.add_argument("--runs", default="runs")
    p.add_argument("--out", default="LEADERBOARD.md")

    args = parser.parse_args(argv)
    if args.command == "generate":
        cases = generate(args.per_combo)
        out = Path(args.out)
        out.parent.mkdir(parents=True, exist_ok=True)
        out.write_text("".join(json.dumps(c, ensure_ascii=False) + "\n" for c in cases), encoding="utf-8")
        kinds = {k: sum(1 for c in cases if c["kind"] == k) for k in ("attack", "control", "clean")}
        print(f"wrote {len(cases)} cases to {out}: {kinds}")
    elif args.command == "run":
        cases = _load_cases(Path(args.cases))
        if not cases:
            raise SystemExit(f"{args.cases} is empty. Run 'generate' first.")
        if args.family:
            cases = [c for c in cases if c.get("family") == args.family]
        if args.only:
            wanted = {c.zfill(4) for c in re.split(r"[,\s]+", args.only.strip()) if c}
            cases = [c for c in cases if c["case_id"] in wanted]
            if not cases:
                raise SystemExit(f"No case matched --only {args.only!r}. In PowerShell, put the list in quotes.")
        elif args.limit and args.limit < len(cases):
            step = len(cases) / args.limit   # spread the sample so it includes attacks, controls and clean cases
            cases = [cases[int(i * step)] for i in range(args.limit)]
        agent = make_agent(args.agent)
        for name in (REGISTRY if args.defense == "all" else [args.defense]):
            results = run(cases, agent, name, args.workers)
            out_dir = Path(args.runs) / "debug" if args.only else Path(args.runs) / args.family if args.family else Path(args.runs)
            path = save(results, agent.name, name, out_dir)
            s = summarize(results)
            print(f"{agent.name} + {name}: attack success {s['asr']}%, utility under attack {s['utility_under_attack']}%, "
                  f"clean utility {s['clean_utility']}%, no verdict {s['incomplete']}, errors {s['errors']} -> {path}")
            if args.only:
                for r in results:
                    print(f"\n--- case {r['case_id']} ({r['scenario']}, {r['goal']}, {r['technique']}, {r['carrier']})")
                    print(f"attack_success: {r['attack_success']}  payload seen: {r['exposed']}  unsafe: {r['unsafe_actions']}")
                    print(f"verdict: {r['verdict']}\nsteps: {r['steps']}  stop_reason: {r['stop_reason']}  error: {r['error']}")
                    print(f"last text from the model: {r['final_text']!r}")
    else:
        text = leaderboard(load_runs(Path(args.runs)))
        Path(args.out).write_text(text, encoding="utf-8")
        print(f"wrote {args.out}")


if __name__ == "__main__":
    main()
