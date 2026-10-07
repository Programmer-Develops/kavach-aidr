"""
train.py — Train and evaluate VulnGraphSAGE on CVEfixes-Python functions.

Input : data/processed/python_functions.jsonl  (from prepare_cvefixes.py)
        one JSON object per line:
        {"id", "code", "label" (1 = vulnerable, 0 = fixed), "project", "cwe", "pair"}
Output: models/vulngnn_cvefixes.pt   (weights + decision threshold)
        reports/vulngnn_eval.json    (held-out metrics, project-disjoint split)

Split policy: split by *project* (repository), so no project contributes
functions to more than one of train / val / test. Before/after versions of
the same fix always stay together.
"""

from __future__ import annotations

import argparse
import json
import pickle
import random
import time
from pathlib import Path

import torch
import torch.nn.functional as F

from kavach.vuln_gnn.cpg import build_cpg
from kavach.vuln_gnn.graphsage import VulnGraphSAGE, collate

ROOT = Path(__file__).resolve().parents[2]
DATA = ROOT / "data" / "processed" / "python_functions.jsonl"
CACHE = ROOT / "data" / "processed" / "cpg_cache.pkl"
MODEL_OUT = ROOT / "models" / "vulngnn_cvefixes.pt"
REPORT_OUT = ROOT / "reports" / "vulngnn_eval.json"


def load_graphs():
    if CACHE.exists():
        with open(CACHE, "rb") as f:
            return pickle.load(f)
    rows, skipped = [], 0
    with open(DATA, encoding="utf-8") as f:
        for i, line in enumerate(f):
            try:
                r = json.loads(line)
            except json.JSONDecodeError as e:
                print(f"JSON Error on line {i}: {e}")
                print(f"Line content: {repr(line)}")
                continue
            g = build_cpg(r["code"])
            if g is None:
                skipped += 1
                continue
            rows.append({"id": r["id"], "x": g.x, "edges": g.edges, "label": r["label"],
                         "project": r["project"], "cwe": r.get("cwe", ""), "pair": r.get("pair", r["id"])})
    print(f"CPGs built: {len(rows)}  skipped (unparseable / too large): {skipped}")
    with open(CACHE, "wb") as f:
        pickle.dump(rows, f)
    return rows


def split_by_project(rows, seed=42, frac=(0.70, 0.15, 0.15)):
    projects = sorted({r["project"] for r in rows})
    rng = random.Random(seed)
    rng.shuffle(projects)
    n = len(projects)
    a, b = int(frac[0] * n), int((frac[0] + frac[1]) * n)
    part = {p: 0 for p in projects[:a]}
    part.update({p: 1 for p in projects[a:b]})
    part.update({p: 2 for p in projects[b:]})
    out = ([], [], [])
    for r in rows:
        out[part[r["project"]]].append(r)
    return out


def batches(rows, bs, shuffle):
    idx = list(range(len(rows)))
    if shuffle:
        random.shuffle(idx)
    for i in range(0, len(idx), bs):
        chunk = [rows[j] for j in idx[i:i + bs]]
        yield collate([(r["x"], r["edges"], r["label"]) for r in chunk])


@torch.no_grad()
def predict(model, rows, bs=128):
    model.eval()
    probs = []
    for x, ei, b, y, n in batches(rows, bs, False):
        probs.extend(torch.sigmoid(model(x, ei, b, n)).tolist())
    return probs


def metrics(labels, probs, thr):
    tp = sum(1 for l, p in zip(labels, probs) if l == 1 and p >= thr)
    fp = sum(1 for l, p in zip(labels, probs) if l == 0 and p >= thr)
    fn = sum(1 for l, p in zip(labels, probs) if l == 1 and p < thr)
    tn = sum(1 for l, p in zip(labels, probs) if l == 0 and p < thr)
    prec = tp / (tp + fp) if tp + fp else 0.0
    rec = tp / (tp + fn) if tp + fn else 0.0
    f1 = 2 * prec * rec / (prec + rec) if prec + rec else 0.0
    acc = (tp + tn) / max(1, len(labels))
    return {"threshold": thr, "tp": tp, "fp": fp, "fn": fn, "tn": tn,
            "precision": prec, "recall": rec, "f1": f1, "accuracy": acc}


def best_threshold(labels, probs, objective="f1", min_recall=0.0):
    best, best_thr = -1.0, 0.5
    for t in [i / 100 for i in range(5, 96)]:
        m = metrics(labels, probs, t)
        if m["recall"] < min_recall:
            continue
        s = m[objective]
        if s > best:
            best, best_thr = s, t
    return best_thr


def auc(labels, probs):
    pos = [p for l, p in zip(labels, probs) if l == 1]
    neg = [p for l, p in zip(labels, probs) if l == 0]
    if not pos or not neg:
        return 0.0
    wins = 0.0
    for p in pos:
        for q in neg:
            wins += 1.0 if p > q else 0.5 if p == q else 0.0
    return wins / (len(pos) * len(neg))


def bootstrap_ci(labels, probs, thr, n=1000, seed=0):
    rng = random.Random(seed)
    N = len(labels)
    ps, fs = [], []
    for _ in range(n):
        ids = [rng.randrange(N) for _ in range(N)]
        m = metrics([labels[i] for i in ids], [probs[i] for i in ids], thr)
        ps.append(m["precision"]); fs.append(m["f1"])
    ps.sort(); fs.sort()
    lo, hi = int(0.025 * n), int(0.975 * n)
    return {"precision_ci95": [ps[lo], ps[hi]], "f1_ci95": [fs[lo], fs[hi]]}


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--epochs", type=int, default=40)
    ap.add_argument("--bs", type=int, default=64)
    ap.add_argument("--lr", type=float, default=1e-3)
    ap.add_argument("--hidden", type=int, default=64)
    ap.add_argument("--seed", type=int, default=42)
    ap.add_argument("--objective", default="f1")
    args = ap.parse_args()

    random.seed(args.seed); torch.manual_seed(args.seed)
    rows = load_graphs()
    train, val, test = split_by_project(rows, args.seed)
    for name, part in (("train", train), ("val", val), ("test", test)):
        pos = sum(r["label"] for r in part)
        print(f"{name:5s}: {len(part):6d} graphs  vulnerable={pos}  safe={len(part) - pos}  "
              f"projects={len({r['project'] for r in part})}")

    n_pos = sum(r["label"] for r in train)
    pos_weight = torch.tensor((len(train) - n_pos) / max(1, n_pos))
    model = VulnGraphSAGE(hidden=args.hidden)
    opt = torch.optim.Adam(model.parameters(), lr=args.lr, weight_decay=1e-5)

    best_val, best_state, best_thr, patience = -1.0, None, 0.5, 0
    val_labels = [r["label"] for r in val]
    for ep in range(1, args.epochs + 1):
        model.train()
        t0, tot = time.time(), 0.0
        for x, ei, b, y, n in batches(train, args.bs, True):
            opt.zero_grad()
            loss = F.binary_cross_entropy_with_logits(model(x, ei, b, n), y, pos_weight=pos_weight)
            loss.backward()
            opt.step()
            tot += loss.item() * n
        vp = predict(model, val)
        thr = best_threshold(val_labels, vp, args.objective)
        vm = metrics(val_labels, vp, thr)
        score = vm[args.objective]
        print(f"ep {ep:02d} loss {tot / len(train):.4f}  val P {vm['precision']:.3f} "
              f"R {vm['recall']:.3f} F1 {vm['f1']:.3f} AUC {auc(val_labels, vp):.3f} "
              f"thr {thr:.2f}  ({time.time() - t0:.0f}s)")
        if score > best_val:
            best_val, best_thr, patience = score, thr, 0
            best_state = {k: v.clone() for k, v in model.state_dict().items()}
        else:
            patience += 1
            if patience >= 8:
                print("early stop")
                break

    model.load_state_dict(best_state)
    MODEL_OUT.parent.mkdir(exist_ok=True)
    torch.save({"state_dict": best_state, "threshold": best_thr, "hidden": args.hidden}, MODEL_OUT)

    test_labels = [r["label"] for r in test]
    tp_ = predict(model, test)
    tm = metrics(test_labels, tp_, best_thr)
    tm["auc"] = auc(test_labels, tp_)
    tm.update(bootstrap_ci(test_labels, tp_, best_thr))
    tm["n_test"] = len(test)
    tm["n_test_projects"] = len({r["project"] for r in test})

    # Operating points: high-precision threshold chosen on validation only.
    vp = predict(model, val)
    hp_thr = best_threshold(val_labels, vp, "precision", min_recall=0.30)
    hp = metrics(test_labels, tp_, hp_thr)
    result = {"test_at_best_f1_threshold": tm, "test_at_high_precision_threshold": hp,
              "train_size": len(train), "val_size": len(val), "args": vars(args)}
    REPORT_OUT.parent.mkdir(exist_ok=True)
    REPORT_OUT.write_text(json.dumps(result, indent=2))
    print(json.dumps(result, indent=2))


if __name__ == "__main__":
    main()
