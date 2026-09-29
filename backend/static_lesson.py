"""static_lesson.py — 検証済みの静的事実から、根拠付きの演習を作る。

ログ教材（explain.py）とは別の組み立てにする。共用するのは、画面側の
設問・証拠カード・採点・振り返りの部品と、`evidence.visible` / `pick_index`
だけ。ログの出来事（時刻・ホスト・実行）を模した項目は作らない。

設問は次の七種類（テンプレート）を候補にし、根拠が揃ったものだけを作る。

  * 文字列参照       命令 → Ghidra が保存した参照先の定義済み文字列
  * 文字列の参照元   定義済み文字列 → その文字列への参照命令を持つ関数
  * 直接呼び出し     呼び出し命令 → 一意に解決された呼び出し先の関数
  * 直接呼び出し元   関数 → その入口への直接呼び出し命令を持つ関数
  * 外部関数         外部関数（EXTERNAL 空間）の記録と、その識別情報
  * 外部関数の登録先 外部関数の記録 → 保存されているライブラリ名
  * 判断の限界       命令の記録 → その記録だけでは確認できないこと

どの設問も「正解はこの構造化された記録から一意に決まる」ことを、作った後に
`verify_quiz` で確かめてから採用する。誤答は、同じ文字列・同じ名前・同じ
アドレスを持たないものだけから選ぶ。単に似た名前や同じ文字列があるだけでは
正解にならない。

候補を作ったあと、`quiz_select.select` で 1 回の演習に出す設問（既定で最大
8 問）を選び、選んだ設問から段階を組み立てる。

言わないこと: 実行されたこと、呼ばれた回数や順序、悪性かどうか、ATT&CK の
手法。呼び出し命令が存在することは、実行時にその呼び出しが起きたことを
意味しない。
"""

from __future__ import annotations

import hashlib

import quiz_select
from evidence import pick_index, visible
from static_facts import MAX_INSTRUCTION, SCHEMA, StaticFacts

LESSON_PREFIX = "gen-gzf-"

#: 選択肢として出す文字列の最大長。これを超える文字列は、表示で切ると
#: 根拠（どの文字列か）が見えなくなるので、設問に使わない。
MAX_OPTION = 60
MAX_STRING_QUESTIONS = 2
MAX_CALL_QUESTIONS = 2
MAX_EXTERNAL_QUESTIONS = 1
MAX_REFERRER_QUESTIONS = 2
MAX_CALLER_QUESTIONS = 2
MAX_LIBRARY_QUESTIONS = 1
MAX_LIMITS_QUESTIONS = 1
OPTIONS = 4

#: 設問テンプレート。識別子 → (利用者に見せる呼び名, カテゴリ)。
TEMPLATES: dict[str, tuple[str, str]] = {
    "static.string-ref": ("命令が参照する文字列を読む", "static-string"),
    "static.string-referrer": ("文字列を参照する関数をたどる", "static-string"),
    "static.call": ("直接呼び出しの行き先を読む", "static-call"),
    "static.caller": ("直接呼び出し元の関数をたどる", "static-call"),
    "static.external": ("外部関数を見分ける", "static-external"),
    "static.external-library": ("外部関数の登録先を読む", "static-external"),
    "static.limits": ("記録から確認できないことを分ける", "static-limits"),
}

#: 上限を超える候補があるときの優先順（`quiz_select.select` を参照）。
TEMPLATE_PRIORITY = [
    "static.string-ref",
    "static.call",
    "static.external",
    "static.limits",
    "static.string-referrer",
    "static.caller",
    "static.external-library",
]

#: 同じ命令について、正方向と逆方向の設問。同じ根拠を使うなら並べない。
REVERSE_TEMPLATES = frozenset({
    frozenset({"static.string-ref", "static.string-referrer"}),
    frozenset({"static.call", "static.caller"}),
})

#: カテゴリ → 段階。段階は選んだ設問から、この順で組み立てる。
STAGES = (
    ("static-string", "static-strings"),
    ("static-call", "static-calls"),
    ("static-external", "static-externals"),
    ("static-limits", "static-limits"),
)

#: Ghidra がライブラリ名を持たない外部関数に付ける名前。実在のライブラリ名ではない。
UNKNOWN_LIBRARY = "<EXTERNAL>"

STORED = "stored"   # 証拠の確からしさ：「保存済みの解析情報に記録されている」


class NoQuestions(Exception):
    """根拠の揃った設問を 1 問も作れなかった。"""

    code = "no-questions"

    def __init__(self, reasons: list[str]):
        super().__init__("; ".join(reasons))
        self.reasons = reasons


def lesson_id(input_sha256: str) -> str:
    return LESSON_PREFIX + input_sha256[:16]


def show_addr(address: str) -> str:
    """`ram:0000000000101234` を `ram:00101234` のように短くする。桁は 8 桁まで残す。"""
    space, _, off = address.rpartition(":")
    off = off.lstrip("0").rjust(8, "0")
    return f"{space}:{off}"


def _quote(value: str) -> str:
    return f"「{visible(value, MAX_OPTION)}」"


class _Evidence:
    """静的な根拠。ID は入力と記録の位置から決まり、毎回同じになる。"""

    def __init__(self, facts: StaticFacts):
        self.facts = facts
        self.items: dict[str, dict] = {}
        self.program = visible(facts.program["name"], 120)

    def _add(self, kind: str, key: str, source: dict) -> str:
        digest = hashlib.sha256()
        for part in ("static", self.facts.input_sha256, kind, key):
            digest.update(part.encode("utf-8", "surrogateescape"))
            digest.update(b"\0")
        ident = "ev-" + digest.hexdigest()[:24]
        if ident not in self.items:
            self.items[ident] = {
                "id": ident,
                "kind": kind,
                "evidenceType": "static",
                "confidence": STORED,
                "source": {"program": self.program, **source},
            }
        return ident

    def instruction(self, function_id: str, address: str, text: str,
                    relation: str, target: str) -> str:
        fn = self.facts.functions[function_id]
        return self._add("instruction", address + "\0" + relation, {
            "function": visible(fn["name"], 120),
            "address": show_addr(address),
            "instruction": visible(text, MAX_INSTRUCTION),
            # 参照先・呼び出し先は、アドレスだけを書く。名前や文字列の中身は
            # 別の記録にあり、それを突き合わせるのが設問で問う読み方である。
            "reference": f"{relation}: {show_addr(target)}",
            "excerpt": visible(text, MAX_INSTRUCTION),
        })

    def string(self, sid: str) -> str:
        s = self.facts.strings[sid]
        return self._add("string", s["address"], {
            "function": None,
            "address": show_addr(s["address"]),
            "instruction": None,
            "reference": f"定義済み文字列（{s['length']} 文字）",
            "excerpt": _quote(s["value"]),
        })

    def function(self, fid: str) -> str:
        f = self.facts.functions[fid]
        return self._add("function", f["entry"], {
            "function": visible(f["name"], 120),
            "address": show_addr(f["entry"]),
            "instruction": None,
            "reference": "関数の入口（このプログラム内）",
            "excerpt": f"{visible(f['name'], 120)} @ {show_addr(f['entry'])}",
        })

    def external(self, eid: str) -> str:
        e = self.facts.externals[eid]
        lib = visible(e["library"] or "（ライブラリ名の記録なし）", 120)
        return self._add("external", e["address"], {
            "function": visible(e["name"], 120),
            "address": show_addr(e["address"]),
            "instruction": None,
            "reference": f"外部関数（登録先: {lib}）",
            "excerpt": f"{visible(e['name'], 120)} @ {show_addr(e['address'])} — {lib}",
        })


def _usable_instruction(text: str) -> bool:
    # 抽出側は上限で切る。上限ちょうどの長さは切られた可能性があるので使わない。
    return 0 < len(text) < MAX_INSTRUCTION and visible(text, MAX_INSTRUCTION) == text


def _usable_string(s: dict) -> bool:
    v = s["value"]
    return (not s["clipped"] and len(v.strip()) >= 3 and len(v) <= MAX_OPTION
            and visible(v, MAX_OPTION) == v)


def _plain_name(name: str) -> bool:
    return 0 < len(name) <= 80 and visible(name, 80) == name


def _choose(seed: str, items: list, count: int, key=None) -> list:
    """候補から決定的に count 件選ぶ。key が同じものは 2 件目以降を避ける。"""
    chosen, used = [], set()
    pool = list(items)
    start = pick_index(seed, len(pool)) if pool else 0
    ordered = pool[start:] + pool[:start]
    for item in ordered:
        k = key(item) if key else None
        if k is not None and k in used:
            continue
        chosen.append(item)
        if k is not None:
            used.add(k)
        if len(chosen) >= count:
            break
    return chosen


def _arrange(seed: str, right, wrong: list) -> tuple[list, int]:
    at = pick_index(seed, len(wrong) + 1)
    return wrong[:at] + [right] + wrong[at:], at


# ---------------------------------------------------------------------------
# 設問の検証（作ったあとに、構造化された記録から正解を確かめ直す）
# ---------------------------------------------------------------------------

#: その種類の設問の正解が一つだと言うために、欠けていてはいけない一覧。
#: 文字列参照: 参照の一覧が欠けていると、同じ命令が誤答の文字列も参照して
#:   いる（＝誤答も正解）可能性を否定できない。
#: 外部関数: 外部関数・関数の一覧が欠けていると、誤答に使ったプログラム内の
#:   関数と同じ名前の外部関数や thunk が一覧の外にある可能性を否定できない。
#: 直接呼び出しは、1 つの命令の行き先が 1 つに決まり、打ち切りで省かれるのは
#: 記録ごとなので、一覧が欠けても正解の一意性は崩れない。
#: 文字列の参照元: 参照の一覧が欠けていると、誤答に使った関数が同じ文字列を
#:   参照している（＝誤答も正解）可能性を否定できない。参照元の関数が一覧の
#:   外にあるときも、抽出側は参照を書かずに stringRefs の打ち切りとして記録する
#:   ので、stringRefs が完全なら、選択肢に出す関数の参照はすべて揃っている。
#: 直接呼び出し元: 同じく、呼び出しの一覧が欠けていると、誤答に使った関数が
#:   同じ関数を呼んでいる可能性を否定できない。呼び出し先・thunk の行き先が
#:   一覧の外にあるときも、抽出側は calls の打ち切りとして記録する。
#: 外部関数の登録先: 答えは対象の 1 レコードの `library` 欄で、1 レコードの
#:   登録先は 1 つしかない。ほかのレコードが欠けても、誤答が正解に変わる
#:   ことはない（誤答は実在するレコードの登録先から取る）。
#: 判断の限界: 選択肢の「確認できる事実」は対象のレコードそのものから
#:   確かめ、「確認できないこと」はどの一覧が揃っても静的な記録からは
#:   確かめられない主張なので、一覧の完全性に依らない。
REQUIRES_COMPLETE = {
    "string-ref": ("stringRefs",),
    "external": ("externals", "functions"),
    "call": (),
    "string-referrer": ("stringRefs",),
    "caller": ("calls",),
    "external-library": (),
    "limits": (),
}


def library_name(value: str | None) -> str:
    """記録された登録先。空欄・不明（`<EXTERNAL>`）・表示できない値は空文字。"""
    if not value or not value.strip() or value.strip() == UNKNOWN_LIBRARY:
        return ""
    return value if _plain_name(value) else ""


def _referrers(facts: StaticFacts, sid: str) -> set:
    return {r["function"] for r in facts.string_refs if r["string"] == sid}


def _callers(facts: StaticFacts, fid: str) -> tuple[set, set]:
    """関数 fid の入口を直接呼ぶ関数と、thunk を経て fid に解決される呼び出しを持つ関数。"""
    direct = {c["function"] for c in facts.calls
              if c["target"] == fid and c["resolvedTarget"] is None}
    via_thunk = {c["function"] for c in facts.calls if c["resolvedTarget"] == fid}
    return direct, via_thunk


def _fn_label(f: dict) -> str:
    return f"{visible(f['name'], 80)} @ {show_addr(f['entry'])}"


def verify_quiz(facts: StaticFacts, quiz: dict) -> bool:
    check = quiz.get("answerCheck") or {}
    if check.get("kind") not in REQUIRES_COMPLETE:
        return False
    if any(t in facts.truncated for t in REQUIRES_COMPLETE[check["kind"]]):
        return False
    ids = quiz.get("optionIds") or []
    if len(ids) != len(quiz.get("options") or []) or len(set(ids)) != len(ids):
        return False
    correct = quiz.get("correct")
    if not isinstance(correct, int) or not 0 <= correct < len(ids):
        return False
    kind = check.get("kind")
    if kind == "string-ref":
        refs = [r for r in facts.string_refs
                if r["from"] == check.get("from") and r["function"] == check.get("function")]
        answers = {r["string"] for r in refs}
        if ids[correct] not in answers or len(answers) != 1:
            return False
        in_function = {facts.strings[r["string"]]["value"] for r in facts.string_refs
                       if r["function"] == check.get("function")}
        values = [facts.strings[i]["value"] for i in ids]
        if len(set(values)) != len(values):
            return False
        return all(facts.strings[i]["value"] not in in_function
                   for n, i in enumerate(ids) if n != correct)
    if kind == "call":
        calls = [c for c in facts.calls
                 if c["from"] == check.get("from") and c["function"] == check.get("function")]
        if len(calls) != 1 or calls[0]["resolvedTarget"] is not None:
            return False
        target = calls[0]["target"]
        if ids[correct] != target:
            return False
        names = [facts.functions[i]["name"] for i in ids]
        if len(set(names)) != len(names):
            return False
        return all(facts.functions[i]["entry"] != calls[0]["targetAddress"]
                   for n, i in enumerate(ids) if n != correct)
    if kind == "external":
        if ids[correct] not in facts.externals:
            return False
        ext_names = {e["name"] for e in facts.externals.values()}
        thunk_names = {f["name"] for f in facts.functions.values() if f["thunk"]}
        for n, i in enumerate(ids):
            if n == correct:
                continue
            f = facts.functions.get(i)
            if f is None or f["thunk"] or f["name"] in ext_names or f["name"] in thunk_names:
                return False
        names = [facts.name_of(i) for i in ids]
        return len(set(names)) == len(names)
    if kind == "string-referrer":
        sid = check.get("string")
        if sid not in facts.strings:
            return False
        referrers = _referrers(facts, sid)
        if ids[correct] not in referrers:
            return False
        value = facts.strings[sid]["value"]
        same_value = {s["id"] for s in facts.strings.values() if s["value"] == value}
        for n, i in enumerate(ids):
            f = facts.functions.get(i)
            if f is None or f["thunk"]:
                return False
            if n == correct:
                continue
            # 誤答の関数は、この文字列も、同じ中身の別の文字列も参照していない。
            if any(r["function"] == i and r["string"] in same_value
                   for r in facts.string_refs):
                return False
        names = [facts.functions[i]["name"] for i in ids]
        return (len(set(names)) == len(names)
                and quiz.get("options") == [_fn_label(facts.functions[i]) for i in ids])
    if kind == "caller":
        target = check.get("target")
        t = facts.functions.get(target)
        if t is None or t["thunk"]:
            return False
        direct, via_thunk = _callers(facts, target)
        if ids[correct] not in direct:
            return False
        for n, i in enumerate(ids):
            f = facts.functions.get(i)
            if f is None or f["thunk"]:
                return False
            if n != correct and (i in direct or i in via_thunk or i == target):
                return False
        names = [facts.functions[i]["name"] for i in ids]
        return (len(set(names)) == len(names)
                and quiz.get("options") == [_fn_label(facts.functions[i]) for i in ids])
    if kind == "external-library":
        if ids[correct] != check.get("external"):
            return False
        recs = [facts.externals.get(i) for i in ids]
        if any(r is None for r in recs):
            return False
        libs = [library_name(r["library"]) for r in recs]
        if not all(libs) or len({x.casefold() for x in libs}) != len(libs):
            return False
        right = recs[correct]
        if any(r["name"].casefold() == right["name"].casefold()
               for n, r in enumerate(recs) if n != correct):
            return False
        return quiz.get("options") == [visible(x, 120) for x in libs]
    if kind == "limits":
        expected = _limits_claims(facts, check)
        if expected is None:
            return False
        hypotheses = [n for n, i in enumerate(ids) if i.startswith("hypothesis:")]
        if hypotheses != [correct]:
            return False
        options = quiz.get("options") or []
        return all(expected.get(i) == options[n] for n, i in enumerate(ids))
    return False


# ---------------------------------------------------------------------------
# 設問づくり
# ---------------------------------------------------------------------------

STRING_HINTS = [
    "命令の欄にあるオペランドと、その下の「参照先」に書かれたアドレスに注目してください。",
    "そのアドレスを、この段階に並んだ「定義済み文字列」の記録のアドレスと照らし合わせてください。",
    "文字列の中身が関数名と関係ありそうかどうかでは決めません。アドレスが一致する記録を選びます。",
]
CALL_HINTS = [
    "CALL などの呼び出し命令は、オペランドに呼び出し先の入口アドレスを持ちます。「呼び出し先」の欄も見てください。",
    "この段階に並んだ関数の記録から、入口アドレスが呼び出し先と一致するものを探してください。",
    "名前の印象ではなく、アドレスの一致で判断します。命令があることと、実行時に呼ばれたことは別です。",
]
EXTERNAL_HINTS = [
    "外部関数は、このプログラムの外（共有ライブラリなど）にある関数として、EXTERNAL というアドレス空間に登録されます。",
    "並んでいる記録それぞれのアドレス空間と、「登録先」の欄を確かめてください。",
    "有名なライブラリ関数の名前に似ているかどうかでは決めません。記録上の登録先で判断します。",
]


def _string_questions(facts: StaticFacts, ev: _Evidence, reasons: list) -> list[dict]:
    if any(t in facts.truncated for t in REQUIRES_COMPLETE["string-ref"]):
        reasons.append(
            "文字列参照: 参照の一覧が上限で打ち切られているため、同じ命令が誤答の文字列も"
            "参照していないことを確かめられません。正解が一つに決まらないおそれがあるので、"
            "この種類の設問は作っていません。"
        )
        return []
    by_function: dict[str, set] = {}
    for r in facts.string_refs:
        by_function.setdefault(r["function"], set()).add(facts.strings[r["string"]]["value"])
    by_from: dict[tuple, set] = {}
    for r in facts.string_refs:
        by_from.setdefault((r["from"], r["function"]), set()).add(r["string"])

    referenced = {r["string"] for r in facts.string_refs}
    candidates = []
    for r in facts.string_refs:
        f = facts.functions[r["function"]]
        s = facts.strings[r["string"]]
        if f["thunk"] or not _plain_name(f["name"]) or not _usable_string(s):
            continue
        if not _usable_instruction(r["instruction"]):
            continue
        if len(by_from[(r["from"], r["function"])]) != 1:
            continue  # 1 命令が複数の文字列を指すと、正解が一つに決まらない
        candidates.append(r)
    candidates.sort(key=lambda r: (r["from"], r["string"]))
    if not candidates:
        reasons.append("文字列参照: 関数内の命令から参照され、表示上限に収まる文字列がありませんでした。")
        return []

    quizzes = []
    picked = _choose(facts.input_sha256 + ":string", candidates, len(candidates),
                     key=lambda r: r["function"])
    for r in picked:
        if len(quizzes) >= MAX_STRING_QUESTIONS:
            break
        s = facts.strings[r["string"]]
        avoid = by_function[r["function"]]
        pool, seen = [], {s["value"]}
        # 他の関数から実際に参照されている文字列を先に使う。どこからも参照
        # されない文字列ばかりだと、「参照されていそうなもの」で当てられる。
        for sid in sorted(facts.strings, key=lambda i: (i not in referenced, i)):
            t = facts.strings[sid]
            if t["value"] in avoid or t["value"] in seen or not _usable_string(t):
                continue
            pool.append(sid)
            seen.add(t["value"])
        wrong = _choose(facts.input_sha256 + r["from"], pool, OPTIONS - 1)
        if len(wrong) < OPTIONS - 1:
            continue
        seed = facts.input_sha256 + ":s:" + r["from"]
        ids, at = _arrange(seed, r["string"], wrong)
        fn = facts.functions[r["function"]]
        instr_ev = ev.instruction(r["function"], r["from"], r["instruction"], "参照先", s["address"])
        right_ev = ev.string(r["string"])
        shown = sorted(ids, key=lambda i: facts.strings[i]["address"])
        ask = (f"関数 {visible(fn['name'], 80)} の {show_addr(r['from'])} にある命令について。"
               "この命令が参照している定義済み文字列はどれですか。")
        quiz = {
            "id": f"q-str-{len(quizzes) + 1}",
            "type": "single_choice",
            "category": "static-string",
            "templateId": "static.string-ref",
            "learningObjective": "命令が参照するアドレスを、定義済み文字列の記録と突き合わせる",
            "q": ask,
            "prompt": ask,
            "options": [_quote(facts.strings[i]["value"]) for i in ids],
            "optionIds": ids,
            "correct": at,
            "hints": list(STRING_HINTS),
            "explain": (
                f"{show_addr(r['from'])} の命令「{visible(r['instruction'], MAX_INSTRUCTION)}」には、"
                f"Ghidra が保存した参照（種類 {visible(r['refType'], 32)}）があり、参照先は "
                f"{show_addr(s['address'])} です。このアドレスに定義されている文字列は "
                f"{_quote(s['value'])} です。\n\n"
                "ほかの選択肢は、この関数のどの命令からも参照されていない文字列です。"
                "参照があることは、その文字列が実行時に使われたことまでは示しません。"
            ),
            "evidenceIds": [instr_ev, right_ev],
            "subjectEvidenceIds": [instr_ev],
            "answerCheck": {"kind": "string-ref", "function": r["function"],
                            "from": r["from"], "string": r["string"]},
            "_events": [
                {"type": "instruction",
                 "detail": f"{visible(fn['name'], 80)} / {show_addr(r['from'])}: "
                           f"{visible(r['instruction'], MAX_INSTRUCTION)}",
                 "evidenceIds": [instr_ev]},
            ] + [
                {"type": "string",
                 "detail": f"{show_addr(facts.strings[i]['address'])}: "
                           f"{_quote(facts.strings[i]['value'])}",
                 "evidenceIds": [ev.string(i)]}
                for i in shown
            ],
        }
        if verify_quiz(facts, quiz):
            quizzes.append(quiz)
    if not quizzes:
        reasons.append("文字列参照: 誤答にできる別の文字列（同じ関数から参照されていないもの）が足りませんでした。")
    return quizzes


def _internal_functions(facts: StaticFacts) -> list[dict]:
    return sorted((f for f in facts.functions.values()
                   if not f["thunk"] and _plain_name(f["name"])),
                  key=lambda f: f["entry"])


def _call_questions(facts: StaticFacts, ev: _Evidence, reasons: list) -> list[dict]:
    internal = _internal_functions(facts)
    per_from: dict[tuple, int] = {}
    for c in facts.calls:
        per_from[(c["from"], c["function"])] = per_from.get((c["from"], c["function"]), 0) + 1
    candidates = []
    for c in facts.calls:
        caller = facts.functions[c["function"]]
        target = facts.functions.get(c["target"])
        if target is None or target["thunk"] or c["resolvedTarget"] is not None:
            continue
        if caller["thunk"] or not _plain_name(caller["name"]) or not _plain_name(target["name"]):
            continue
        if not _usable_instruction(c["instruction"]) or per_from[(c["from"], c["function"])] != 1:
            continue
        candidates.append(c)
    candidates.sort(key=lambda c: c["from"])
    if not candidates:
        reasons.append("直接呼び出し: 呼び出し先を一意に解決できた、このプログラム内の関数への呼び出しがありませんでした。")
        return []

    quizzes = []
    picked = _choose(facts.input_sha256 + ":call", candidates, len(candidates),
                     key=lambda c: c["target"])
    for c in picked:
        if len(quizzes) >= MAX_CALL_QUESTIONS:
            break
        target = facts.functions[c["target"]]
        pool, seen = [], {target["name"]}
        for f in internal:
            if f["id"] == target["id"] or f["entry"] == c["targetAddress"] or f["name"] in seen:
                continue
            pool.append(f["id"])
            seen.add(f["name"])
        wrong = _choose(facts.input_sha256 + c["from"], pool, OPTIONS - 1)
        if len(wrong) < OPTIONS - 1:
            continue
        ids, at = _arrange(facts.input_sha256 + ":c:" + c["from"], target["id"], wrong)
        caller = facts.functions[c["function"]]
        instr_ev = ev.instruction(c["function"], c["from"], c["instruction"], "呼び出し先",
                                  c["targetAddress"])
        right_ev = ev.function(target["id"])
        shown = sorted(ids, key=lambda i: facts.functions[i]["entry"])
        mnemonic = visible(c["mnemonic"], 32)
        ask = (f"関数 {visible(caller['name'], 80)} の {show_addr(c['from'])} にある "
               f"{mnemonic} 命令について。この命令が直接呼び出す関数はどれですか。")
        quiz = {
            "id": f"q-call-{len(quizzes) + 1}",
            "type": "single_choice",
            "category": "static-call",
            "templateId": "static.call",
            "learningObjective": "呼び出し命令の行き先アドレスを、関数の入口アドレスと突き合わせる",
            "q": ask,
            "prompt": ask,
            "options": [visible(facts.functions[i]["name"], 80) for i in ids],
            "optionIds": ids,
            "correct": at,
            "hints": list(CALL_HINTS),
            "explain": (
                f"{show_addr(c['from'])} の命令「{visible(c['instruction'], MAX_INSTRUCTION)}」の"
                f"呼び出し先は {show_addr(c['targetAddress'])} です。この入口アドレスを持つ関数は "
                f"{visible(target['name'], 80)} です。\n\n"
                "ここで分かるのは「呼び出す命令がある」ことまでです。条件分岐の先にある場合も"
                "あり、実行時に実際に呼ばれたかどうかは、この記録だけでは分かりません。"
            ),
            "evidenceIds": [instr_ev, right_ev],
            "subjectEvidenceIds": [instr_ev],
            "answerCheck": {"kind": "call", "function": c["function"], "from": c["from"]},
            "_events": [
                {"type": "call",
                 "detail": f"{visible(caller['name'], 80)} / {show_addr(c['from'])}: "
                           f"{visible(c['instruction'], MAX_INSTRUCTION)}",
                 "evidenceIds": [instr_ev]},
            ] + [
                {"type": "function",
                 "detail": f"{visible(facts.functions[i]['name'], 80)} — 入口 "
                           f"{show_addr(facts.functions[i]['entry'])}",
                 "evidenceIds": [ev.function(i)]}
                for i in shown
            ],
        }
        if verify_quiz(facts, quiz):
            quizzes.append(quiz)
    if not quizzes:
        reasons.append("直接呼び出し: 誤答にできる別の関数（名前も入口も異なるもの）が足りませんでした。")
    return quizzes


def _external_questions(facts: StaticFacts, ev: _Evidence, reasons: list) -> list[dict]:
    if any(t in facts.truncated for t in REQUIRES_COMPLETE["external"]):
        reasons.append(
            "外部関数: 関数または外部関数の一覧が上限で打ち切られているため、誤答に使う関数と"
            "同じ名前の外部関数が一覧の外にないことを確かめられません。この種類の設問は"
            "作っていません。"
        )
        return []
    ext_names = {e["name"] for e in facts.externals.values()}
    thunk_names = {f["name"] for f in facts.functions.values() if f["thunk"]}
    called = {c["resolvedTarget"] for c in facts.calls if c["resolvedTarget"]}
    externals = sorted((e for e in facts.externals.values() if _plain_name(e["name"])),
                       key=lambda e: (e["id"] not in called, e["address"]))
    pool = [f["id"] for f in _internal_functions(facts)
            if f["name"] not in ext_names and f["name"] not in thunk_names]
    if not externals:
        reasons.append("外部関数: 外部関数の記録がありませんでした。")
        return []
    if len({facts.functions[i]["name"] for i in pool}) < OPTIONS - 1:
        reasons.append("外部関数: 誤答にできる、このプログラム内の関数が足りませんでした。")
        return []

    quizzes = []
    for e in _choose(facts.input_sha256 + ":ext", externals, MAX_EXTERNAL_QUESTIONS):
        seen, names = set(), []
        for i in pool:
            n = facts.functions[i]["name"]
            if n not in seen:
                names.append(i)
                seen.add(n)
        wrong = _choose(facts.input_sha256 + e["id"], names, OPTIONS - 1)
        ids, at = _arrange(facts.input_sha256 + ":e:" + e["id"], e["id"], wrong)
        right_ev = ev.external(e["id"])
        evs = {i: (ev.external(i) if i in facts.externals else ev.function(i)) for i in ids}
        lib = visible(e["library"] or "（記録なし）", 120)
        ask = "次の関数のうち、このプログラムに外部関数（プログラムの外にある関数）として登録されているものはどれですか。"
        quiz = {
            "id": f"q-ext-{len(quizzes) + 1}",
            "type": "single_choice",
            "category": "static-external",
            "templateId": "static.external",
            "learningObjective": "関数の記録から、プログラム内の関数と外部関数を見分ける",
            "q": ask,
            "prompt": ask,
            "options": [visible(facts.name_of(i), 80) for i in ids],
            "optionIds": ids,
            "correct": at,
            "hints": list(EXTERNAL_HINTS),
            "explain": (
                f"{visible(e['name'], 80)} は {show_addr(e['address'])}（EXTERNAL 空間）に"
                f"外部関数として登録されており、登録先のライブラリは {lib} です。"
                "ほかの選択肢は、このプログラムのメモリ上に入口を持つ関数です。\n\n"
                "外部関数として登録されていることは、その関数を使う準備があることを示すだけで、"
                "何のために使うのか、実行時に呼ばれたのかは分かりません。関数名だけから"
                "悪性や攻撃手法を決めつけないでください。"
            ),
            "evidenceIds": [right_ev],
            "subjectEvidenceIds": [],
            "answerCheck": {"kind": "external", "external": e["id"]},
            "_events": [
                {"type": "external" if i in facts.externals else "function",
                 "detail": (f"{visible(facts.name_of(i), 80)} — "
                            + (f"{show_addr(facts.externals[i]['address'])}"
                               if i in facts.externals
                               else f"入口 {show_addr(facts.functions[i]['entry'])}")),
                 "evidenceIds": [evs[i]]}
                for i in sorted(ids, key=lambda i: facts.name_of(i).lower())
            ],
        }
        if verify_quiz(facts, quiz):
            quizzes.append(quiz)
    return quizzes


REFERRER_HINTS = [
    "問題の文字列のアドレスを確かめてください。同じ中身の文字列が別のアドレスにあることもあるので、中身ではなくアドレスで見分けます。",
    "この段階に並んだ命令の記録それぞれについて、「参照先」のアドレスが問題の文字列のアドレスと一致するかを見てください。",
    "一致した命令の「関数」の欄が答えです。関数名の印象や、文字列の中身と関係がありそうかどうかでは決めません。",
]
CALLER_HINTS = [
    "問題の関数の入口アドレスを確かめてください。",
    "この段階に並んだ呼び出し命令の記録それぞれについて、「呼び出し先」のアドレスが、その入口アドレスと一致するかを見てください。",
    "一致した命令を持つ関数が答えです。thunk（中継の関数）を経由する呼び出しや、行き先が実行時に決まる間接呼び出しは、ここでは直接呼び出しに数えません。",
]
LIBRARY_HINTS = [
    "問題の外部関数を、名前だけでなくアドレス（EXTERNAL 空間）で特定してください。同じ名前の関数が別のライブラリに登録されていることもあります。",
    "特定した記録の「登録先」の欄を読みます。",
    "関数名から有名なライブラリを思い浮かべて答えるのではなく、保存されている登録先の値をそのまま選びます。",
]
LIMITS_HINTS = [
    "選択肢を一つずつ、上の記録のどの欄で確かめられるかを考えてください（関数・アドレス・命令・参照先）。",
    "記録の欄で確かめられるのは「どんな命令やデータがどこにあるか」までです。",
    "いつ・何回・何のために、は静的な記録の欄には書かれていません。確かめられる欄が見つからない選択肢を選びます。",
]


def _decoy_instruction(facts: StaticFacts, fid: str, bad_strings: set, bad_target: str | None,
                       per_ref: dict, per_call: dict, prefer: str = "ref") -> tuple | None:
    """選択肢に並べる関数の、材料として見せる命令の記録を 1 件選ぶ。

    正解の関数だけに命令の記録があると、中身を読まなくても当てられる。
    誤答の関数にも、問題の対象とは別のものを指す命令を 1 件ずつ並べる。
    正解と同じ種類の命令（`prefer`: 文字列参照 "ref" か呼び出し "call"）を
    先に探し、種類の違いで正解が見分けられないようにする。1 命令が複数の
    行き先を持つものは使わない（記録に行き先が 1 つしか出ない）。
    戻り値は (命令のアドレス, 命令, 関係, 行き先アドレス)。
    """
    def from_refs():
        for r in facts.string_refs:
            if r["function"] != fid or r["string"] in bad_strings:
                continue
            if per_ref[(r["from"], r["function"])] != 1 or not _usable_instruction(r["instruction"]):
                continue
            return (r["from"], r["instruction"], "参照先", facts.strings[r["string"]]["address"])
        return None

    def from_calls():
        for c in facts.calls:
            if c["function"] != fid:
                continue
            if bad_target is not None and bad_target in (c["target"], c["resolvedTarget"]):
                continue
            if per_call[(c["from"], c["function"])] != 1 or not _usable_instruction(c["instruction"]):
                continue
            return (c["from"], c["instruction"], "呼び出し先", c["targetAddress"])
        return None

    first, second = (from_refs, from_calls) if prefer == "ref" else (from_calls, from_refs)
    return first() or second()


def _per_from(facts: StaticFacts) -> tuple[dict, dict]:
    per_ref: dict[tuple, int] = {}
    for r in facts.string_refs:
        per_ref[(r["from"], r["function"])] = per_ref.get((r["from"], r["function"]), 0) + 1
    per_call: dict[tuple, int] = {}
    for c in facts.calls:
        per_call[(c["from"], c["function"])] = per_call.get((c["from"], c["function"]), 0) + 1
    return per_ref, per_call


def _instruction_events(facts: StaticFacts, ev: "_Evidence", rows: list[tuple]) -> tuple[list, dict]:
    """(関数 ID, 命令の記録) の並びから、段階に並べる命令の事象と証拠 ID を作る。"""
    events, ids = [], {}
    for fid, (frm, text, relation, target) in sorted(rows, key=lambda x: x[1][0]):
        ident = ev.instruction(fid, frm, text, relation, target)
        ids[fid] = ident
        events.append({
            "type": "call" if relation == "呼び出し先" else "instruction",
            "detail": (f"{visible(facts.functions[fid]['name'], 80)} / {show_addr(frm)}: "
                       f"{visible(text, MAX_INSTRUCTION)}"),
            "evidenceIds": [ident],
        })
    return events, ids


def _referrer_questions(facts: StaticFacts, ev: "_Evidence", reasons: list) -> list[dict]:
    """文字列の参照元（G1）: この文字列への参照命令を持つ関数はどれか。

    文字列はアドレスで特定する（同じ中身の文字列が別のアドレスにあり得る）。
    参照元が複数ある文字列でも、ほかの参照元を誤答から外せば一つに決まる。
    同じ中身の別の文字列を参照する関数も、紛らわしいので誤答にしない。
    """
    if any(t in facts.truncated for t in REQUIRES_COMPLETE["string-referrer"]):
        reasons.append(
            "文字列の参照元: 参照の一覧が上限で打ち切られているため、誤答に使う関数が同じ"
            "文字列を参照していないことを確かめられません。この種類の設問は作っていません。"
        )
        return []
    per_ref, per_call = _per_from(facts)
    by_string: dict[str, list] = {}
    for r in facts.string_refs:
        by_string.setdefault(r["string"], []).append(r)
    internal = _internal_functions(facts)
    candidates = []
    for sid in sorted(by_string):
        s = facts.strings[sid]
        if not _usable_string(s):
            continue
        right = None
        for r in sorted(by_string[sid], key=lambda r: (facts.functions[r["function"]]["entry"], r["from"])):
            f = facts.functions[r["function"]]
            if f["thunk"] or not _plain_name(f["name"]):
                continue
            if per_ref[(r["from"], r["function"])] != 1 or not _usable_instruction(r["instruction"]):
                continue
            right = r
            break
        if right is not None:
            candidates.append((sid, right))
    if not candidates:
        reasons.append("文字列の参照元: 参照命令を表示できる、このプログラム内の関数から参照された文字列がありませんでした。")
        return []

    quizzes = []
    for sid, r in _choose(facts.input_sha256 + ":referrer", candidates, len(candidates),
                          key=lambda x: x[1]["function"]):
        if len(quizzes) >= MAX_REFERRER_QUESTIONS:
            break
        s = facts.strings[sid]
        referrers = _referrers(facts, sid)
        same_value = {t["id"] for t in facts.strings.values() if t["value"] == s["value"]}
        near = {x["function"] for x in facts.string_refs if x["string"] in same_value}
        right_fn = facts.functions[r["function"]]
        pool, seen = [], {right_fn["name"]}
        for f in internal:
            if f["id"] in referrers or f["id"] in near or f["name"] in seen:
                continue
            decoy = _decoy_instruction(facts, f["id"], same_value, None, per_ref, per_call)
            if decoy is None:
                continue
            pool.append((f["id"], decoy))
            seen.add(f["name"])
        wrong = _choose(facts.input_sha256 + sid, pool, OPTIONS - 1)
        if len(wrong) < OPTIONS - 1:
            continue
        ids, at = _arrange(facts.input_sha256 + ":r:" + sid, r["function"], [w[0] for w in wrong])
        rows = [(r["function"], (r["from"], r["instruction"], "参照先", s["address"]))] + list(wrong)
        events, instr = _instruction_events(facts, ev, rows)
        str_ev = ev.string(sid)
        others = sorted(referrers - {r["function"]})
        ask = (f"{show_addr(s['address'])} の定義済み文字列 {_quote(s['value'])} について。"
               "この文字列への参照命令を持つ関数はどれですか。")
        quiz = {
            "id": f"q-strsrc-{len(quizzes) + 1}",
            "type": "single_choice",
            "category": "static-string",
            "templateId": "static.string-referrer",
            "learningObjective": "文字列のアドレスから、それを参照する命令と関数を逆にたどる",
            "q": ask,
            "prompt": ask,
            "options": [_fn_label(facts.functions[i]) for i in ids],
            "optionIds": ids,
            "correct": at,
            "hints": list(REFERRER_HINTS),
            "explain": (
                f"{show_addr(r['from'])} の命令「{visible(r['instruction'], MAX_INSTRUCTION)}」の参照先は "
                f"{show_addr(s['address'])} で、この命令は関数 {_fn_label(right_fn)} の中にあります。\n\n"
                "ほかの選択肢の関数には、この文字列（同じ中身の別のアドレスの文字列も含む）への"
                "参照命令が記録されていません。"
                + (f"この文字列は、選択肢に無いほかの {len(others)} 個の関数からも参照されています。"
                   if others else "")
                + "参照命令があることは、その関数が実行時にこの文字列を使ったことまでは示しません。"
            ),
            "evidenceIds": [str_ev, instr[r["function"]]],
            "subjectEvidenceIds": [str_ev],
            "subjectLabel": "問題の文字列を見る",
            "answerCheck": {"kind": "string-referrer", "string": sid},
            "_events": [{"type": "string",
                         "detail": f"{show_addr(s['address'])}: {_quote(s['value'])}",
                         "evidenceIds": [str_ev]}] + events,
        }
        if verify_quiz(facts, quiz):
            quizzes.append(quiz)
    if not quizzes:
        reasons.append("文字列の参照元: 誤答にできる関数（その文字列を参照せず、材料として見せる命令の記録を持つもの）が足りませんでした。")
    return quizzes


def _caller_questions(facts: StaticFacts, ev: "_Evidence", reasons: list) -> list[dict]:
    """直接呼び出し元（G2）: この関数の入口への直接呼び出し命令を持つ関数はどれか。

    初版は、このプログラム内の関数（thunk でないもの）どうしの直接呼び出しに
    限る。呼び出し先が thunk の呼び出しは、thunk の行き先へ「解決された」
    呼び出しで、行き先の関数への直接呼び出しではない。そうした呼び出しを
    持つ関数は、紛らわしいので誤答にも使わない。間接呼び出し・未解決の
    呼び出しは記録に行き先が無いので補わない。
    """
    if any(t in facts.truncated for t in REQUIRES_COMPLETE["caller"]):
        reasons.append(
            "直接呼び出し元: 呼び出しの一覧が上限で打ち切られているため、誤答に使う関数が"
            "同じ関数を呼び出していないことを確かめられません。この種類の設問は作っていません。"
        )
        return []
    per_ref, per_call = _per_from(facts)
    internal = _internal_functions(facts)
    candidates = []
    for t in internal:
        right = None
        for c in sorted((c for c in facts.calls if c["target"] == t["id"] and c["resolvedTarget"] is None),
                        key=lambda c: (facts.functions[c["function"]]["entry"], c["from"])):
            f = facts.functions[c["function"]]
            if f["thunk"] or not _plain_name(f["name"]) or f["id"] == t["id"]:
                continue
            if per_call[(c["from"], c["function"])] != 1 or not _usable_instruction(c["instruction"]):
                continue
            right = c
            break
        if right is not None:
            candidates.append((t["id"], right))
    if not candidates:
        reasons.append("直接呼び出し元: このプログラム内の関数どうしで、呼び出し命令を表示できる直接呼び出しがありませんでした。")
        return []

    quizzes = []
    for tid, c in _choose(facts.input_sha256 + ":caller", candidates, len(candidates),
                          key=lambda x: x[1]["function"]):
        if len(quizzes) >= MAX_CALLER_QUESTIONS:
            break
        t = facts.functions[tid]
        direct, via_thunk = _callers(facts, tid)
        right_fn = facts.functions[c["function"]]
        pool, seen = [], {right_fn["name"], t["name"]}
        for f in internal:
            if f["id"] in direct or f["id"] in via_thunk or f["id"] == tid or f["name"] in seen:
                continue
            decoy = _decoy_instruction(facts, f["id"], set(), tid, per_ref, per_call,
                                       prefer="call")
            if decoy is None:
                continue
            pool.append((f["id"], decoy))
            seen.add(f["name"])
        wrong = _choose(facts.input_sha256 + tid, pool, OPTIONS - 1)
        if len(wrong) < OPTIONS - 1:
            continue
        ids, at = _arrange(facts.input_sha256 + ":cr:" + tid, c["function"], [w[0] for w in wrong])
        rows = [(c["function"], (c["from"], c["instruction"], "呼び出し先", c["targetAddress"]))] + list(wrong)
        events, instr = _instruction_events(facts, ev, rows)
        fn_ev = ev.function(tid)
        others = sorted(direct - {c["function"]})
        ask = (f"関数 {_fn_label(t)} について。この関数の入口への直接呼び出し命令を持つ関数は"
               "どれですか。")
        quiz = {
            "id": f"q-caller-{len(quizzes) + 1}",
            "type": "single_choice",
            "category": "static-call",
            "templateId": "static.caller",
            "learningObjective": "関数の入口アドレスから、そこへの直接呼び出し命令を持つ関数を逆にたどる",
            "q": ask,
            "prompt": ask,
            "options": [_fn_label(facts.functions[i]) for i in ids],
            "optionIds": ids,
            "correct": at,
            "hints": list(CALLER_HINTS),
            "explain": (
                f"{show_addr(c['from'])} の命令「{visible(c['instruction'], MAX_INSTRUCTION)}」の"
                f"呼び出し先は {show_addr(c['targetAddress'])} で、{visible(t['name'], 80)} の入口と"
                f"一致します。この命令は関数 {_fn_label(right_fn)} の中にあります。\n\n"
                "ほかの選択肢の関数には、この入口への直接呼び出し命令が記録されていません。"
                + (f"選択肢に無いほかの {len(others)} 個の関数にも、この入口への直接呼び出し命令があります。"
                   if others else "")
                + "ここで分かるのは「呼び出す命令がある」ことまでです。実行時に実際に呼ばれたか、"
                "間接呼び出しなど記録に行き先の無い呼び出しで到達するかは、この記録からは分かりません。"
            ),
            "evidenceIds": [fn_ev, instr[c["function"]]],
            "subjectEvidenceIds": [fn_ev],
            "subjectLabel": "問題の関数を見る",
            "answerCheck": {"kind": "caller", "target": tid},
            "_events": [{"type": "function",
                         "detail": f"{visible(t['name'], 80)} — 入口 {show_addr(t['entry'])}",
                         "evidenceIds": [fn_ev]}] + events,
        }
        if verify_quiz(facts, quiz):
            quizzes.append(quiz)
    if not quizzes:
        reasons.append("直接呼び出し元: 誤答にできる関数（その関数を呼び出さず、材料として見せる命令の記録を持つもの）が足りませんでした。")
    return quizzes


def _library_questions(facts: StaticFacts, ev: "_Evidence", reasons: list) -> list[dict]:
    """外部関数の登録先（G3）: この外部関数の登録先として保存されているライブラリはどれか。

    答えは対象レコード（ID・アドレスで特定）の `library` 欄。空欄や不明
    （`<EXTERNAL>`）を実在のライブラリ名として扱わない。誤答は、ほかの
    外部関数のレコードに実際に保存されている、異なる登録先から取る。
    同じ名前の外部関数のレコードは、名前だけでは区別できないので使わない。
    保存された登録先を問うもので、実行時にそのライブラリが読み込まれた
    ことは言わない。
    """
    known = [e for e in facts.externals.values()
             if _plain_name(e["name"]) and library_name(e["library"])]
    libraries = {library_name(e["library"]).casefold() for e in known}
    if len(libraries) < OPTIONS:
        reasons.append(
            f"外部関数の登録先: 登録先（ライブラリ名）が保存されている外部関数の登録先が "
            f"{len(libraries)} 種類しかなく、選択肢を {OPTIONS} つ作れませんでした。空欄や"
            "不明（<EXTERNAL>）はライブラリ名として扱っていません。"
        )
        return []
    called = {c["resolvedTarget"] for c in facts.calls if c["resolvedTarget"]}
    targets = sorted(known, key=lambda e: (e["id"] not in called, e["address"]))
    quizzes = []
    for e in _choose(facts.input_sha256 + ":lib", targets, len(targets)):
        if len(quizzes) >= MAX_LIBRARY_QUESTIONS:
            break
        lib = library_name(e["library"])
        pool, seen = [], {lib.casefold()}
        for x in sorted(known, key=lambda x: x["address"]):
            other = library_name(x["library"])
            if other.casefold() in seen or x["name"].casefold() == e["name"].casefold():
                continue
            pool.append(x["id"])
            seen.add(other.casefold())
        wrong = _choose(facts.input_sha256 + e["id"] + ":lib", pool, OPTIONS - 1)
        if len(wrong) < OPTIONS - 1:
            continue
        ids, at = _arrange(facts.input_sha256 + ":l:" + e["id"], e["id"], wrong)
        right_ev = ev.external(e["id"])
        evs = {i: ev.external(i) for i in ids}
        ask = (f"外部関数 {visible(e['name'], 80)}（{show_addr(e['address'])}）のレコードについて。"
               "この外部関数の登録先として保存されているライブラリはどれですか。")
        quiz = {
            "id": f"q-lib-{len(quizzes) + 1}",
            "type": "single_choice",
            "category": "static-external",
            "templateId": "static.external-library",
            "learningObjective": "外部関数のレコードをアドレスで特定し、保存された登録先を読む",
            "q": ask,
            "prompt": ask,
            "options": [visible(library_name(facts.externals[i]["library"]), 120) for i in ids],
            "optionIds": ids,
            "correct": at,
            "hints": list(LIBRARY_HINTS),
            "explain": (
                f"{show_addr(e['address'])} の外部関数 {visible(e['name'], 80)} のレコードには、"
                f"登録先として {visible(lib, 120)} が保存されています。ほかの選択肢は、別の外部関数の"
                "レコードに保存されている登録先です。\n\n"
                "これは Ghidra が解析時に保存した登録先です。実行時にそのライブラリが読み込まれたことや、"
                "この関数が実際に呼ばれたことは示しません。"
            ),
            "evidenceIds": [right_ev],
            # 対象のレコードそのものに答えが書いてあるので、解答前には飛ばさない。
            "subjectEvidenceIds": [],
            "answerCheck": {"kind": "external-library", "external": e["id"]},
            "_events": [
                {"type": "external",
                 "detail": f"{visible(facts.externals[i]['name'], 80)} — {show_addr(facts.externals[i]['address'])}",
                 "evidenceIds": [evs[i]]}
                for i in sorted(ids, key=lambda i: facts.externals[i]["address"])
            ],
        }
        if verify_quiz(facts, quiz):
            quizzes.append(quiz)
    if not quizzes:
        reasons.append("外部関数の登録先: 名前の重ならない外部関数から、異なる登録先を 3 つ集められませんでした。")
    return quizzes


#: 静的な記録からは確かめられない主張。出題のための仮説で、事実ではない。
CALL_HYPOTHESES = (
    ("executed", "この呼び出しが、実行時に実際に行われた"),
    ("count", "この呼び出しが、実行時に何回行われるか"),
    ("intent", "この呼び出しが、攻撃の目的で使われる"),
)
STRING_HYPOTHESES = (
    ("executed", "この命令が、実行時に実際に実行された"),
    ("displayed", "この文字列が、実行時に画面へ表示された"),
    ("intent", "この文字列が、攻撃者への指示として使われる"),
)


def _limits_claims(facts: StaticFacts, check: dict) -> dict | None:
    """判断の限界の設問の、選択肢 ID → 文言。記録から作り直す（検証にも使う）。

    `stored:*` は対象のレコードから確かめられる事実、`hypothesis:*` は静的な
    記録からは確かめられない主張。どちらも、ここで記録から組み立てる。
    """
    subject = check.get("subject")
    if subject == "call":
        c = next((c for c in facts.calls
                  if c["from"] == check.get("from") and c["function"] == check.get("function")), None)
        if c is None or c["resolvedTarget"] is not None:
            return None
        caller, target = facts.functions[c["function"]], facts.functions.get(c["target"])
        if target is None or target["entry"] != c["targetAddress"]:
            return None
        out = {
            "stored:instruction": (f"関数 {visible(caller['name'], 80)} の {show_addr(c['from'])} に"
                                   f" {visible(c['mnemonic'], 32)} 命令が記録されている"),
            "stored:target-address": f"この命令の直接の行き先として {show_addr(c['targetAddress'])} が記録されている",
            "stored:target-function": (f"{show_addr(c['targetAddress'])} は、関数 "
                                       f"{visible(target['name'], 80)} の入口として記録されている"),
        }
        out.update({f"hypothesis:{k}": v for k, v in CALL_HYPOTHESES})
        return out
    if subject == "string-ref":
        r = next((r for r in facts.string_refs
                  if r["from"] == check.get("from") and r["function"] == check.get("function")
                  and r["string"] == check.get("string")), None)
        if r is None:
            return None
        fn, s = facts.functions[r["function"]], facts.strings[r["string"]]
        out = {
            "stored:instruction": f"関数 {visible(fn['name'], 80)} の {show_addr(r['from'])} に命令が記録されている",
            "stored:reference": f"この命令の参照先として {show_addr(s['address'])} が記録されている",
            "stored:string": f"{show_addr(s['address'])} に定義済み文字列 {_quote(s['value'])} が記録されている",
        }
        out.update({f"hypothesis:{k}": v for k, v in STRING_HYPOTHESES})
        return out
    return None


def _limits_questions(facts: StaticFacts, ev: "_Evidence", reasons: list) -> list[dict]:
    """判断の限界（G4）: この命令の記録だけでは確認できないことはどれか。

    一般論の暗記にしないため、特定の命令のレコードに結び付ける。選択肢は、
    そのレコードから確かめられる事実 3 つと、確かめられない主張 1 つ。
    確かめられない主張を複数並べると正解が複数になるので、1 つだけにする。
    実行すれば分かる、という方向のヒントや説明は書かない。
    """
    per_ref, per_call = _per_from(facts)
    subjects = []
    for c in sorted(facts.calls, key=lambda c: c["from"]):
        caller, target = facts.functions[c["function"]], facts.functions.get(c["target"])
        if target is None or target["thunk"] or caller["thunk"] or c["resolvedTarget"] is not None:
            continue
        if not (_plain_name(caller["name"]) and _plain_name(target["name"])):
            continue
        if per_call[(c["from"], c["function"])] != 1 or not _usable_instruction(c["instruction"]):
            continue
        subjects.append(("call", c))
    if not subjects:
        for r in sorted(facts.string_refs, key=lambda r: r["from"]):
            fn = facts.functions[r["function"]]
            if fn["thunk"] or not _plain_name(fn["name"]) or not _usable_string(facts.strings[r["string"]]):
                continue
            if per_ref[(r["from"], r["function"])] != 1 or not _usable_instruction(r["instruction"]):
                continue
            subjects.append(("string-ref", r))
    if not subjects:
        reasons.append("判断の限界: 表示できる直接呼び出しや文字列参照の命令の記録がありませんでした。")
        return []

    quizzes = []
    for kind, rec in _choose(facts.input_sha256 + ":limits", subjects, MAX_LIMITS_QUESTIONS):
        if kind == "call":
            check = {"kind": "limits", "subject": "call", "function": rec["function"], "from": rec["from"]}
            instr_ev = ev.instruction(rec["function"], rec["from"], rec["instruction"], "呼び出し先",
                                      rec["targetAddress"])
            other_ev = ev.function(rec["target"])
            hyps = CALL_HYPOTHESES
            what = f" {visible(rec['mnemonic'], 32)} 命令"
        else:
            check = {"kind": "limits", "subject": "string-ref", "function": rec["function"],
                     "from": rec["from"], "string": rec["string"]}
            instr_ev = ev.instruction(rec["function"], rec["from"], rec["instruction"], "参照先",
                                      facts.strings[rec["string"]]["address"])
            other_ev = ev.string(rec["string"])
            hyps = STRING_HYPOTHESES
            what = "命令"
        claims = _limits_claims(facts, check)
        if claims is None:
            continue
        seed = facts.input_sha256 + ":lim:" + rec["from"]
        hyp = f"hypothesis:{hyps[pick_index(seed, len(hyps))][0]}"
        stored = [k for k in claims if k.startswith("stored:")]
        ids, at = _arrange(seed, hyp, stored)
        fn = facts.functions[rec["function"]]
        ask = (f"関数 {visible(fn['name'], 80)} の {show_addr(rec['from'])} にある{what}について。"
               "下に示した記録だけでは確認できないことはどれですか。")
        quiz = {
            "id": f"q-slimits-{len(quizzes) + 1}",
            "type": "single_choice",
            "category": "static-limits",
            "templateId": "static.limits",
            "learningObjective": "保存された記録で確かめられる事実と、確かめられない主張を分ける",
            "q": ask,
            "prompt": ask,
            "options": [claims[i] for i in ids],
            "optionIds": ids,
            "correct": at,
            "optionKind": "claims",
            "hints": list(LIMITS_HINTS),
            "explain": (
                f"「{claims[hyp]}」は、この記録のどの欄にも書かれていません。ほかの選択肢は、"
                "下の記録の関数・アドレス・命令・参照先の欄で確かめられる事実です。\n\n"
                "静的な記録が示すのは、どこにどんな命令やデータがあるかまでです。実行されたか、"
                "何回か、何のためかは、この教材が扱う保存済みの解析情報からは決まりません。"
                "確かめたい場合は、この記録とは別の種類の証拠が必要になります。"
            ),
            "evidenceIds": [instr_ev, other_ev],
            # 問い文が「下に示した記録」と言っている二つ。解答前から見せる。
            "subjectEvidenceIds": [instr_ev, other_ev],
            "answerCheck": check,
            "_events": [
                {"type": "call" if kind == "call" else "instruction",
                 "detail": f"{visible(fn['name'], 80)} / {show_addr(rec['from'])}: "
                           f"{visible(rec['instruction'], MAX_INSTRUCTION)}",
                 "evidenceIds": [instr_ev]},
                {"type": "function" if kind == "call" else "string",
                 "detail": ev.items[other_ev]["source"]["excerpt"],
                 "evidenceIds": [other_ev]},
            ],
        }
        if verify_quiz(facts, quiz):
            quizzes.append(quiz)
    return quizzes


# ---------------------------------------------------------------------------
# 教材
# ---------------------------------------------------------------------------

def _stage(stage_id: str, name: str, intro: str, quizzes: list[dict]) -> dict:
    events, seen = [], set()
    for q in quizzes:
        for e in q.pop("_events"):
            key = (e["type"], e["detail"])
            if key not in seen:
                events.append(e)
                seen.add(key)
    return {"id": stage_id, "name": name, "intro": intro, "events": events,
            "quizzes": quizzes}


#: 作れなかった理由（`reasons`）の書き出し。テンプレートとの対応に使う。
REASON_PREFIX = {
    "static.string-ref": "文字列参照:",
    "static.string-referrer": "文字列の参照元:",
    "static.call": "直接呼び出し:",
    "static.caller": "直接呼び出し元:",
    "static.external": "外部関数:",
    "static.external-library": "外部関数の登録先:",
    "static.limits": "判断の限界:",
}

#: 段階の名前と導入。選んだ設問のテンプレートに合わせて導入を組み立てる。
STAGE_TEXT = {
    "static-strings": (
        "文字列の参照を読む",
        "Ghidra は、命令がどのアドレスのデータを指しているかを「参照」として保存します。\n\n"
        "下の記録には、関数の命令と、プログラム内に定義された文字列が並んでいます。"
        "命令の参照先アドレスと、文字列が置かれたアドレスを突き合わせてください。"
        "命令から文字列へたどる設問と、文字列から参照元の関数へ逆にたどる設問があります。",
    ),
    "static-calls": (
        "直接呼び出しを読む",
        "呼び出し命令（x86 の CALL など）は、行き先のアドレスを持ちます。そのアドレスが"
        "どの関数の入口かを、関数の記録と照らし合わせて確かめます。命令から行き先へ、"
        "関数から呼び出し元へ、の両方向があります。\n\n"
        "間接呼び出し（レジスタやメモリの値で行き先が決まるもの）は、この教材では扱いません。",
    ),
    "static-externals": (
        "外部関数を読む",
        "プログラムの中にある関数と、共有ライブラリなど外から取り込む関数は、Ghidra の"
        "記録では登録先（アドレス空間）が違います。外部関数のレコードには、登録先として"
        "保存されたライブラリ名が付くことがあります。",
    ),
    "static-limits": (
        "記録から言えないことを分ける",
        "保存済みの解析情報から確かめられるのは、どこにどんな命令やデータがあるかまでです。"
        "下の記録を見て、確かめられる事実と、確かめられない主張を分けます。",
    ),
}


def build(facts: StaticFacts, *, image: dict, origin: dict,
          sample: dict | None = None,
          max_questions: int | None = quiz_select.MAX_QUESTIONS) -> dict:
    """静的事実から演習を 1 つ作る。設問が 1 問も作れなければ NoQuestions。

    同じ入力・同じ固定ツール版からは、同じ教材（ID・設問・選択肢の並び）になる。
    テンプレートごとに検証済みの候補を作り、`max_questions` 問までを選んでから
    段階を組み立てる（None なら全部の候補を出す。テンプレートの確認用）。
    """
    reasons: list[str] = []
    if not facts.program["analyzed"]:
        raise NoQuestions([
            "この GZF は解析済みとして保存されていません。自動再解析は行わない設計のため、"
            "Ghidra で解析してから保存した GZF を使ってください。"
        ])
    if not facts.functions:
        raise NoQuestions(["関数の記録が 1 件もありませんでした。解析情報が不足しています。"])

    ev = _Evidence(facts)
    made = {
        "static.string-ref": _string_questions(facts, ev, reasons),
        "static.string-referrer": _referrer_questions(facts, ev, reasons),
        "static.call": _call_questions(facts, ev, reasons),
        "static.caller": _caller_questions(facts, ev, reasons),
        "static.external": _external_questions(facts, ev, reasons),
        "static.external-library": _library_questions(facts, ev, reasons),
        "static.limits": _limits_questions(facts, ev, reasons),
    }
    stage_of = dict(STAGES)
    candidates = [(stage_of[TEMPLATES[t][1]], q) for t in TEMPLATES for q in made[t]]
    if not candidates:
        raise NoQuestions(reasons or ["根拠の揃う設問を作れませんでした。"])
    picked = quiz_select.select(candidates, TEMPLATE_PRIORITY, max_questions, REVERSE_TEMPLATES)
    not_generated = [
        {"templateId": t, "label": TEMPLATES[t][0],
         "reason": next((r for r in reasons if r.startswith(REASON_PREFIX[t])), "")
         or "この入力には、この種類の設問を作るための根拠が揃いませんでした。"}
        for t in TEMPLATES if not made[t]
    ]
    selection = quiz_select.summary(candidates, picked, max_questions,
                                    {k: v[0] for k, v in TEMPLATES.items()}, not_generated)

    name = visible(facts.program["name"], 80)
    stages = []
    for _, stage_id in STAGES:
        chosen = [q for sid, q in picked if sid == stage_id]
        if not chosen:
            continue
        title, intro = STAGE_TEXT[stage_id]
        stages.append(_stage(stage_id, f"段階{len(stages) + 1} — {title}", intro, chosen))
    strings = [q for s in stages for q in s["quizzes"] if q["category"] == "static-string"]
    calls = [q for s in stages for q in s["quizzes"] if q["category"] == "static-call"]
    externals = [q for s in stages for q in s["quizzes"] if q["category"] == "static-external"]
    limits = [q for s in stages for q in s["quizzes"] if q["category"] == "static-limits"]

    counts = facts.counts()
    unknowns = [
        {"topic": "実行はしていません",
         "detail": ("この教材は、GZF に保存済みの解析情報を読み出して作りました。対象プログラムの"
                    "起動・エミュレーション・デバッガ接続は行っていません。実行時の挙動（何が"
                    "起きたか、どの順で呼ばれたか）は、ここからは分かりません。")},
        {"topic": "呼び出し命令と実際の呼び出し",
         "detail": ("呼び出し命令が存在することは、実行時にその呼び出しが起きたことを意味しません。"
                    f"間接呼び出し {counts['indirectCalls']} 件と、行き先を一意に解決できなかった"
                    f"呼び出し {counts['unresolvedCalls']} 件は、設問に使っていません。")},
        {"topic": "悪性の判断",
         "detail": ("文字列や外部関数の名前だけから、悪性かどうかや攻撃手法を決めることはしていません。"
                    "この教材は ATT&CK との対応付けを行いません。")},
        {"topic": "保存時点の解析結果であること",
         "detail": ("記録は GZF を保存した時点の Ghidra の解析結果です。自動解析はやり直していないので、"
                    "解析の設定や版が違えば、関数や参照の数は変わり得ます。")},
    ]
    if facts.truncated:
        unknowns.append({
            "topic": "抽出の打ち切り",
            "detail": (f"上限に達したため、{'、'.join(sorted(facts.truncated))} の一部を"
                       "読み出していません。完全な一覧ではない前提で読んでください。"),
        })
    for r in reasons:
        unknowns.append({"topic": "作れなかった設問", "detail": r})
    if selection["notSelected"]:
        labels = []
        for row in selection["notSelected"]:
            if row["label"] not in labels:
                labels.append(row["label"])
        unknowns.append({
            "topic": "出題数の上限で採用しなかった設問",
            "detail": (f"根拠の揃った設問が {selection['candidates']} 問ありましたが、1 回の演習は "
                       f"{max_questions} 問までにしているため、次の種類の設問を一部出していません: "
                       f"{'、'.join(labels)}。根拠が足りなかったわけではありません。"),
        })

    facts_list = []
    for stage in stages:
        for q in stage["quizzes"]:
            facts_list.append({
                "title": q["explain"].split("\n\n", 1)[0],
                "category": q["category"],
                "evidenceIds": list(q["evidenceIds"]),
            })

    # カテゴリ別の数（旧来のキーを保つ）と、テンプレート別の数。どちらも
    # 選んだ設問から数える。
    question_counts = {"string": len(strings), "call": len(calls),
                       "external": len(externals), "limits": len(limits)}
    total = sum(question_counts.values())
    # 教材に残す根拠は、選んだ設問と段階の記録が指すものだけにする。
    used: set[str] = set()
    for stage in stages:
        for e in stage["events"]:
            used.update(e["evidenceIds"])
        for q in stage["quizzes"]:
            used.update(q["evidenceIds"])
            used.update(q.get("subjectEvidenceIds") or [])
    objectives = [text for template, text in (
        ("static.string-ref", "命令が参照するアドレスを、定義済み文字列の記録と突き合わせる"),
        ("static.string-referrer", "文字列のアドレスから、それを参照する命令と関数をたどる"),
        ("static.call", "呼び出し命令の行き先を、関数の入口アドレスから特定する"),
        ("static.caller", "関数の入口から、そこへの直接呼び出し命令を持つ関数をたどる"),
        ("static.external", "プログラム内の関数と、外部関数の記録を見分ける"),
        ("static.external-library", "外部関数のレコードから、保存された登録先を読む"),
    ) if selection["templateCounts"].get(template)]
    objectives.append("記録から言えることと、実行しないと分からないことを分ける")
    meta = {
        "schemaVersion": SCHEMA,
        "input": {"sha256": facts.input_sha256, "bytes": facts.input_bytes},
        "tool": {"ghidraVersion": facts.ghidra_version, "scriptVersion": facts.script_version,
                 **{k: image[k] for k in ("imageRef", "imageId", "scriptSha256",
                                          "baseImage", "arch") if k in image}},
        "program": {
            "name": name,
            "languageId": visible(facts.program["languageId"], 128),
            "compilerSpecId": visible(facts.program["compilerSpecId"], 64),
            "executableFormat": visible(facts.program["executableFormat"] or "", 120),
            "storedExecutableSha256": facts.program["storedExecutableSha256"],
            "imageBase": show_addr(facts.program["imageBase"]),
        },
        "counts": counts,
        "truncated": list(facts.truncated),
        "questionCounts": question_counts,
        "templateCounts": dict(selection["templateCounts"]),
        "skipped": list(reasons),
        "origin": origin,
        "sample": sample,
    }
    return {
        "id": lesson_id(facts.input_sha256),
        "kind": "static",
        "title": f"{name} — Ghidra 静的解析",
        "tagline": "Ghidra の保存済み解析情報から自動生成しました。使用前に内容を確認してください。",
        "difficulty": "入門",
        "family": "静的解析",
        "source": {
            "type": "generated-static",
            "note": "GZF に保存済みの解析情報から自動生成した演習です。対象プログラムは実行していません。",
        },
        "static": meta,
        "generator": {"quizTemplates": quiz_select.TEMPLATES_VERSION},
        "selection": selection,
        "evidence": {k: ev.items[k] for k in sorted(ev.items) if k in used},
        "introduction": {
            "kind": "static",
            "status": "draft",
            "scenario": (
                "Ghidra で解析して保存されたプログラムの記録を読み、命令・文字列・関数の"
                "つながりを確かめます。プログラムは動かさず、保存済みの記録だけを使います。"
            ),
            "objectives": objectives,
            "estimatedMinutes": 5 + 2 * total,
            "static": meta,
        },
        "report": {
            "timeline": [],
            "techniques": [],
            "facts": facts_list,
            "unknowns": unknowns,
            "nextInvestigations": [
                "Ghidra で同じアドレスを開き、前後の命令と引数の準備を読む",
                "参照（XREF）の一覧で、同じ文字列や関数を使っている別の箇所を確かめる",
                "間接呼び出しの行き先は、データの流れを追うか、隔離環境での動的解析で確かめる",
            ],
        },
        "recap": {
            "summary": (
                f"{name} の保存済み解析情報から、文字列の参照 {len(strings)} 問、直接呼び出し "
                f"{len(calls)} 問、外部関数 {len(externals)} 問、記録から言えないことの区別 "
                f"{len(limits)} 問の計 {total} 問を解きました。どれも静的に確認できる"
                "記録の読み方で、実行時の挙動は含みません。"
            ),
        },
        "stages": stages,
    }
