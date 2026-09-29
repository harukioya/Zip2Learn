"""quiz_select.py — 検証済みの設問候補から、1 回の演習で出す設問を選ぶ。

ログ教材（explain.py）と静的解析教材（static_lesson.py）の両方が使う。
テンプレートの数と、1 回に出す設問の数は別のものとして扱う。生成側は
根拠の揃った候補をテンプレートごとに作り、ここで上限までを選ぶ。候補が
足りなければ少ないまま返し、数を満たすために根拠の弱い設問を足さない。

選び方（`select`）。候補を 1 問ずつ貪欲に取る。毎回、次の順で比べて最小の
ものを取る。

  1. 取り済みの設問と「逆向き」の関係にならないこと（`_conflicts`）。
     同じ引用について、値を読む設問と、その行を根拠として選ばせる設問を
     並べると、一方がもう一方の答えを見せてしまう。避けられないときだけ使う。
  2. まだ使っていないテンプレートであること（同じ種類の 2 問目は後回し）。
  3. 取り済みの設問が少ないカテゴリであること。候補のあるカテゴリが、
     一つの種類に押し出され続けないようにする。
  4. 取り済みの設問が無い段階であること。
  5. テンプレートの優先順（`priority` の並び）。
  6. 候補として渡された順（生成側の決まった順）。

どれも入力だけから決まり、時刻や乱数を使わない。同じ入力からは同じ設問を
同じ順で選ぶ。選んだ設問は、渡された候補の並び（段階・生成の順）へ戻して
返すので、段階の中で出題の順が選んだ順に振り回されることもない。
"""

from __future__ import annotations

#: 1 回の演習で出す設問の上限（初期値）。
MAX_QUESTIONS = 8

#: 設問テンプレートと選び方の版。教材の `generator` に記録する。テンプレートや
#: 選び方を変えたら上げる。保存済みの教材は、この値ごとそのまま残る
#: （起動時に作り直したり書き換えたりはしない）。
TEMPLATES_VERSION = "quiz-templates/2"


def template_of(quiz: dict) -> str:
    """設問のテンプレート。識別子を持たない旧教材では設問 ID で代える。"""
    return quiz.get("templateId") or quiz.get("id") or ""


def _answer_evidence(quiz: dict) -> str | None:
    """根拠を選ばせる設問の、正解の証拠 ID。"""
    if quiz.get("type") != "evidence_pick":
        return None
    options = quiz.get("options") or []
    at = quiz.get("correct")
    if isinstance(at, int) and 0 <= at < len(options) and isinstance(options[at], dict):
        return options[at].get("evidenceId")
    return None


def _conflicts(a: dict, b: dict, reverse: frozenset) -> bool:
    """二つの設問が、同じ記録について逆向きの関係にあるか。

    * 一方が根拠を選ばせる設問で、その正解の行を、もう一方が解答前に対象と
      して示している（「○○ の N 行目について」「下に示した記録」）。
    * テンプレートの組が逆向きとして宣言されていて（`reverse`）、同じ根拠を
      使っている（命令→文字列 と 文字列→参照元の関数 など）。
    """
    for x, y in ((a, b), (b, a)):
        ans = _answer_evidence(x)
        if ans and ans in (y.get("subjectEvidenceIds") or []):
            return True
    pair = frozenset({template_of(a), template_of(b)})
    if len(pair) == 2 and pair in reverse:
        if set(a.get("evidenceIds") or []) & set(b.get("evidenceIds") or []):
            return True
    return False


def select(candidates: list[tuple[str, dict]], priority: list[str],
           limit: int | None = MAX_QUESTIONS,
           reverse: frozenset = frozenset()) -> list[tuple[str, dict]]:
    """`(段階 ID, 設問)` の候補から、上限までを決定的に選ぶ。

    戻り値も `(段階 ID, 設問)` の並びで、候補として渡された順を保つ。
    `limit` が None なら全部を返す（テンプレートの確認用）。
    """
    if limit is None or len(candidates) <= limit:
        return list(candidates)
    rank = {t: i for i, t in enumerate(priority)}
    chosen: list[int] = []
    used_templates: dict[str, int] = {}
    per_category: dict[str, int] = {}
    per_stage: dict[str, int] = {}
    left = list(range(len(candidates)))
    while left and len(chosen) < limit:
        def score(i: int) -> tuple:
            stage, quiz = candidates[i]
            clash = any(_conflicts(quiz, candidates[j][1], reverse) for j in chosen)
            return (
                1 if clash else 0,
                used_templates.get(template_of(quiz), 0),
                per_category.get(quiz.get("category", ""), 0),
                1 if per_stage.get(stage, 0) else 0,
                rank.get(template_of(quiz), len(rank)),
                i,
            )
        best = min(left, key=score)
        left.remove(best)
        chosen.append(best)
        stage, quiz = candidates[best]
        t = template_of(quiz)
        used_templates[t] = used_templates.get(t, 0) + 1
        c = quiz.get("category", "")
        per_category[c] = per_category.get(c, 0) + 1
        per_stage[stage] = per_stage.get(stage, 0) + 1
    return [candidates[i] for i in sorted(chosen)]


def summary(candidates: list[tuple[str, dict]], picked: list[tuple[str, dict]],
            limit: int | None, labels: dict[str, str],
            not_generated: list[dict]) -> dict:
    """教材に残す、選抜の記録。

    「根拠が足りず作れなかった」（`notGenerated`）と、「作れたが上限のため
    出さなかった」（`notSelected`）を分けて持つ。
    """
    kept = {id(q) for _, q in picked}
    counts: dict[str, int] = {}
    for _, q in picked:
        t = template_of(q)
        counts[t] = counts.get(t, 0) + 1
    return {
        "maxQuestions": limit,
        "candidates": len(candidates),
        "selected": len(picked),
        "templateCounts": {k: counts[k] for k in sorted(counts)},
        "notSelected": [
            {"id": q.get("id", ""), "templateId": template_of(q),
             "label": labels.get(template_of(q), template_of(q)),
             "reason": f"出題数の上限（{limit} 問）のため採用しませんでした。"}
            for _, q in candidates if id(q) not in kept
        ],
        "notGenerated": list(not_generated),
    }
