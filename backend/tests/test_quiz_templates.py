"""追加した設問テンプレート（ログ 4 種・静的解析 4 種）と、出題の選び方のテスト。

実データは使わない。端末名・パス・ホスト名・アドレスは、テストのために作った
値（RFC 2606 の example ドメイン、RFC 5737 の文書用アドレス）で組み立てる。

各テンプレートについて、次の四つを直接確かめる。8 問への選抜の結果だけを
見ると、実際には一度も作られないテンプレートを見落とすので、候補（上限なし）
と、テンプレートを作る関数そのものを見る。

  * 根拠が揃えば作られること（正常生成）
  * 根拠が足りなければ作られないこと
  * 誤答の候補が足りなければ作られないこと
  * 正解が複数になる入力を拒むこと
"""

from __future__ import annotations

import copy
import json
import os
import sys
import unittest
from unittest import mock

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

import evidence  # noqa: E402
import explain  # noqa: E402
import quiz_select  # noqa: E402
import static_facts as sf  # noqa: E402
import static_lesson as sl  # noqa: E402
import timeline  # noqa: E402
from parsers import InputSource, ParserRegistry  # noqa: E402
from parsers import itm2 as itm2_fmt  # noqa: E402
from parsers import proxy as proxy_fmt  # noqa: E402

import ghidra_fixtures as fx  # noqa: E402

ENDPOINT = "case/evidence/logs.zip :: logs/ws01.log"
OTHER = "case/evidence/logs.zip :: logs/ws02.log"
PROXY = "case/evidence/logs.zip :: logs/proxy.log"
FORMATS = ["itm2", "proxy"]


def itm2(ts, host="WS01", evt="ps", sub="start", ip="192.0.2.10", **fields) -> str:
    extra = " ".join(f'{k}="{v}"' for k, v in fields.items())
    return (f'{ts} loc=en-US type=ITM2 sn=1 lv=5 evt={evt} subEvt={sub} os=Win '
            f'com="{host}" ip={ip} {extra}')


def proxy(ts, ip="192.0.2.10", method="GET", target="http://files.example.net/x") -> str:
    return f'{ip} - - [{ts}] "{method} {target} HTTP/1.1" 200 42'


#: 端末 WS01 の記録。起動 4 種・ファイル操作 3 件。
ENDPOINT_TEXT = "\n".join([
    itm2("10/05/2022 14:00:00.000 +0900", psPath="C:\\Windows\\System32\\cmd.exe",
         cmd="cmd.exe /c whoami", parentPath="C:\\Windows\\explorer.exe"),
    itm2("10/05/2022 14:00:10.000 +0900", psPath="C:\\Windows\\System32\\notepad.exe",
         cmd="notepad.exe C:\\Users\\test\\report.docx"),
    itm2("10/05/2022 14:00:20.000 +0900", psPath="C:\\Tools\\copy.exe",
         cmd="copy.exe C:\\Users\\test\\AppData\\drop.dat D:\\backup"),
    itm2("10/05/2022 14:00:34.000 +0900", evt="file", sub="create",
         path="C:\\Users\\test\\AppData\\drop.dat"),
    itm2("10/05/2022 14:00:40.000 +0900", evt="file", sub="write",
         path="C:\\Users\\test\\report.docx"),
    itm2("10/05/2022 14:05:00.000 +0900", psPath="C:\\Windows\\System32\\ping.exe",
         cmd="ping.exe -n 1 host.example.com"),
    itm2("10/05/2022 14:09:00.000 +0900", evt="file", sub="create",
         path="C:\\Users\\test\\other.tmp"),
])

PROXY_TEXT = "\n".join([
    proxy("05/Oct/2022:14:00:05 +0900", method="CONNECT", target="update.example.com:443"),
    proxy("05/Oct/2022:14:30:00 +0900", target="http://files.example.net/x"),
    proxy("05/Oct/2022:14:40:00 +0900", ip="192.0.2.11", target="http://cdn.example.org/y.js"),
])


def build(sources=None, **kw):
    kw.setdefault("max_questions", None)
    return explain.build_lesson("t", sources or {ENDPOINT: ENDPOINT_TEXT, PROXY: PROXY_TEXT},
                                "gen-templates", parser_ids=FORMATS, **kw)


def all_quizzes(lesson):
    return [q for s in lesson["stages"] for q in s["quizzes"]]


def by_template(lesson, template):
    return [q for q in all_quizzes(lesson) if q.get("templateId") == template]


def excerpt(lesson, ident):
    return lesson["evidence"][ident]["source"]["excerpt"]


def not_generated(lesson, template):
    return next((r for r in lesson["selection"]["notGenerated"]
                 if r["templateId"] == template), None)


# ---------------------------------------------------------------------------
# パーサー側の読み直し（形式の知識はパーサーに置く）
# ---------------------------------------------------------------------------

class TestParserRereads(unittest.TestCase):

    def test_a_truncated_quoted_value_is_not_read(self):
        """保存用の切り詰めで引用符が閉じていない値を、項目の値として読まない。"""
        line = itm2("10/05/2022 14:00:00.000 +0900", psPath="C:\\W\\a.exe",
                    cmd="a.exe " + "x" * 1200)
        clipped = evidence.visible(line)
        self.assertTrue(clipped.endswith("…"))
        self.assertIsNone(itm2_fmt.PARSER.reread("process", "command_line", clipped))
        self.assertEqual(itm2_fmt.field_in(clipped, "cmd"), "")
        # 切れていない行なら読める。
        self.assertEqual(itm2_fmt.PARSER.reread("process", "command_line", line).value,
                         "a.exe " + "x" * 1200)

    def test_an_unquoted_value_cut_at_the_clip_mark_is_not_read(self):
        text = "evt=file subEvt=create path=" + "C:\\x" * 400
        clipped = evidence.visible(text)
        self.assertEqual(itm2_fmt.field_in(clipped, "path"), "")

    def test_command_line_is_read_from_cmd_only(self):
        """親プロセスの項目や引数に同じ文字列があっても、コマンドライン欄だけを読む。"""
        line = itm2("10/05/2022 14:00:00.000 +0900", psPath="C:\\W\\a.exe",
                    parentPath='C:\\W\\cmd.exe', parentCmd="cmd.exe /c a.exe")
        self.assertIsNone(itm2_fmt.PARSER.reread("process", "command_line", line))

    def test_file_operation_is_read_only_from_a_file_record(self):
        start = itm2("10/05/2022 14:00:00.000 +0900", psPath="", path="C:\\W\\a.exe")
        self.assertIsNone(itm2_fmt.PARSER.reread("file", "operation", start))
        write = itm2("10/05/2022 14:00:00.000 +0900", evt="file", sub="write", path="C:\\a")
        got = itm2_fmt.PARSER.reread("file", "operation", write)
        self.assertEqual((got.value, got.field), ("write", "subEvt"))
        self.assertEqual(itm2_fmt.PARSER.operation_label("file", "write"), "書き込み")
        self.assertEqual(itm2_fmt.PARSER.operation_label("file", "create"), "作成")
        self.assertEqual(itm2_fmt.PARSER.operation_label("file", "delete"), "")

    def test_proxy_target_is_the_second_word_of_the_request_as_written(self):
        line = proxy("05/Oct/2022:14:00:05 +0900", method="CONNECT", target="example.com:443")
        self.assertEqual(proxy_fmt.target(line), "example.com:443")
        url = proxy("05/Oct/2022:14:00:05 +0900", target="http://example.com/a/b?c=1")
        self.assertEqual(proxy_fmt.target(url), "http://example.com/a/b?c=1",
                         "URL をホスト名へ直さない")
        self.assertNotEqual(proxy_fmt.target(url), proxy_fmt.client(url))

    def test_proxy_target_cut_by_the_excerpt_limit_is_not_read(self):
        line = proxy("05/Oct/2022:14:00:05 +0900", target="http://example.com/" + "a" * 1200)
        self.assertEqual(proxy_fmt.target(evidence.visible(line)), "")

    def test_time_resolution_comes_from_the_written_digits(self):
        self.assertEqual(itm2_fmt.parse_timestamp("10/05/2022 14:00:00.750 +0900").resolution, 0.001)
        self.assertEqual(itm2_fmt.parse_timestamp("10/05/2022 14:00:00.7 +0900").resolution, 0.1)
        self.assertEqual(itm2_fmt.parse_timestamp("10/05/2022 14:00:00 +0900").resolution, 1.0)
        self.assertEqual(proxy_fmt.parse_timestamp("05/Oct/2022:14:00:05 +0900").resolution, 1.0)
        self.assertEqual(timeline.UNKNOWN.resolution, 0.0)


# ---------------------------------------------------------------------------
# Z1: 通信先の読み取り
# ---------------------------------------------------------------------------

class TestTargetTemplate(unittest.TestCase):

    def test_generated_and_grounded_in_the_cited_line(self):
        (quiz,) = by_template(build(), "log.network.target")
        lesson = build()
        (quiz,) = by_template(lesson, "log.network.target")
        cited = excerpt(lesson, quiz["evidenceIds"][0])
        answer = quiz["options"][quiz["correct"]]
        self.assertEqual(answer, proxy_fmt.target(cited))
        self.assertNotEqual(answer, proxy_fmt.client(cited), "要求元と取り違えていない")
        self.assertEqual(quiz["category"], "log-reading")
        self.assertEqual(quiz["subjectEvidenceIds"], quiz["evidenceIds"][:1])
        self.assertEqual(len(set(quiz["options"])), len(quiz["options"]))
        for option in quiz["options"]:
            self.assertIn(option, PROXY_TEXT, "誤答も実在する行の値")

    def test_values_keep_their_recorded_form(self):
        lesson = build()
        (quiz,) = by_template(lesson, "log.network.target")
        forms = {o for o in quiz["options"]}
        self.assertTrue(any("://" in o for o in forms) or any(":443" in o for o in forms))
        for o in forms:
            self.assertTrue(o in ("update.example.com:443", "http://files.example.net/x",
                                  "http://cdn.example.org/y.js"), o)

    def test_not_generated_without_a_readable_target(self):
        text = "\n".join([
            proxy("05/Oct/2022:14:00:05 +0900", target="http://a.example.com/" + "a" * 1200),
            proxy("05/Oct/2022:14:00:06 +0900", target="http://b.example.com/" + "b" * 1200),
        ])
        lesson = build({ENDPOINT: ENDPOINT_TEXT, PROXY: text})
        self.assertEqual(by_template(lesson, "log.network.target"), [])
        self.assertIn("通信先の読み取り", not_generated(lesson, "log.network.target")["reason"])

    def test_same_destination_in_another_form_is_not_a_distractor(self):
        """`host:443` と `http://host/...` はどちらもその宛先。誤答にすると正解が二つになる。"""
        text = "\n".join([
            proxy("05/Oct/2022:14:00:05 +0900", method="CONNECT", target="evil.example.com:443"),
            proxy("05/Oct/2022:14:00:06 +0900", target="http://EVIL.example.com/x"),
        ])
        lesson = build({ENDPOINT: ENDPOINT_TEXT, PROXY: text})
        self.assertEqual(by_template(lesson, "log.network.target"), [],
                         "誤答の候補が無いときは作らない")
        self.assertIsNotNone(not_generated(lesson, "log.network.target"))


# ---------------------------------------------------------------------------
# Z2: コマンドラインの読み取り
# ---------------------------------------------------------------------------

class TestCommandLineTemplate(unittest.TestCase):

    def test_generated_and_read_from_the_cmd_field(self):
        lesson = build()
        (quiz,) = by_template(lesson, "log.process.command-line")
        cited = excerpt(lesson, quiz["evidenceIds"][0])
        answer = quiz["options"][quiz["correct"]]
        self.assertEqual(answer, itm2_fmt.field_in(cited, "cmd"))
        self.assertIn("「cmd」", quiz["hint"])
        self.assertNotIn(answer, quiz["hint"])
        for option in quiz["options"]:
            self.assertIn(option, ENDPOINT_TEXT)

    def test_it_prefers_a_line_other_than_the_program_question(self):
        lesson = build()
        (cmd,) = by_template(lesson, "log.process.command-line")
        (prog,) = by_template(lesson, "log.process.program")
        self.assertNotEqual(cmd["evidenceIds"], prog["evidenceIds"])

    def test_a_clipped_command_line_is_never_the_answer(self):
        lines = [
            itm2("10/05/2022 14:00:00.000 +0900", psPath=f"C:\\W\\t{i}.exe",
                 cmd=f"t{i}.exe " + "x" * 1200)
            for i in range(3)
        ]
        lesson = build({ENDPOINT: "\n".join(lines)})
        self.assertEqual(by_template(lesson, "log.process.command-line"), [])

    def test_long_command_lines_are_not_offered(self):
        # 抜粋には収まる（切り詰められない）が、選択肢には長すぎる値。
        self.assertLess(explain.MAX_COMMAND_OPTION, 200)
        lines = [
            itm2("10/05/2022 14:00:00.000 +0900", psPath=f"C:\\W\\t{i}.exe",
                 cmd=f"t{i}.exe " + "y" * 200)
            for i in range(3)
        ]
        lesson = build({ENDPOINT: "\n".join(lines)})
        self.assertEqual(by_template(lesson, "log.process.command-line"), [])

    def test_values_that_differ_only_in_spacing_or_case_are_not_distractors(self):
        lines = [
            itm2("10/05/2022 14:00:00.000 +0900", psPath="C:\\W\\a.exe", cmd="a.exe /x  run"),
            itm2("10/05/2022 14:00:01.000 +0900", psPath="C:\\W\\b.exe", cmd="A.EXE /x run"),
        ]
        lesson = build({ENDPOINT: "\n".join(lines)})
        self.assertEqual(by_template(lesson, "log.process.command-line"), [],
                         "見分けられない値しか無ければ作らない")

    def test_different_commands_of_the_same_program_are_candidates(self):
        """回帰: 一覧は「端末＋プログラム名」で間引かれる。候補は間引く前から取る。"""
        cmds = ["cmd.exe /c whoami", "cmd.exe /c hostname", "cmd.exe /c ver"]
        text = "\n".join(
            itm2(f"10/05/2022 14:00:0{i}.000 +0900", psPath="C:\\W\\cmd.exe", cmd=c)
            for i, c in enumerate(cmds))
        lesson = build({ENDPOINT: text})
        (quiz,) = by_template(lesson, "log.process.command-line")
        self.assertEqual(sorted(quiz["options"]), sorted(cmds))
        self.assertIsNone(not_generated(lesson, "log.process.command-line"))
        # 誤答の値を読んだ行も、証拠表に実在する行として残る。
        excerpts = " ".join(excerpt(lesson, i) for i in quiz["distractorEvidenceIds"])
        for n, option in enumerate(quiz["options"]):
            if n != quiz["correct"]:
                self.assertIn(option, excerpts)
        self.assertEqual(itm2_fmt.field_in(excerpt(lesson, quiz["evidenceIds"][0]), "cmd"),
                         quiz["options"][quiz["correct"]])

    def test_a_long_first_candidate_does_not_block_usable_ones(self):
        """回帰: 長すぎる値を先に選んで諦めない。採用条件は選ぶ前に確かめる。"""
        text = "\n".join([
            itm2("10/05/2022 14:00:00.000 +0900", psPath="C:\\W\\a.exe", cmd="a.exe /x"),
            itm2("10/05/2022 14:00:01.000 +0900", psPath="C:\\W\\b.exe",
                 cmd="b.exe " + "y" * 180),
            itm2("10/05/2022 14:00:02.000 +0900", psPath="C:\\W\\c.exe", cmd="c.exe /z"),
        ])
        lesson = build({ENDPOINT: text})
        (quiz,) = by_template(lesson, "log.process.command-line")
        self.assertEqual(sorted(quiz["options"]), ["a.exe /x", "c.exe /z"])

    def test_only_the_chosen_lines_are_registered_as_evidence(self):
        """候補を間引く前から探しても、証拠表へ入れるのは使った行だけ。"""
        text = "\n".join(
            itm2(f"10/05/2022 11:{i // 60:02d}:{i % 60:02d}.000 +0900",
                 psPath="C:\\W\\cmd.exe", cmd=f"cmd.exe /c job{i}")
            for i in range(500))
        real = explain._lesson_event
        calls = []

        def counted(nev, store, readers=None):
            calls.append(nev)
            return real(nev, store, readers)

        with mock.patch.object(explain, "_lesson_event", counted):
            lesson = build({ENDPOINT: text})
        (quiz,) = by_template(lesson, "log.process.command-line")
        # 一覧の 1 件（間引き後）＋出題の行・誤答の行（最大 4）＋相関の組（最大 4）。
        self.assertLessEqual(len(calls), 1 + 4 + 4)

    def test_parent_fields_do_not_supply_the_answer(self):
        """コマンドライン欄が無い行は、親の項目に同じ文字列があっても対象にしない。"""
        lines = [
            itm2("10/05/2022 14:00:00.000 +0900", psPath="C:\\W\\a.exe",
                 parentPath="C:\\W\\b.exe", parentCmd="b.exe /c a.exe"),
            itm2("10/05/2022 14:00:01.000 +0900", psPath="C:\\W\\c.exe", cmd="c.exe /q"),
        ]
        lesson = build({ENDPOINT: "\n".join(lines)})
        self.assertEqual(by_template(lesson, "log.process.command-line"), [])


# ---------------------------------------------------------------------------
# Z3: 二つの記録の時間差
# ---------------------------------------------------------------------------

def candidates(*texts):
    events = []
    for name, text in texts:
        parser = itm2_fmt.PARSER if "ITM2" in text else proxy_fmt.PARSER
        events += parser.parse(InputSource(name, text), None)
    return explain.correlation_candidates(events)


class TestGapTemplate(unittest.TestCase):

    def test_generated_with_the_recomputable_gap(self):
        lesson = build()
        (quiz,) = by_template(lesson, "log.correlation.gap")
        self.assertEqual(quiz["options"][quiz["correct"]], f"{quiz['correlation']['gapSeconds']} 秒")
        shown = [excerpt(lesson, i) for i in quiz["evidenceIds"]]
        stamps = [itm2_fmt.parse_timestamp(x) for x in shown]
        self.assertEqual(round(stamps[1].sort - stamps[0].sort), quiz["correlation"]["gapSeconds"])
        self.assertEqual(quiz["subjectEvidenceIds"], quiz["evidenceIds"])
        self.assertEqual(quiz["optionKind"], "arithmetic-candidates")
        self.assertIn("出題のために作った数値の候補", quiz["explain"])
        self.assertIn("引き起こした", quiz["explain"])
        self.assertEqual(len(set(quiz["options"])), 4)

    def test_it_uses_a_different_pair_from_the_order_question_when_one_exists(self):
        lesson = build()
        (order,) = by_template(lesson, "log.correlation.order")
        (gap,) = by_template(lesson, "log.correlation.gap")
        self.assertFalse(set(order["evidenceIds"]) & set(gap["evidenceIds"]))
        stage = next(s for s in lesson["stages"] if s["id"] == "correlate")
        shown = {i for e in stage["events"] for i in e["evidenceIds"]}
        self.assertLessEqual(set(gap["evidenceIds"]) | set(order["evidenceIds"]), shown)

    def test_a_usable_pair_is_found_when_the_nearest_pair_is_not(self):
        """回帰: 最も近い組の精度が違っても、条件を満たす別の組で作る。"""
        endpoint = "\n".join([
            itm2("10/05/2022 14:00:00.000 +0900", psPath="C:\\W\\a.exe"),
            itm2("10/05/2022 14:00:10.000 +0900", evt="file", sub="create", path="C:\\a.dat"),
        ])
        alone = build({ENDPOINT: endpoint})
        self.assertEqual(by_template(alone, "log.correlation.gap")[0]["correlation"]["gapSeconds"], 10)
        lesson = build({ENDPOINT: endpoint, PROXY: proxy("05/Oct/2022:14:00:01 +0900")})
        (order,) = by_template(lesson, "log.correlation.order")
        self.assertEqual(order["correlation"]["gapSeconds"], 1.0, "前後の設問は最も近い組のまま")
        (gap,) = by_template(lesson, "log.correlation.gap")
        self.assertEqual(gap["options"][gap["correct"]], "10 秒")
        self.assertEqual(gap["correlation"]["resolutionSeconds"], 0.001)

    def test_an_integer_pair_is_used_when_the_nearest_gap_is_fractional(self):
        cands = candidates((ENDPOINT, "\n".join([
            itm2("10/05/2022 14:00:00.000 +0900", psPath="C:\\W\\a.exe"),
            itm2("10/05/2022 14:00:02.500 +0900", evt="file", sub="create", path="C:\\a.dat"),
            itm2("10/05/2022 14:00:07.000 +0900", evt="file", sub="write", path="C:\\b.dat"),
        ])))
        quiz, _, _ = explain._gap_quiz(evidence.EvidenceStore(), cands, "q", set())
        self.assertEqual(quiz["options"][quiz["correct"]], "7 秒")

    def test_fractional_gaps_are_not_asked(self):
        cands = candidates((ENDPOINT, "\n".join([
            itm2("10/05/2022 14:00:01.250 +0900", psPath="C:\\W\\a.exe"),
            itm2("10/05/2022 14:00:35.000 +0900", evt="file", sub="create", path="C:\\a.dat"),
        ])))
        quiz, why, pair = explain._gap_quiz(evidence.EvidenceStore(), cands, "q", set())
        self.assertIsNone(quiz)
        self.assertIn("整数秒", why)
        self.assertEqual(pair, [])

    def test_different_precision_is_not_asked(self):
        """秒までの記録とミリ秒までの記録の差は、端数が記録から決まらない。"""
        cands = candidates(
            (ENDPOINT, itm2("10/05/2022 14:00:00.000 +0900", psPath="C:\\W\\a.exe")),
            (PROXY, proxy("05/Oct/2022:14:00:05 +0900")),
        )
        quiz, why, _ = explain._gap_quiz(evidence.EvidenceStore(), cands, "q", set())
        self.assertIsNone(quiz)
        self.assertIn("同じ細かさ", why)

    def test_same_time_is_not_asked(self):
        same = "10/05/2022 14:00:01.000 +0900"
        cands = candidates((ENDPOINT, "\n".join([
            itm2(same, psPath="C:\\W\\a.exe"),
            itm2(same, evt="file", sub="create", path="C:\\a.dat"),
        ])))
        quiz, _, _ = explain._gap_quiz(evidence.EvidenceStore(), cands, "q", set())
        self.assertIsNone(quiz)

    def test_logs_without_timezone_are_not_compared_across_files(self):
        cands = candidates(
            (ENDPOINT, itm2("10/05/2022 14:00:00.000", psPath="C:\\W\\a.exe")),
            (OTHER, itm2("10/05/2022 14:00:10.000", evt="file", sub="create", path="C:\\a")),
        )
        quiz, _, _ = explain._gap_quiz(evidence.EvidenceStore(), cands, "q", set())
        self.assertIsNone(quiz)

    def test_float_error_does_not_turn_a_near_integer_into_an_integer(self):
        a = itm2_fmt.parse_timestamp("10/05/2022 14:00:00.100 +0900")
        b = itm2_fmt.parse_timestamp("10/05/2022 14:00:34.100 +0900")
        self.assertEqual(explain._recorded_gap_seconds(a, b), (34, ""))
        c = itm2_fmt.parse_timestamp("10/05/2022 14:00:34.101 +0900")
        self.assertIsNone(explain._recorded_gap_seconds(a, c)[0])
        d = itm2_fmt.parse_timestamp("10/05/2022 14:00:34.000001 +0900")
        e = itm2_fmt.parse_timestamp("10/05/2022 14:00:00.000000 +0900")
        self.assertIsNone(explain._recorded_gap_seconds(e, d)[0])

    def test_distractors_never_equal_the_answer(self):
        for seconds in (1, 2, 30, 59, 60):
            text = "\n".join([
                itm2("10/05/2022 14:00:00.000 +0900", psPath="C:\\W\\a.exe"),
                itm2(f"10/05/2022 14:{seconds // 60:02d}:{seconds % 60:02d}.000 +0900",
                     evt="file", sub="create", path="C:\\a.dat"),
            ])
            quiz, _, _ = explain._gap_quiz(evidence.EvidenceStore(),
                                           candidates((ENDPOINT, text)), "q", set())
            with self.subTest(seconds=seconds):
                self.assertEqual(quiz["options"].count(f"{seconds} 秒"), 1)
                self.assertEqual(quiz["options"][quiz["correct"]], f"{seconds} 秒")
                self.assertEqual(len(set(quiz["options"])), 4)


# ---------------------------------------------------------------------------
# Z4: ファイル操作の根拠選択
# ---------------------------------------------------------------------------

class TestFileEvidenceTemplate(unittest.TestCase):

    def test_generated_and_the_answer_proves_host_path_and_operation(self):
        lesson = build()
        (quiz,) = by_template(lesson, "log.file.evidence")
        self.assertEqual(quiz["type"], "evidence_pick")
        right = quiz["options"][quiz["correct"]]["evidenceId"]
        self.assertEqual([right], quiz["evidenceIds"])
        text = excerpt(lesson, right)
        reader = itm2_fmt.PARSER
        op = reader.operation_label("file", reader.reread("file", "operation", text).value)
        path = reader.reread("file", "path", text).value
        host = reader.reread("file", "host", text).value
        self.assertIn(f"端末 {host} で、{path} の{op}", quiz["q"])
        self.assertNotIn("subjectEvidenceIds", quiz, "根拠を先に見せない")

    def test_the_operation_is_named_as_recorded(self):
        """作成を「書き込み」と言い換えない。"""
        text = "\n".join([
            itm2("10/05/2022 14:00:00.000 +0900", evt="file", sub="create", path="C:\\a.dat"),
            itm2("10/05/2022 14:00:05.000 +0900", evt="file", sub="write", path="C:\\b.dat"),
        ])
        lesson = build({ENDPOINT: text})
        (quiz,) = by_template(lesson, "log.file.evidence")
        right = excerpt(lesson, quiz["evidenceIds"][0])
        if "subEvt=create" in right:
            self.assertIn("の作成が記録された", quiz["q"])
        else:
            self.assertIn("の書き込みが記録された", quiz["q"])

    def test_a_line_that_only_mentions_the_path_is_a_distractor_not_the_answer(self):
        lesson = build()
        (quiz,) = by_template(lesson, "log.file.evidence")
        right = quiz["options"][quiz["correct"]]["evidenceId"]
        path = itm2_fmt.PARSER.reread("file", "path", excerpt(lesson, right)).value
        mentions = [o["evidenceId"] for o in quiz["options"]
                    if o["evidenceId"] != right and path in excerpt(lesson, o["evidenceId"])]
        self.assertTrue(mentions, "パスを引数に含むだけの起動記録が誤答に並ぶ")
        for ident in mentions:
            self.assertIn("evt=ps", excerpt(lesson, ident))

    def test_another_line_proving_the_same_claim_is_not_a_distractor(self):
        store = evidence.EvidenceStore()
        text = "\n".join([
            itm2("10/05/2022 14:00:00.000 +0900", evt="file", sub="write", path="C:\\a.dat"),
            itm2("10/05/2022 14:00:09.000 +0900", evt="file", sub="write", path="C:\\a.dat"),
            itm2("10/05/2022 14:00:30.000 +0900", evt="file", sub="write", path="C:\\b.dat"),
        ])
        events = [explain._lesson_event(n, store)
                  for n in itm2_fmt.PARSER.parse(InputSource(ENDPOINT, text), None)]
        quiz = explain._file_evidence_quiz(store, events, [], set(), explain._Readers())
        right = quiz["evidenceIds"][0]
        ids = [o["evidenceId"] for o in quiz["options"]]
        self.assertEqual(len(ids), 2, "同じ主張を裏付ける 2 行目は誤答にしない")
        self.assertIn(events[2]["evidenceIds"][0], ids)
        self.assertIn(right, (events[0]["evidenceIds"][0], events[1]["evidenceIds"][0]))

    def test_not_generated_without_distractors(self):
        store = evidence.EvidenceStore()
        text = itm2("10/05/2022 14:00:00.000 +0900", evt="file", sub="write", path="C:\\a.dat")
        events = [explain._lesson_event(n, store)
                  for n in itm2_fmt.PARSER.parse(InputSource(ENDPOINT, text), None)]
        self.assertIsNone(explain._file_evidence_quiz(store, events, [], set(), explain._Readers()))

    def test_not_generated_when_the_parser_does_not_name_the_operation(self):
        class Unnamed(itm2_fmt.Itm2Parser):
            OPERATION_LABELS = {}

        lesson = explain.build_lesson("t", {ENDPOINT: ENDPOINT_TEXT}, "g",
                                      registry=ParserRegistry([Unnamed()]), max_questions=None)
        self.assertEqual(by_template(lesson, "log.file.evidence"), [])
        self.assertIn("ファイル操作の根拠選択", not_generated(lesson, "log.file.evidence")["reason"])


# ---------------------------------------------------------------------------
# 既存の根拠選択も、誤答が同じ主張を裏付けないこと
# ---------------------------------------------------------------------------

class TestEvidencePickDistractorsDoNotProveTheClaim(unittest.TestCase):

    def test_same_program_on_another_host_is_not_a_distractor(self):
        text = "\n".join([
            itm2("10/05/2022 14:00:00.000 +0900", "WS01", psPath="C:\\W\\cmd.exe", cmd="cmd.exe"),
            itm2("10/05/2022 14:00:01.000 +0900", "WS02", ip="192.0.2.20",
                 psPath="C:\\W\\cmd.exe", cmd="cmd.exe"),
            itm2("10/05/2022 14:00:02.000 +0900", "WS01", psPath="C:\\W\\calc.exe", cmd="calc.exe"),
        ])
        lesson = build({ENDPOINT: text})
        (quiz,) = by_template(lesson, "log.process.evidence")
        claim = quiz["q"].split("「", 1)[1].split(" が", 1)[0]
        for n, option in enumerate(quiz["options"]):
            if n != quiz["correct"]:
                self.assertNotEqual(itm2_fmt.program_name(excerpt(lesson, option["evidenceId"])),
                                    claim)


# ---------------------------------------------------------------------------
# ログ教材の選抜
# ---------------------------------------------------------------------------

class TestLogSelection(unittest.TestCase):

    def test_all_four_new_log_templates_are_generated_from_one_input(self):
        lesson = build()
        made = {q["templateId"] for q in all_quizzes(lesson)}
        self.assertLessEqual({"log.network.target", "log.process.command-line",
                              "log.correlation.gap", "log.file.evidence"}, made)

    def test_at_most_eight_and_every_category_is_kept(self):
        full = build()
        self.assertGreater(len(all_quizzes(full)), quiz_select.MAX_QUESTIONS)
        lesson = build(max_questions=quiz_select.MAX_QUESTIONS)
        picked = all_quizzes(lesson)
        self.assertEqual(len(picked), quiz_select.MAX_QUESTIONS)
        self.assertEqual({q["category"] for q in picked},
                         {q["category"] for q in all_quizzes(full)})
        self.assertEqual(len({q["templateId"] for q in picked}), len(picked),
                         "異なる種類を先に選ぶ")

    def test_selection_is_recorded_and_matches_what_is_shown(self):
        lesson = build(max_questions=8)
        sel = lesson["selection"]
        picked = all_quizzes(lesson)
        self.assertEqual(sel["selected"], len(picked))
        self.assertEqual(sel["candidates"], len(picked) + len(sel["notSelected"]))
        self.assertEqual(sum(sel["templateCounts"].values()), len(picked))
        self.assertEqual(lesson["generator"]["quizTemplates"], quiz_select.TEMPLATES_VERSION)
        topics = [u["topic"] for u in lesson["report"]["unknowns"]]
        self.assertIn("出題数の上限で採用しなかった設問", topics)
        for row in sel["notSelected"]:
            self.assertIn("上限", row["reason"])
        self.assertEqual(lesson["introduction"]["estimatedMinutes"],
                         max(5, 2 * len(picked) + len(lesson["stages"])))

    def test_no_empty_stage_and_no_dangling_evidence(self):
        lesson = build(max_questions=8)
        for stage in lesson["stages"]:
            self.assertTrue(stage["quizzes"] or stage.get("note"), stage["id"])
            for q in stage["quizzes"]:
                ids = list(q["evidenceIds"]) + list(q.get("subjectEvidenceIds") or [])
                ids += [o["evidenceId"] for o in q["options"] if isinstance(o, dict)]
                for i in ids:
                    self.assertIn(i, lesson["evidence"])

    def test_no_evidence_pick_answer_is_shown_as_another_question_subject(self):
        lesson = build(max_questions=8)
        subjects = {i for q in all_quizzes(lesson) for i in q.get("subjectEvidenceIds") or []}
        for q in all_quizzes(lesson):
            if q["type"] == "evidence_pick":
                self.assertNotIn(q["options"][q["correct"]]["evidenceId"], subjects, q["id"])

    def test_selection_is_deterministic(self):
        a = build(max_questions=8)
        b = build(max_questions=8)
        self.assertEqual(json.dumps(a, sort_keys=True), json.dumps(b, sort_keys=True))

    def test_small_inputs_are_not_padded(self):
        text = "\n".join([
            itm2("10/05/2022 14:00:00.000 +0900", psPath="C:\\W\\a.exe", cmd="a.exe"),
            itm2("10/05/2022 14:00:01.000 +0900", psPath="C:\\W\\b.exe", cmd="b.exe"),
        ])
        lesson = build({ENDPOINT: text}, max_questions=8)
        self.assertLess(len(all_quizzes(lesson)), 8)
        self.assertEqual(lesson["selection"]["notSelected"], [])


# ---------------------------------------------------------------------------
# 静的解析: 合成の事実（架空のプログラム）
# ---------------------------------------------------------------------------

def _a(off, space="ram"):
    return f"{space}:{off:016x}"


def rich_doc() -> dict:
    """新しい 4 種類がすべて成り立つ、架空のプログラムの抽出結果。

    * 同じ中身の文字列が別のアドレスに 2 つ（0x102000 と 0x102030）
    * 複数の関数から参照される文字列（0x102070）
    * thunk を経て内部関数 init_board へ解決される呼び出し
    * 登録先が 5 種類（大文字小文字違いの重複と、不明 <EXTERNAL> を含む）
    * 別のライブラリに登録された同名の外部関数（connect）
    """
    doc = fx.facts_doc()
    doc["functions"] += [
        fx._fn(0x101300, "save_score"),
        fx._fn(0x101340, "load_config"),
        fx._fn(0x101380, "net_send"),
        fx._fn(0x1013c0, "board_thunk", "fn:" + _a(0x101100)),
    ]
    doc["functions"].sort(key=lambda f: f["entry"])
    doc["externals"] += [
        fx._ext(0x28, "connect", "WS2_32.DLL"),
        fx._ext(0x30, "connect", "WSOCK32.DLL"),
        fx._ext(0x38, "CreateFileW", "KERNEL32.DLL"),
        fx._ext(0x40, "ExitProcess", "kernel32.dll"),
        fx._ext(0x48, "mystery", "<EXTERNAL>"),
        fx._ext(0x50, "blank", ""),
        fx._ext(0x58, "MessageBoxW", "USER32.DLL"),
    ]
    doc["strings"] += [fx._str(0x102070, "score.dat"), fx._str(0x102080, "config.ini")]
    doc["stringRefs"] += [
        fx._ref(0x101310, 0x101300, 0x102070),
        fx._ref(0x101350, 0x101340, 0x102070),
        fx._ref(0x101360, 0x101340, 0x102080),
    ]
    doc["calls"] += [
        fx._call(0x101320, 0x101300, "fn:" + _a(0x101190), _a(0x101190)),
        fx._call(0x101390, 0x101380, "fn:" + _a(0x1013c0), _a(0x1013c0), "fn:" + _a(0x101100)),
        fx._call(0x101370, 0x101340, "fn:" + _a(0x101180), _a(0x101180)),
    ]
    doc["stringRefs"].sort(key=lambda r: (r["from"], r["string"]))
    return doc


def parse(doc):
    return sf.parse(json.dumps(doc).encode(), expected_sha256=fx.PROGRAM_SHA,
                    expected_ghidra="12.1.4", expected_script="1.0.0")


def build_static(doc=None, **kw):
    kw.setdefault("max_questions", None)
    facts = parse(doc if doc is not None else rich_doc())
    return facts, sl.build(facts, image={}, origin={"kind": "upload", "name": "t.gzf"}, **kw)


def made(facts, maker):
    reasons = []
    return maker(facts, sl._Evidence(facts), reasons), reasons


class TestStaticFixtureIsValid(unittest.TestCase):
    def test_rich_doc_passes_the_contract(self):
        facts = parse(rich_doc())
        self.assertEqual(facts.truncated, [])


class TestStringReferrerTemplate(unittest.TestCase):

    def test_generated_and_verified(self):
        facts, lesson = build_static()
        qs = by_template(lesson, "static.string-referrer")
        self.assertTrue(qs)
        for q in qs:
            sid = q["answerCheck"]["string"]
            self.assertTrue(sl.verify_quiz(facts, q))
            refs = {r["function"] for r in facts.string_refs if r["string"] == sid}
            self.assertIn(q["optionIds"][q["correct"]], refs)
            for n, fid in enumerate(q["optionIds"]):
                if n != q["correct"]:
                    self.assertNotIn(fid, refs)

    def test_every_option_function_has_an_instruction_card(self):
        """正解の関数にだけ命令の記録があると、読まずに当てられる。"""
        facts, lesson = build_static()
        for stage in lesson["stages"]:
            for q in stage["quizzes"]:
                if q["templateId"] != "static.string-referrer":
                    continue
                shown = {lesson["evidence"][i]["source"]["function"]
                         for e in stage["events"] for i in e["evidenceIds"]
                         if lesson["evidence"][i]["kind"] == "instruction"}
                for fid in q["optionIds"]:
                    self.assertIn(facts.functions[fid]["name"], shown)

    def test_same_text_at_another_address_is_not_confused(self):
        facts, _ = build_static()
        quizzes, _ = made(facts, sl._referrer_questions)
        for q in quizzes:
            value = facts.strings[q["answerCheck"]["string"]]["value"]
            same = {s["id"] for s in facts.strings.values() if s["value"] == value}
            users = {r["function"] for r in facts.string_refs if r["string"] in same}
            for n, fid in enumerate(q["optionIds"]):
                if n != q["correct"]:
                    self.assertNotIn(fid, users)
            self.assertIn(sl.show_addr(facts.strings[q["answerCheck"]["string"]]["address"]), q["q"])

    def test_other_referrers_are_left_out_of_the_options(self):
        facts = parse(rich_doc())
        ev = sl._Evidence(facts)
        # score.dat は save_score と load_config の両方から参照される。1 種類
        # あたりの上限を外して、すべての文字列の設問を作らせる。
        sid = "str:" + _a(0x102070)
        with mock.patch.object(sl, "MAX_REFERRER_QUESTIONS", 100):
            q = next(q for q in sl._referrer_questions(facts, ev, [])
                     if q["answerCheck"]["string"] == sid)
        referrers = {"fn:" + _a(0x101300), "fn:" + _a(0x101340)}
        self.assertEqual(len(referrers & set(q["optionIds"])), 1)
        self.assertTrue(sl.verify_quiz(facts, q))
        self.assertIn("ほかの 1 個の関数からも参照", q["explain"])

    def test_restoring_an_omitted_reference_is_rejected(self):
        """省いた参照を戻すと誤答も正解になる入力を、検証が拒むこと。"""
        facts, lesson = build_static()
        q = by_template(lesson, "static.string-referrer")[0]
        wrong = q["optionIds"][(q["correct"] + 1) % 4]
        facts.string_refs.append({"from": _a(0x1019f0), "function": wrong,
                                  "string": q["answerCheck"]["string"],
                                  "instruction": "LEA RSI,[0x0]", "refType": "DATA"})
        self.assertFalse(sl.verify_quiz(facts, q))

    def test_truncation_rules(self):
        for listed, allowed in (("stringRefs", False), ("functions", True), ("strings", True),
                                ("calls", True), ("externals", True)):
            doc = rich_doc()
            doc["truncated"] = [listed]
            facts, lesson = build_static(doc)
            with self.subTest(truncated=listed):
                self.assertEqual(bool(by_template(lesson, "static.string-referrer")), allowed)
        doc = rich_doc()
        doc["truncated"] = ["stringRefs"]
        _, lesson = build_static(doc)
        self.assertIn("文字列の参照元", not_generated(lesson, "static.string-referrer")["reason"])

    def test_not_generated_without_enough_distractors(self):
        doc = rich_doc()
        keep = {"fn:" + _a(x) for x in (0x101100, 0x101180, 0x101200)}
        doc["functions"] = [f for f in doc["functions"] if f["id"] in keep or f["thunk"]]
        doc["functions"] = [f for f in doc["functions"] if not f["thunk"]]
        doc["stringRefs"] = [r for r in doc["stringRefs"] if r["function"] in keep]
        doc["calls"] = [c for c in doc["calls"]
                        if c["function"] in keep and c["target"] in keep]
        facts = parse(doc)
        quizzes, reasons = made(facts, sl._referrer_questions)
        self.assertEqual(quizzes, [])
        self.assertTrue(any("文字列の参照元" in r for r in reasons))

    def test_not_generated_without_references(self):
        doc = rich_doc()
        doc["stringRefs"] = []
        facts = parse(doc)
        quizzes, reasons = made(facts, sl._referrer_questions)
        self.assertEqual(quizzes, [])
        self.assertTrue(reasons)


class TestStaticDisplayEdgeCases(unittest.TestCase):
    """表示の切り詰め・制御文字・UTF-16・同名関数で、区別が失われないこと。"""

    def _referrer_for(self, doc, sid):
        facts = parse(doc)
        with mock.patch.object(sl, "MAX_REFERRER_QUESTIONS", 100):
            qs = sl._referrer_questions(facts, sl._Evidence(facts), [])
        return facts, next((q for q in qs if q["answerCheck"]["string"] == sid), None)

    def test_utf16_strings_are_measured_in_utf16_units(self):
        doc = rich_doc()
        value = "スコア🎮保存"
        s = next(s for s in doc["strings"] if s["id"] == "str:" + _a(0x102070))
        s["value"], s["length"] = value, sf.utf16_len(value)
        facts, q = self._referrer_for(doc, s["id"])
        self.assertIsNotNone(q, "UTF-16 で数えた長さが一致すれば使える")
        self.assertIn(value, q["q"])
        self.assertTrue(sl.verify_quiz(facts, q))

    def test_control_characters_and_clipped_strings_are_not_asked(self):
        for value, clipped in (("score‮.dat", False), ("score.dat", True)):
            doc = rich_doc()
            s = next(s for s in doc["strings"] if s["id"] == "str:" + _a(0x102070))
            s["value"] = value
            s["length"] = sf.utf16_len(value) + (10 if clipped else 0)
            s["clipped"] = clipped
            _, q = self._referrer_for(doc, s["id"])
            with self.subTest(value=value, clipped=clipped):
                self.assertIsNone(q)

    def test_same_named_functions_at_other_addresses_are_told_apart(self):
        doc = rich_doc()
        doc["functions"].append(fx._fn(0x101900, "draw"))
        doc["stringRefs"].append(fx._ref(0x101910, 0x101900, 0x102040))
        doc["stringRefs"].sort(key=lambda r: (r["from"], r["string"]))
        facts, lesson = build_static(doc)
        for q in by_template(lesson, "static.string-referrer") + by_template(lesson, "static.caller"):
            names = [facts.functions[i]["name"] for i in q["optionIds"]]
            self.assertEqual(len(set(names)), len(names), "同名の関数を選択肢に並べない")
            for label, fid in zip(q["options"], q["optionIds"]):
                self.assertIn(sl.show_addr(facts.functions[fid]["entry"]), label)


class TestCallerTemplate(unittest.TestCase):

    def test_generated_and_verified(self):
        facts, lesson = build_static()
        qs = by_template(lesson, "static.caller")
        self.assertTrue(qs)
        for q in qs:
            self.assertTrue(sl.verify_quiz(facts, q))
            self.assertNotIn("実際に呼び出した", q["q"])
            target = q["answerCheck"]["target"]
            callers = {c["function"] for c in facts.calls
                       if c["target"] == target and c["resolvedTarget"] is None}
            self.assertIn(q["optionIds"][q["correct"]], callers)

    def test_a_call_resolved_through_a_thunk_is_neither_answer_nor_distractor(self):
        """net_send は board_thunk（→ init_board）を呼ぶ。init_board への直接呼び出しではない。"""
        facts = parse(rich_doc())
        quizzes, _ = made(facts, sl._caller_questions)
        for q in quizzes:
            if q["answerCheck"]["target"] == "fn:" + _a(0x101100):
                self.assertNotIn("fn:" + _a(0x101380), q["optionIds"])
        # thunk 自身は問いの対象にしない。
        self.assertNotIn("fn:" + _a(0x1013c0), [q["answerCheck"]["target"] for q in quizzes])

    def test_restoring_an_omitted_call_is_rejected(self):
        facts, lesson = build_static()
        q = by_template(lesson, "static.caller")[0]
        wrong = q["optionIds"][(q["correct"] + 1) % 4]
        target = facts.functions[q["answerCheck"]["target"]]
        facts.calls.append({"from": _a(0x1019e0), "function": wrong, "mnemonic": "CALL",
                            "instruction": "CALL 0x0", "target": target["id"],
                            "targetAddress": target["entry"], "resolvedTarget": None})
        self.assertFalse(sl.verify_quiz(facts, q))

    def test_truncation_rules(self):
        for listed, allowed in (("calls", False), ("functions", True), ("stringRefs", True),
                                ("strings", True), ("externals", True)):
            doc = rich_doc()
            doc["truncated"] = [listed]
            _, lesson = build_static(doc)
            with self.subTest(truncated=listed):
                self.assertEqual(bool(by_template(lesson, "static.caller")), allowed)

    def test_indirect_and_unresolved_calls_are_not_filled_in(self):
        facts, lesson = build_static()
        for q in by_template(lesson, "static.caller"):
            self.assertIn("間接呼び出し", q["explain"])

    def test_not_generated_without_internal_direct_calls(self):
        doc = rich_doc()
        doc["calls"] = [c for c in doc["calls"] if c["resolvedTarget"] is not None]
        facts = parse(doc)
        quizzes, reasons = made(facts, sl._caller_questions)
        self.assertEqual(quizzes, [])
        self.assertTrue(any("直接呼び出し元" in r for r in reasons))

    def test_not_generated_without_enough_distractors(self):
        doc = rich_doc()
        keep = {"fn:" + _a(x) for x in (0x101100, 0x101150, 0x101200)}
        doc["functions"] = [f for f in doc["functions"] if f["id"] in keep]
        doc["stringRefs"] = [r for r in doc["stringRefs"] if r["function"] in keep]
        doc["calls"] = [c for c in doc["calls"] if c["function"] in keep and c["target"] in keep]
        facts = parse(doc)
        quizzes, _ = made(facts, sl._caller_questions)
        self.assertEqual(quizzes, [])


class TestLibraryTemplate(unittest.TestCase):

    def test_generated_and_verified(self):
        facts, lesson = build_static()
        (q,) = by_template(lesson, "static.external-library")
        self.assertTrue(sl.verify_quiz(facts, q))
        e = facts.externals[q["answerCheck"]["external"]]
        self.assertEqual(q["options"][q["correct"]], e["library"])
        self.assertIn(sl.show_addr(e["address"]), q["q"])
        self.assertEqual(q["subjectEvidenceIds"], [], "答えの書かれた記録へ解答前に飛ばさない")
        self.assertIn("読み込まれたこと", q["explain"])

    def test_unknown_libraries_are_never_options(self):
        _, lesson = build_static()
        (q,) = by_template(lesson, "static.external-library")
        for option in q["options"]:
            self.assertNotIn(option.strip(), ("", "<EXTERNAL>"))

    def test_libraries_differing_only_in_case_are_one_library(self):
        _, lesson = build_static()
        (q,) = by_template(lesson, "static.external-library")
        folded = [o.casefold() for o in q["options"]]
        self.assertEqual(len(set(folded)), 4)

    def test_same_named_external_elsewhere_is_not_used(self):
        facts = parse(rich_doc())
        ev = sl._Evidence(facts)
        for e in facts.externals.values():
            if not sl.library_name(e["library"]):
                continue
            quizzes = sl._library_questions(facts, ev, [])
            for q in quizzes:
                right = facts.externals[q["optionIds"][q["correct"]]]
                for n, i in enumerate(q["optionIds"]):
                    if n != q["correct"]:
                        self.assertNotEqual(facts.externals[i]["name"].casefold(),
                                            right["name"].casefold())

    def test_not_generated_with_unknown_or_too_few_libraries(self):
        facts, lesson = build_static(fx.facts_doc())
        self.assertEqual(by_template(lesson, "static.external-library"), [])
        self.assertIn("2 種類", not_generated(lesson, "static.external-library")["reason"])
        doc = rich_doc()
        for e in doc["externals"]:
            e["library"] = "<EXTERNAL>"
        _, lesson = build_static(doc)
        self.assertIn("0 種類", not_generated(lesson, "static.external-library")["reason"])

    def test_verify_rejects_a_duplicate_library(self):
        facts, lesson = build_static()
        (q,) = by_template(lesson, "static.external-library")
        bad = copy.deepcopy(q)
        wrong = (q["correct"] + 1) % 4
        facts.externals[bad["optionIds"][wrong]]["library"] = \
            facts.externals[q["answerCheck"]["external"]]["library"].lower()
        self.assertFalse(sl.verify_quiz(facts, bad))

    def test_truncation_does_not_block_it(self):
        for listed in ("externals", "functions", "calls", "stringRefs", "strings"):
            doc = rich_doc()
            doc["truncated"] = [listed]
            _, lesson = build_static(doc)
            with self.subTest(truncated=listed):
                self.assertTrue(by_template(lesson, "static.external-library"))


class TestStaticLimitsTemplate(unittest.TestCase):

    def test_generated_with_exactly_one_unconfirmable_option(self):
        facts, lesson = build_static()
        (q,) = by_template(lesson, "static.limits")
        self.assertTrue(sl.verify_quiz(facts, q))
        hyps = [n for n, i in enumerate(q["optionIds"]) if i.startswith("hypothesis:")]
        self.assertEqual(hyps, [q["correct"]])
        self.assertEqual(q["subjectEvidenceIds"], q["evidenceIds"])

    def test_verify_rejects_two_hypotheses_or_an_edited_fact(self):
        facts, lesson = build_static()
        (q,) = by_template(lesson, "static.limits")
        two = copy.deepcopy(q)
        wrong = (q["correct"] + 1) % 4
        two["optionIds"][wrong] = "hypothesis:count"
        two["options"][wrong] = dict(sl.CALL_HYPOTHESES)["count"]
        self.assertFalse(sl.verify_quiz(facts, two))
        edited = copy.deepcopy(q)
        edited["options"][wrong] = edited["options"][wrong].replace("ram:", "ram:9")
        self.assertFalse(sl.verify_quiz(facts, edited))

    def test_falls_back_to_a_string_reference(self):
        doc = rich_doc()
        doc["calls"] = []
        facts, lesson = build_static(doc)
        (q,) = by_template(lesson, "static.limits")
        self.assertEqual(q["answerCheck"]["subject"], "string-ref")
        self.assertTrue(sl.verify_quiz(facts, q))

    def test_not_generated_without_any_instruction_record(self):
        doc = rich_doc()
        doc["calls"], doc["stringRefs"] = [], []
        facts = parse(doc)
        quizzes, reasons = made(facts, sl._limits_questions)
        self.assertEqual(quizzes, [])
        self.assertTrue(any("判断の限界" in r for r in reasons))

    def test_hints_never_ask_to_run_the_program(self):
        for text in sl.LIMITS_HINTS + sl.REFERRER_HINTS + sl.CALLER_HINTS + sl.LIBRARY_HINTS:
            for banned in ("実行して", "動かして", "起動して", "デバッガ"):
                self.assertNotIn(banned, text)


class TestStaticSelection(unittest.TestCase):

    def test_all_seven_templates_are_generated_from_the_synthetic_input(self):
        _, lesson = build_static()
        self.assertEqual({q["templateId"] for q in all_quizzes(lesson)}, set(sl.TEMPLATES))

    def test_at_most_eight_with_every_template_first(self):
        _, full = build_static()
        self.assertGreater(len(all_quizzes(full)), 8)
        facts, lesson = build_static(max_questions=8)
        picked = all_quizzes(lesson)
        self.assertEqual(len(picked), 8)
        self.assertEqual({q["templateId"] for q in picked}, set(sl.TEMPLATES))
        for q in picked:
            self.assertTrue(sl.verify_quiz(facts, q), q["id"])
        counts = lesson["static"]["questionCounts"]
        self.assertEqual(sum(counts.values()), 8)
        self.assertEqual(lesson["introduction"]["estimatedMinutes"], 5 + 2 * 8)
        self.assertEqual(lesson["selection"]["selected"], 8)

    def test_stages_are_numbered_after_selection_and_evidence_is_trimmed(self):
        _, lesson = build_static(max_questions=8)
        names = [s["name"] for s in lesson["stages"]]
        self.assertEqual([n.split(" — ")[0] for n in names],
                         [f"段階{i + 1}" for i in range(len(names))])
        used = set()
        for s in lesson["stages"]:
            self.assertTrue(s["quizzes"])
            for e in s["events"]:
                used.update(e["evidenceIds"])
            for q in s["quizzes"]:
                used.update(q["evidenceIds"])
                shown = {i for e in s["events"] for i in e["evidenceIds"]}
                for i in q["evidenceIds"] + q["subjectEvidenceIds"]:
                    self.assertIn(i, shown, "jump target must be on the stage")
        self.assertEqual(set(lesson["evidence"]), used)

    def test_forward_and_reverse_on_the_same_instruction_are_not_both_picked(self):
        facts, lesson = build_static(max_questions=8)
        picked = all_quizzes(lesson)
        for a in picked:
            for b in picked:
                pair = frozenset({a["templateId"], b["templateId"]})
                if pair in sl.REVERSE_TEMPLATES:
                    self.assertFalse(set(a["evidenceIds"]) & set(b["evidenceIds"]),
                                     (a["id"], b["id"]))

    def test_deterministic(self):
        _, a = build_static(max_questions=8)
        _, b = build_static(max_questions=8)
        self.assertEqual(json.dumps(a, sort_keys=True), json.dumps(b, sort_keys=True))

    def test_bundled_sample_generates_the_expected_kinds(self):
        """同梱サンプル（事前抽出）では、登録先の設問は出ない（記録が <EXTERNAL> だけ）。"""
        here = os.path.dirname(os.path.abspath(__file__))
        with open(os.path.join(here, "fixtures", "ghidra", "termmines-facts.json"),
                  encoding="utf-8") as fh:
            doc = json.load(fh)["facts"]
        facts = sf.parse(json.dumps(doc).encode(), expected_sha256=doc["input"]["sha256"],
                         expected_ghidra="12.1.4", expected_script="1.0.0")
        lesson = sl.build(facts, image={}, origin={"kind": "sample"})
        made_ids = {q["templateId"] for q in all_quizzes(lesson)}
        self.assertEqual(made_ids, set(sl.TEMPLATES) - {"static.external-library"})
        self.assertLessEqual(len(all_quizzes(lesson)), 8)
        self.assertIn("<EXTERNAL>", not_generated(lesson, "static.external-library")["reason"])
        for q in all_quizzes(lesson):
            self.assertTrue(sl.verify_quiz(facts, q), q["id"])


# ---------------------------------------------------------------------------
# 選び方そのもの
# ---------------------------------------------------------------------------

def _q(qid, template, category, ev=(), subj=(), pick=False):
    q = {"id": qid, "templateId": template, "category": category,
         "evidenceIds": list(ev), "subjectEvidenceIds": list(subj),
         "type": "evidence_pick" if pick else "single_choice", "options": [], "correct": 0}
    if pick:
        q["options"] = [{"evidenceId": ev[0]}]
    return q


class TestSelector(unittest.TestCase):

    def test_under_the_limit_everything_is_kept_in_order(self):
        cands = [("s", _q(str(i), f"t{i}", "c")) for i in range(3)]
        self.assertEqual(quiz_select.select(cands, [], 8), cands)
        self.assertEqual(quiz_select.select(cands * 4, [], None), cands * 4)

    def test_distinct_templates_before_repeats(self):
        cands = [("s", _q("a1", "a", "x")), ("s", _q("a2", "a", "x")),
                 ("s", _q("b1", "b", "y")), ("s", _q("c1", "c", "z"))]
        got = [q["id"] for _, q in quiz_select.select(cands, ["a", "b", "c"], 3)]
        self.assertEqual(got, ["a1", "b1", "c1"])

    def test_a_category_is_not_crowded_out(self):
        cands = [("s", _q(f"r{i}", f"r{i}", "reading")) for i in range(6)]
        cands.append(("s", _q("z", "z", "rare")))
        got = [q["id"] for _, q in quiz_select.select(cands, [f"r{i}" for i in range(6)] + ["z"], 2)]
        self.assertIn("z", got)

    def test_reverse_pairs_are_avoided_when_possible(self):
        cands = [("s", _q("read", "read", "x", ev=["e1"], subj=["e1"])),
                 ("s", _q("pick", "pick", "y", ev=["e1"], pick=True)),
                 ("s", _q("pick2", "pick2", "y", ev=["e2"], pick=True))]
        got = [q["id"] for _, q in quiz_select.select(cands, ["read", "pick", "pick2"], 2)]
        self.assertEqual(got, ["read", "pick2"])

    def test_old_quizzes_without_template_ids_are_handled(self):
        old = {"id": "q-old", "category": "log-reading"}
        self.assertEqual(quiz_select.template_of(old), "q-old")
        cands = [("s", old), ("s", dict(old, id="q-old-2"))]
        self.assertEqual(len(quiz_select.select(cands, [], 1)), 1)


if __name__ == "__main__":
    unittest.main(verbosity=2)
