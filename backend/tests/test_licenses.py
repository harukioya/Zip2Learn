"""第三者ライセンスの同梱と、アプリ内で読む経路のテスト。

  * 同梱した MITRE ATT&CK のライセンスが、記録した原文（SHA-256）のまま残っていること
  * アプリの /api/licenses/<名前> が、固定の対応表にあるファイルだけを返すこと
    （静的配信の許可は広げていない）
  * 第三者表記と README の相対リンクが、実在するファイルを指していること
"""

import hashlib
import http.client
import os
import re
import sys
import threading
import unittest
from http.server import ThreadingHTTPServer

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

import api  # noqa: E402

REPO = os.path.dirname(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
ATTACK_LICENSE = os.path.join(REPO, "third_party", "mitre-attack", "LICENSE.txt")
#: 2026-09-29 に公式（attack-stix-data の LICENSE.txt）から取得した原文の SHA-256。
ATTACK_LICENSE_SHA256 = "738144f7fb054722a4ef9d3367c51710341dc12fc574c6ac3a41daaaecd8bf5e"


def read(*parts):
    with open(os.path.join(REPO, *parts), encoding="utf-8") as fh:
        return fh.read()


class TestBundledAttackLicense(unittest.TestCase):
    def test_license_is_the_unmodified_official_text(self):
        with open(ATTACK_LICENSE, "rb") as fh:
            body = fh.read()
        self.assertEqual(hashlib.sha256(body).hexdigest(), ATTACK_LICENSE_SHA256)
        text = body.decode("utf-8")
        self.assertIn("The MITRE Corporation (MITRE) hereby grants you", text)
        self.assertIn("The MITRE Corporation. This work is reproduced and distributed", text)
        self.assertIn("Disclaimers", text)

    def test_notices_record_source_hash_and_the_unknown_adopted_version(self):
        notices = " ".join(read("THIRD_PARTY_NOTICES.md").split())
        self.assertIn("third_party/mitre-attack/LICENSE.txt", notices)
        self.assertIn(ATTACK_LICENSE_SHA256, notices)
        self.assertIn("attack-stix-data/master/LICENSE.txt", notices)
        self.assertIn("ログ教材の手法 ID・名称", notices)
        # ライセンスを確認した日と、手法情報の採用版は別のこと。採用版は推測で埋めない。
        self.assertIn("ライセンスを取得・確認した日", notices)
        self.assertIn("手法情報の採用版 | **不明（記録なし）**", notices)
        self.assertIn("承認・推奨・支援を受けたものではありません", notices)

    def test_first_mentions_carry_the_registered_mark(self):
        self.assertIn("MITRE ATT&CK®", read("js", "home.js"))
        self.assertIn("MITRE ATT&CK®", read("js", "intro.js"))
        self.assertIn("MITRE ATT&CK®", read("js", "recap.js"))


class TestDocumentLinks(unittest.TestCase):
    """相対リンクの行き先が実在すること。存在しない節を参照していた不具合の再発を防ぐ。"""

    LINK = re.compile(r"\]\(([^)\s]+)\)")

    def test_relative_links_point_to_existing_files(self):
        for doc in ("THIRD_PARTY_NOTICES.md", "README.md"):
            for target in self.LINK.findall(read(doc)):
                if re.match(r"[a-z]+:", target):
                    continue
                path = target.split("#", 1)[0]
                if not path:
                    continue
                with self.subTest(doc=doc, target=target):
                    self.assertTrue(os.path.exists(os.path.join(REPO, path)), target)

    def test_notices_no_longer_point_to_missing_readme_sections(self):
        notices = read("THIRD_PARTY_NOTICES.md")
        self.assertNotIn("README の「", notices)
        self.assertIn("### Docker", notices)
        self.assertIn("THIRD_PARTY_NOTICES.md#docker", read("README.md"))

    def test_readme_states_the_dependency_scope(self):
        readme = " ".join(read("README.md").split())
        self.assertNotIn("外部のライブラリは使っていません", readme)
        self.assertIn("Python 標準ライブラリとブラウザ標準機能で動作し", readme)
        self.assertIn("追加の Python・JavaScript パッケージは不要", readme)


class TestLicenseRoute(unittest.TestCase):
    """学生の権限（読むだけ）で、同梱したライセンス本文を読めること。"""

    def setUp(self):
        state = api.State.__new__(api.State)
        state.role = "student"
        state.caps = set(api.ROLE_CAPS["student"])
        state.token = "tok"
        state.lock = threading.Lock()
        orig_state = api.STATE
        api.STATE = state
        self.addCleanup(setattr, api, "STATE", orig_state)
        self.httpd = ThreadingHTTPServer(("127.0.0.1", 0), api.Handler)
        self.port = self.httpd.server_address[1]
        orig_hosts = api.ALLOWED_HOSTS
        api.ALLOWED_HOSTS = frozenset({f"127.0.0.1:{self.port}"})
        self.addCleanup(setattr, api, "ALLOWED_HOSTS", orig_hosts)
        threading.Thread(target=self.httpd.serve_forever, daemon=True).start()
        self.addCleanup(self.httpd.server_close)
        self.addCleanup(self.httpd.shutdown)

    def get(self, path):
        conn = http.client.HTTPConnection("127.0.0.1", self.port, timeout=10)
        conn.request("GET", path, headers={"Host": f"127.0.0.1:{self.port}"})
        res = conn.getresponse()
        body = res.read()
        conn.close()
        return res.status, res.getheader("Content-Type"), body

    def test_every_listed_file_exists_and_is_served_verbatim(self):
        for name, rel in api.LICENSE_FILES.items():
            with self.subTest(name=name):
                with open(os.path.join(REPO, rel), "rb") as fh:
                    expected = fh.read()
                status, ctype, body = self.get(f"/api/licenses/{name}")
                self.assertEqual(status, 200)
                self.assertEqual(ctype, "text/plain; charset=utf-8")
                self.assertEqual(body, expected)

    def test_unknown_names_and_paths_are_refused(self):
        for path in ("/api/licenses/readme", "/api/licenses/..%2FREADME.md",
                     "/api/licenses/../README.md", "/api/licenses/NOTICES"):
            with self.subTest(path=path):
                self.assertEqual(self.get(path)[0], 404)

    def test_static_serving_is_not_widened(self):
        for path in ("/THIRD_PARTY_NOTICES.md", "/third_party/mitre-attack/LICENSE.txt",
                     "/ghidra/sample/LICENSE-Apache-2.0.txt", "/README.md"):
            with self.subTest(path=path):
                self.assertEqual(self.get(path)[0], 404)
        self.assertEqual(set(api.STATIC_DIRS), {"js", "styles", "data"})


if __name__ == "__main__":
    unittest.main(verbosity=2)
