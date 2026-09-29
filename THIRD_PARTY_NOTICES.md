# 第三者ソフトウェアと同梱物の一覧

確認日: 2026-09-27（MITRE ATT&CK® と Docker の節は 2026-09-29）。版を上げたとき・配布するときは、
各リンク先で条件を確認し直してください。

アプリの中では、画面下部の「第三者ソフトウェアとライセンス」（`#/licenses`）から、この一覧と
同梱したライセンス本文を読めます。本文はリポジトリの同梱ファイルを表示するので、オフラインでも読めます。

このリポジトリは、アプリ本体（Python 標準ライブラリだけで動くコードと画面）に加えて、
Ghidra 静的解析教材のためのファイルを含みます。**処理イメージそのもの（Ghidra・JDK・
ベース OS を含むもの）は配布しません。** 利用者の PC の Docker が、下の固定した取得先から
取得して組み立てます。

## リポジトリに含むもの

### termmines.c（Ghidra 公式教材）

| 項目 | 内容 |
|---|---|
| ファイル | [ghidra/sample/termmines.c](ghidra/sample/termmines.c)（**無改変の写し**） |
| 出典 | <https://github.com/NationalSecurityAgency/ghidra/blob/Ghidra_12.1.4_build/GhidraDocs/GhidraClass/ExerciseFiles/Debugger/termmines.c> |
| 採用したコミット | タグ `Ghidra_12.1.4_build` = `8b6bbb857accdfa20dc5b2f5dea471178c2e9fbc` |
| SHA-256 | `a30710cc0ff4e1e8136ec2164c235e201a969672cf6f5a5aceea95d81d6e13d2` |
| ライセンス | Apache License 2.0（ファイル冒頭の表示を保持）。全文: [ghidra/sample/LICENSE-Apache-2.0.txt](ghidra/sample/LICENSE-Apache-2.0.txt) |
| NOTICE | Ghidra の NOTICE の写し: [ghidra/sample/NOTICE-Ghidra.txt](ghidra/sample/NOTICE-Ghidra.txt) |

マルウェアではなく、解析練習用の端末版マインスイーパーです。

### termmines.gzf（上のソースから作った派生物）

| 項目 | 内容 |
|---|---|
| ファイル | [ghidra/sample/termmines.gzf](ghidra/sample/termmines.gzf) |
| 変更の表示 | termmines.c を **gcc でコンパイル**し（linux/amd64、`-O0`、strip なし）、**Ghidra 12.1.4 で自動解析して GZF として保存**したもの。ソースの内容は変更していない |
| 作り方・記録 | [ghidra/sample/PROVENANCE.md](ghidra/sample/PROVENANCE.md)、[build_sample.py](ghidra/sample/build_sample.py)、`toolchain.txt`、`sample.json` |
| 含まれるもの | termmines のコンパイル結果（Apache 2.0）と、その Ghidra 解析データベース |
| 静的にリンクされた部品 | 解析結果の関数一覧で確認（2026-09-27）。glibc の起動用オブジェクト（`_start`・`_init`・`_fini`）と、`libc_nonshared.a` の `atexit`（どちらも LGPL 2.1 以降。ファイルに「リンクしたプログラムを制限なく配布してよい」という例外条項あり: [start.S](https://github.com/bminor/glibc/blob/glibc-2.39/sysdeps/x86_64/start.S)、[atexit.c](https://github.com/bminor/glibc/blob/glibc-2.39/stdlib/atexit.c)）。GCC の起動用オブジェクト（`register_tm_clones`・`__do_global_dtors_aux` など。GPL 3 + [GCC Runtime Library Exception 3.1](https://www.gnu.org/licenses/gcc-exception-3.1.html)） |
| 含まれないもの | 共有ライブラリ（libc、libncurses、libtinfo、libpthread）の本体。GZF には関数名などの参照だけが残る |

GZF には元のプログラムの内容（コンパイル結果のバイト列）が含まれる前提で、上の条件を確認しています。
GZF の中に記録された情報も確認しました（2026-09-27）。実行ファイルの場所はコンテナ内のパス
（`/in/termmines`）、作成者は固定値 `zip2learn`、ほかにコンパイラの版の文字列だけで、手元のパス・
利用者名・ホスト名は含まれていません。

### termmines-facts.json（テスト用の固定データ）

| 項目 | 内容 |
|---|---|
| ファイル | `backend/tests/fixtures/ghidra/termmines-facts.json` |
| 中身 | 上の termmines.gzf から、アプリの抽出スクリプトが取り出した関数名・文字列・命令の一覧（Ghidra 12.1.4 の実出力） |
| ライセンス | termmines の派生物として Apache License 2.0（上と同じ表示を適用） |

`backend/tests/fixtures/ghidra/static-lesson.json` は、テスト用の架空のデータから作ったもので、
第三者の著作物を含みません。

### 名称について

Ghidra は米国国家安全保障局（NSA）が公開しているソフトウェアです。このプロジェクトは NSA や
Ghidra プロジェクトとは関係がなく、承認や推奨を受けたものではありません。名称は、使用している
ソフトウェアを示すためだけに用いています（Apache License 2.0 第 6 条は商標の使用を許諾しません）。

## リポジトリに含めないもの

開発中のテストには、Ghidra 公式教材の他の練習用プログラム（`WinHelloCPP.exe`、`WallaceSrc.exe`、
`animals` など。いずれも Ghidra の管理ファイル上は Apache 2.0）から作った GZF も使いましたが、
リポジトリの外に置き、同梱していません。Windows 向けのものは、コンパイラの実行時ライブラリの
配布条件をこちらで確かめていないためです。同梱する場合は、先に確認してください。

## 利用者の PC で取得するもの（リポジトリには含まない）

### Ghidra 12.1.4

| 項目 | 内容 |
|---|---|
| 取得先 | <https://github.com/NationalSecurityAgency/ghidra/releases/tag/Ghidra_12.1.4_build>（`ghidra_12.1.4_PUBLIC_20260921.zip`） |
| 照合 | SHA-256 `ddac49f903da9d5bac833e5cc79395098b9c33cfd3279be5f31bd00387d2d4db`（公式リリースページの値。Dockerfile の `ADD --checksum` で照合） |
| ライセンス | Apache License 2.0。米国政府職員が作成した部分は米国内で著作権の対象外（Ghidra の NOTICE を参照） |
| 注意 | Ghidra の各モジュールには、それぞれの第三者部品と LICENSE.txt があり、配布物の `licenses/` にライセンス本文がある。**Ghidra 全体・イメージ全体を単一のライセンスとは表示しない** |

### ベースイメージ（Eclipse Temurin JDK 21、Ubuntu 24.04）

| 項目 | 内容 |
|---|---|
| 取得先 | Docker Hub 公式イメージ `eclipse-temurin:21.0.12.1_1-jdk-noble` |
| 照合 | index digest `sha256:d1eb0297924c2d5a37ba7042a59ae84a3487e086b077ac054019a423767d4311` に固定（amd64 / arm64 を含む） |
| ライセンス | OpenJDK（Eclipse Temurin）は GPL 2 + Classpath Exception ほか。ベースの Ubuntu のパッケージはそれぞれのライセンス。詳細: <https://adoptium.net/about/>、<https://hub.docker.com/_/eclipse-temurin>、<https://ubuntu.com/legal/intellectual-property-policy> |

### Docker

| 項目 | 内容 |
|---|---|
| 用途 | Ghidra 静的解析教材の処理イメージを、利用者の PC で取得・構築・実行するためだけに使う（ログ教材には不要） |
| 同梱・導入 | **同梱しない。自動インストールもしない。** 利用者が自分で導入する |
| 利用条件 | <https://docs.docker.com/subscription-billing/desktop-license/>（確認日: 2026-09-29） |

- Docker Engine（Moby などのオープンソースのプロジェクト）と Docker Desktop では、ライセンス・利用条件の
  扱いが異なります。Docker Desktop は Docker Subscription Service Agreement の対象です。
- Docker Desktop には、個人利用・教育・非商用のオープンソースプロジェクト・一定規模未満の小規模事業者など、
  無料で使える条件があります。一方で、規模の大きい組織での業務利用や政府機関での利用などでは、有料の
  契約が必要です。
- 大学・研究室での利用も、組織の規模や用途によって扱いが変わりえます。「無料で使える」と一律には
  言えません。条件は変わることがあるため、導入・利用の前に上の公式ページで最新の条件を確認してください。

## 画面・教材に表示するもの

### MITRE ATT&CK®

| 項目 | 内容 |
|---|---|
| 使用範囲 | **ログ教材の手法 ID・名称**。`backend/attck.py` の対応規則に書いた ID と名前を、記録の説明と最終レポートの「MITRE ATT&CK® との対応」に表示する。Ghidra の静的解析教材では使わない。ATT&CK のデータセット（STIX など）は同梱しない |
| 出典 | <https://attack.mitre.org/> |
| 利用条件 | <https://attack.mitre.org/resources/legal-and-branding/terms-of-use/>（<https://attack.mitre.org/resources/terms-of-use/> から転送される）。名称の表記: <https://attack.mitre.org/resources/faq/#legal> |
| 同梱したライセンス | [third_party/mitre-attack/LICENSE.txt](third_party/mitre-attack/LICENSE.txt)（著作権表示・ライセンス・免責を含む公式原文。**無改変**。著作権年も原文のまま） |
| ライセンスの取得元 | <https://raw.githubusercontent.com/mitre-attack/attack-stix-data/master/LICENSE.txt>。取得時の `master` は `6cda5ad8462c79e14fbb872f4e09059b18e0cfc4`（このコミットの LICENSE.txt と同一であることを確認）。LICENSE.txt を最後に変更したコミットは `3aba8a0e56096f2d7e966f4492f592106a7aa8e5`（2026-04-28、著作権年の更新） |
| ライセンスを取得・確認した日 | 2026-09-29。SHA-256 `738144f7fb054722a4ef9d3367c51710341dc12fc574c6ac3a41daaaecd8bf5e`。同日、利用条件のページの本文と同じ内容であることも確認した |
| 手法情報の採用版 | **不明（記録なし）**。手法 ID・名称は `backend/attck.py` に直接書かれており、どの ATT&CK のリリースから、いつ取ったかはリポジトリに記録されていない。上の「ライセンスを取得・確認した日」は、手法情報を取得した日ではない。名前には公式名を短くしたものがある（例: T1547.001 を「Boot or Logon Autostart: Registry Run Keys」と表示）。教材に残す `ruleVersion`（例: `2026-09-zip2learn-3`）は本アプリの対応規則の版で、ATT&CK の版ではない |

- 記録と手法の対応付け、およびそれを使った教材の生成は Zip2Learn 独自のものです。The MITRE Corporation
  （MITRE）の承認・推奨・支援を受けたものではありません。
- MITRE ATT&CK と ATT&CK は The MITRE Corporation の登録商標です。MITRE の表記指針に従い、利用者が最初に
  目にする説明（ホームの紹介文、導入画面の用語説明、最終レポートの見出し、アプリ内のライセンス画面）で
  「MITRE ATT&CK®」と表記しています。以降の出現箇所には ® を付けていません。
