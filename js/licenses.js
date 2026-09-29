// licenses.js — 第三者ソフトウェアとライセンスの画面。
//
// 本文はリポジトリに同梱したファイルを、サーバーの固定の対応表
// （/api/licenses/<名前>）から読む。外部のサイトへは取りに行かないので、
// オフラインでも読める。本文は textContent でそのまま表示する。

import { el, homeNav } from './dom.js';

/** 同梱ファイルの本文を読み込んで pre に入れる。失敗したら置き場所を案内する。 */
async function loadInto(pre, name, path) {
  try {
    const res = await fetch(`/api/licenses/${name}`);
    if (!res.ok) throw new Error(String(res.status));
    const text = await res.text();
    if (pre.isConnected) pre.textContent = text;
  } catch (err) {
    if (pre.isConnected) {
      pre.textContent = `読み込めませんでした。リポジトリの ${path} を開いて確認してください。`;
    }
  }
}

function licenseText(name, path, label) {
  const pre = el('pre', 'license-text mono', '読み込み中…');
  pre.tabIndex = 0;
  pre.setAttribute('aria-label', label);
  return { pre, load: () => loadInto(pre, name, path) };
}

/** 開閉できる全文。見出しに同梱ファイルの場所を添える。 */
function fold(title, path, text) {
  const box = el('details', 'fold');
  box.append(el('summary', 'fold__head', title));
  box.append(el('p', 'muted', `同梱ファイル: ${path}`));
  box.append(text.pre);
  return box;
}

function external(href, text) {
  const a = el('a', null, text);
  a.href = href;
  a.target = '_blank';
  a.rel = 'noopener noreferrer';
  return a;
}

export function renderLicenses(mount) {
  mount.textContent = '';
  const root = el('section', 'licenses');
  root.append(homeNav());

  const heading = el('h1', null, '第三者ソフトウェアとライセンス');
  heading.tabIndex = -1;
  root.append(heading);
  root.append(el('p', 'muted',
    'このアプリが使っている第三者の著作物と、そのライセンスです。本文はアプリに同梱したものを表示しており、インターネットに接続していなくても読めます。'));

  // ---- MITRE ATT&CK® ----
  const attck = el('section', 'panel');
  attck.append(el('h2', 'license-title', 'MITRE ATT&CK®'));
  attck.append(el('p', null,
    'ログ教材では、MITRE ATT&CK® の手法 ID と手法名を、記録の説明と最終レポートの「MITRE ATT&CK® との対応」に使っています。Ghidra の静的解析教材では使っていません。'));
  attck.append(el('p', null,
    '記録と手法の対応付け、およびそれを使った教材の生成は Zip2Learn 独自のものです。The MITRE Corporation（MITRE）の承認・推奨・支援を受けたものではありません。MITRE ATT&CK と ATT&CK は The MITRE Corporation の登録商標です。'));
  const src = el('p', 'muted', '出典: ');
  src.append(
    external('https://attack.mitre.org/', 'attack.mitre.org'),
    document.createTextNode('（利用条件: '),
    external('https://attack.mitre.org/resources/legal-and-branding/terms-of-use/', 'Terms of Use'),
    document.createTextNode('）'),
  );
  attck.append(src);
  attck.append(el('p', 'muted', '次は同梱したライセンス本文です（原文のまま）。'));
  const attckText = licenseText('mitre-attack', 'third_party/mitre-attack/LICENSE.txt',
    'MITRE ATT&CK のライセンス本文');
  attck.append(el('p', 'muted', '同梱ファイル: third_party/mitre-attack/LICENSE.txt'));
  attck.append(attckText.pre);
  root.append(attck);

  // ---- Ghidra の同梱サンプル ----
  const ghidra = el('section', 'panel');
  ghidra.append(el('h2', 'license-title', 'Ghidra 公式教材のサンプル（termmines）'));
  ghidra.append(el('p', null,
    '同梱サンプルの termmines.c とそこから作った termmines.gzf は、Apache License 2.0 で配布されている Ghidra 公式教材に基づきます。Zip2Learn は NSA や Ghidra プロジェクトの承認・推奨を受けたものではありません。'));
  const apache = licenseText('apache-license', 'ghidra/sample/LICENSE-Apache-2.0.txt',
    'Apache License 2.0 の全文');
  const notice = licenseText('ghidra-notice', 'ghidra/sample/NOTICE-Ghidra.txt', 'Ghidra の NOTICE');
  ghidra.append(fold('Apache License 2.0 の全文', 'ghidra/sample/LICENSE-Apache-2.0.txt', apache));
  ghidra.append(fold('Ghidra の NOTICE', 'ghidra/sample/NOTICE-Ghidra.txt', notice));
  root.append(ghidra);

  // ---- 一覧 ----
  const all = el('section', 'panel');
  all.append(el('h2', 'license-title', '第三者ソフトウェアと同梱物の一覧'));
  all.append(el('p', null,
    'Docker・Ghidra・JDK など、利用者の PC で取得・構築するものの扱いも含めた一覧です。Docker は同梱も自動インストールもしません。Docker Desktop は組織の規模や用途によって有料の契約が必要になるため、公式の最新の条件を確認してください。'));
  const notices = licenseText('notices', 'THIRD_PARTY_NOTICES.md', '第三者ソフトウェアと同梱物の一覧');
  all.append(fold('THIRD_PARTY_NOTICES.md の全文', 'THIRD_PARTY_NOTICES.md', notices));
  root.append(all);

  mount.replaceChildren(root);
  heading.focus({ preventScroll: true });
  return Promise.all([attckText.load(), apache.load(), notice.load(), notices.load()]);
}
