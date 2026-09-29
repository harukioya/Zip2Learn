// test_ui_licenses.mjs — 「第三者ソフトウェアとライセンス」画面の回帰テスト。
//
// 本物の licenses.js を最小の DOM シムで動かす。本文はサーバーの
// /api/licenses/<名前> から読む前提なので、その応答を同梱ファイルの中身で
// 置き換える。外部のサイトへ取りに行かないこと（オフラインで読めること）も見る。
//
//   node backend/tests/test_ui_licenses.mjs

import assert from 'node:assert/strict';
import fs from 'node:fs';
import path from 'node:path';
import { fileURLToPath } from 'node:url';

const REPO = path.resolve(path.dirname(fileURLToPath(import.meta.url)), '..', '..');

class El {
  constructor(tag) {
    this.tag = tag;
    this.children = [];
    this.attrs = {};
    this._text = '';
    this._on = {};
    this.parent = null;
    this._root = false;
    this.classList = { add: (c) => { this.className = (this.className ? this.className + ' ' : '') + c; } };
  }
  _adopt(c) {
    if (c.parent) c.parent.children = c.parent.children.filter((x) => x !== c);
    c.parent = this;
    return c;
  }
  set textContent(v) { this.children.forEach((c) => (c.parent = null)); this._text = String(v); this.children = []; }
  get textContent() { return this.children.length ? this.children.map((c) => c.textContent).join('') : this._text; }
  appendChild(c) { this.children.push(this._adopt(c)); return c; }
  append(...cs) { cs.forEach((c) => this.children.push(this._adopt(c))); }
  replaceChildren(...cs) { this.children.forEach((c) => (c.parent = null)); this.children = cs.map((c) => this._adopt(c)); }
  setAttribute(k, v) { this.attrs[k] = v; }
  addEventListener(t, f) { (this._on[t] || (this._on[t] = [])).push(f); }
  focus() { globalThis.__focused = this; }
  get isConnected() { let n = this; while (n) { if (n._root) return true; n = n.parent; } return false; }
  find(pred, acc = []) { if (pred(this)) acc.push(this); this.children.forEach((c) => c.find(pred, acc)); return acc; }
  cls(name) { return this.find((e) => String(e.className || '').split(' ').includes(name)); }
}

const app = new El('main');
app._root = true;
globalThis.document = {
  createElement: (t) => new El(t),
  createTextNode: (t) => { const n = new El('#text'); n.textContent = t; return n; },
};
globalThis.location = { hash: '' };

// サーバーの対応表（backend/api.py の LICENSE_FILES）と同じ名前 → 同梱ファイル。
const FILES = {
  notices: 'THIRD_PARTY_NOTICES.md',
  'mitre-attack': 'third_party/mitre-attack/LICENSE.txt',
  'apache-license': 'ghidra/sample/LICENSE-Apache-2.0.txt',
  'ghidra-notice': 'ghidra/sample/NOTICE-Ghidra.txt',
};
const apiSrc = fs.readFileSync(path.join(REPO, 'backend/api.py'), 'utf8');
let requested = [];
let failing = false;
globalThis.fetch = async (url) => {
  requested.push(url);
  const name = String(url).replace(/^\/api\/licenses\//, '');
  if (failing || !FILES[name]) return { ok: false, status: 404, text: async () => '' };
  const body = fs.readFileSync(path.join(REPO, FILES[name]), 'utf8');
  return { ok: true, status: 200, text: async () => body };
};

const results = [];
async function test(name, fn) {
  try { await fn(); results.push(['ok', name]); } catch (e) { results.push(['NG', name, e.stack || e.message]); }
}

const { renderLicenses } = await import(REPO + '/js/licenses.js');

async function open() {
  requested = [];
  const view = new El('div');
  app.replaceChildren(view);
  await renderLicenses(view);
  return view;
}

await test('画面の対応表は、サーバーの許可した名前と同じ', async () => {
  for (const [name, rel] of Object.entries(FILES)) {
    assert.ok(apiSrc.includes(`"${name}": "${rel}"`), `${name} → ${rel} が api.py に無い`);
  }
});

await test('同梱した ATT&CK のライセンス本文を、原文のまま表示する', async () => {
  const view = await open();
  const official = fs.readFileSync(path.join(REPO, FILES['mitre-attack']), 'utf8');
  const shown = view.cls('license-text').map((p) => p.textContent);
  assert.ok(shown.includes(official), 'ライセンス本文が一致しない');
  const text = view.textContent;
  assert.ok(text.includes('MITRE ATT&CK®'), '初出に ® を付ける');
  assert.ok(text.includes('ログ教材では、MITRE ATT&CK® の手法 ID と手法名'), '使用範囲');
  assert.ok(text.includes('承認・推奨・支援を受けたものではありません'), '非承認の表示');
  assert.equal(globalThis.__focused, view.find((e) => e.tag === 'h1')[0], '見出しへフォーカス');
});

await test('Ghidra のライセンス・NOTICE と、第三者表記の一覧も読める', async () => {
  const view = await open();
  const shown = view.cls('license-text').map((p) => p.textContent);
  for (const name of ['apache-license', 'ghidra-notice', 'notices']) {
    const body = fs.readFileSync(path.join(REPO, FILES[name]), 'utf8');
    assert.ok(shown.includes(body), `${name} が表示されない`);
  }
});

await test('本文はすべて同じサーバーの固定の経路から読み、外部へ取りに行かない', async () => {
  await open();
  assert.equal(requested.length, 4);
  assert.ok(requested.every((u) => /^\/api\/licenses\/[a-z0-9-]+$/.test(u)), requested.join(', '));
});

await test('外部サイトへのリンクは利用者が押したときだけ開く（新しいタブ、参照元を送らない）', async () => {
  const view = await open();
  const links = view.find((e) => e.tag === 'a');
  assert.ok(links.length >= 2);
  for (const a of links) {
    assert.match(a.href, /^https:\/\/attack\.mitre\.org\//);
    assert.equal(a.rel, 'noopener noreferrer');
  }
});

await test('読み込めないときは、同梱ファイルの場所を案内する', async () => {
  failing = true;
  const view = await open();
  failing = false;
  const shown = view.cls('license-text').map((p) => p.textContent).join('\n');
  assert.ok(shown.includes('third_party/mitre-attack/LICENSE.txt を開いて確認してください'), shown);
});

await test('ライセンス画面への導線は、どれも別タブで開く（演習・結果を消さない）', async () => {
  // 回答履歴は保存していないので、同じタブで #/licenses へ移ると演習の途中経過・結果・
  // 復習の状態が消える。index.html と js/ の中の #/licenses へのリンクを全部確かめる。
  const html = fs.readFileSync(path.join(REPO, 'index.html'), 'utf8');
  const anchors = [...html.matchAll(/<a\b[^>]*href="#\/licenses"[^>]*>([^<]*)<\/a>/g)];
  assert.equal(anchors.length, 1, 'フッターのリンク');
  const [tag, label] = anchors[0];
  assert.match(tag, /\starget="_blank"/);
  assert.match(tag, /\srel="noopener noreferrer"/);
  assert.equal(label, '第三者ソフトウェアとライセンス');

  const jsDir = path.join(REPO, 'js');
  for (const name of fs.readdirSync(jsDir).filter((n) => n.endsWith('.js'))) {
    const src = fs.readFileSync(path.join(jsDir, name), 'utf8');
    const uses = src.split('\n').filter((l) => /\.href\s*=\s*['"]#\/licenses['"]/.test(l)).length;
    if (!uses) continue;
    const blank = (src.match(/\.target\s*=\s*['"]_blank['"]/g) || []).length;
    const rel = (src.match(/\.rel\s*=\s*['"]noopener noreferrer['"]/g) || []).length;
    assert.ok(blank >= uses && rel >= uses, `${name}: #/licenses へのリンクに別タブの指定が無い`);
    assert.ok(/（別タブ）/.test(src), `${name}: 別タブで開くことを文言で示していない`);
  }
});

let bad = 0;
for (const [status, name, why] of results) {
  if (status === 'ok') console.log(`  ok   ${name}`);
  else { bad++; console.log(`  NG   ${name}\n       ${why}`); }
}
console.log(`\n${results.length - bad} / ${results.length} 成功`);
process.exit(bad ? 1 : 0);
