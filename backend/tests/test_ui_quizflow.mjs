// test_ui_quizflow.mjs — 回答の演出・全体進捗・問題の切り替え・結果と復習の回帰テスト。
//
// 他の UI テストと同じく、最小の DOM シムの上で本物の player.js / quiz.js /
// recap.js / motion.js を動かす。確かめられるのは状態と組み立てまでで、
// 実際の動き・見た目・スクロールの体感は実ブラウザで別に確認する。
//
// 実データは使わない。架空の端末名だけ。
//
//   node backend/tests/test_ui_quizflow.mjs

import assert from 'node:assert/strict';
import path from 'node:path';
import { fileURLToPath } from 'node:url';

const REPO = path.resolve(path.dirname(fileURLToPath(import.meta.url)), '..', '..');

// ---------------------------------------------------------------------------
// 最小の DOM
// ---------------------------------------------------------------------------
class El {
  constructor(tag) {
    this.tag = tag;
    this.children = [];
    this.attrs = {};
    this._text = '';
    this._on = {};
    this.parent = null;
    this._root = false;
    this.hidden = false;
    this.disabled = false;
    this.classList = {
      add: (c) => { this.className = (this.className ? this.className + ' ' : '') + c; },
      remove: (c) => { this.className = String(this.className || '').split(' ').filter((x) => x && x !== c).join(' '); },
    };
  }
  _adopt(c) {
    if (c.parent) c.parent.children = c.parent.children.filter((x) => x !== c);
    c.parent = this;
    return c;
  }
  set textContent(v) {
    this.children.forEach((c) => (c.parent = null));
    this._text = String(v);
    this.children = [];
  }
  get textContent() {
    return this.children.length ? this.children.map((c) => c.textContent).join('') : this._text;
  }
  appendChild(c) { this.children.push(this._adopt(c)); return c; }
  append(...cs) { cs.forEach((c) => this.children.push(this._adopt(c))); }
  insertBefore(c, ref) {
    this._adopt(c);
    const at = this.children.indexOf(ref);
    if (at < 0) this.children.push(c); else this.children.splice(at, 0, c);
    return c;
  }
  replaceChildren(...cs) {
    this.children.forEach((c) => (c.parent = null));
    this._text = '';
    this.children = cs.map((c) => this._adopt(c));
  }
  remove() {
    if (this.parent) this.parent.children = this.parent.children.filter((x) => x !== this);
    this.parent = null;
  }
  setAttribute(k, v) { this.attrs[k] = v; }
  addEventListener(t, f) { (this._on[t] || (this._on[t] = [])).push(f); }
  click(ev) { return Promise.all((this._on.click || []).map((f) => f(ev))); }
  focus(opts) { globalThis.__focused = this; globalThis.__focusOpts = opts; }
  scrollIntoView(opts) { globalThis.__scrolled = this; globalThis.__scrollOpts = opts; }
  get isConnected() {
    let n = this;
    while (n) { if (n._root) return true; n = n.parent; }
    return false;
  }
  find(pred, acc = []) {
    if (pred(this)) acc.push(this);
    this.children.forEach((c) => c.find(pred, acc));
    return acc;
  }
  cls(name) { return this.find((e) => has(e, name)); }
  button(re) { return this.find((e) => e.tag === 'button' && re.test(e.textContent))[0]; }
}
const has = (e, name) => String(e.className || e.attrs.class || '').split(' ').includes(name);

const app = new El('main');
app._root = true;
function byId(node, id) {
  if (node.id === id) return node;
  for (const c of node.children) { const r = byId(c, id); if (r) return r; }
  return null;
}
const docListeners = {};
globalThis.document = {
  createElement: (t) => new El(t),
  createElementNS: (_ns, t) => new El(t),
  getElementById: (id) => (id === 'app' ? app : byId(app, id)),
  querySelector: () => null,
  addEventListener(t, f) { (docListeners[t] || (docListeners[t] = [])).push(f); },
  removeEventListener(t, f) { docListeners[t] = (docListeners[t] || []).filter((x) => x !== f); },
};

// 動きを減らす設定と、フレームの API はテストごとに切り替える。
let reduce = false;
let frames = [];
function enableFrames() {
  frames = [];
  window.requestAnimationFrame = (f) => { frames.push(f); return frames.length; };
  window.cancelAnimationFrame = () => {};
}
function disableFrames() {
  delete window.requestAnimationFrame;
  delete window.cancelAnimationFrame;
}
/** 溜まったフレームを、指定の時刻まで順に進める。 */
function runFrames(until, stepMs = 50) {
  for (let now = 0; now <= until; now += stepMs) {
    const batch = frames;
    frames = [];
    batch.forEach((f) => f(now));
  }
}
globalThis.window = {
  scrollTo() {}, dispatchEvent() {}, addEventListener() {},
  matchMedia: () => ({ matches: reduce }),
};
globalThis.location = { hash: '' };
globalThis.HashChangeEvent = class {};

/** キーボードなどのイベントを、要素か document のリスナーへ直接渡す。 */
function fire(target, type, props = {}) {
  const ev = { key: '', repeat: false, target: null, defaultPrevented: false, ...props };
  ev.preventDefault = () => { ev.defaultPrevented = true; };
  const list = target === document ? (docListeners[type] || []) : (target._on[type] || []);
  [...list].forEach((f) => f(ev));
  return ev;
}

const sleep = (ms) => new Promise((r) => setTimeout(r, ms));

// ---------------------------------------------------------------------------
// fixture（架空データ）
// ---------------------------------------------------------------------------
const q = (id, correct = 0, extra = {}) => ({
  id, type: 'single_choice', category: 'log-reading',
  q: `問い ${id}`, options: ['あ', 'い', 'う'], correct, explain: `解説 ${id}`, ...extra,
});

/**
 * 複数段階の教材。段階 1 に 2 問（新形式）、段階 2 は設問なし、段階 3 は
 * 旧形式の `quiz` 1 問。全体で 3 問。
 */
function multi(overrides = {}) {
  return {
    id: 'gen-flow', title: '進行テスト',
    stages: [
      { id: 's1', name: '端末', events: [{ type: 'process', detail: 'WS99: 起動' }],
        quizzes: [q('a', 0), q('b', 1)] },
      { id: 's2', name: '通信', events: [{ type: 'network', detail: 'WS99: 通信' }],
        quizzes: [], note: 'この段階は記録を読むだけです。' },
      { id: 's3', name: '旧形式', events: [{ type: 'file', detail: 'WS99: 書き込み' }],
        quiz: { q: '旧形式の問い', options: ['はい', 'いいえ'], correct: 1, explain: '旧解説' } },
    ],
    ...overrides,
  };
}

function manyQuestions(n) {
  return {
    id: 'gen-many', title: '多い',
    stages: [{ id: 's', name: '段階', events: [], quizzes: Array.from({ length: n }, (_, i) => q(`m${i}`, 0)) }],
  };
}

const results = [];
async function test(name, fn) {
  reduce = false;
  disableFrames();
  try { await fn(); results.push(['ok', name]); }
  catch (e) { results.push(['NG', name, e.stack || e.message]); }
}

const { renderLesson } = await import(REPO + '/js/player.js');
const { renderQuiz } = await import(REPO + '/js/quiz.js');
const { renderRecap } = await import(REPO + '/js/recap.js');
const { MARK_MS, clearMotion } = await import(REPO + '/js/motion.js');

async function open(obj) {
  globalThis.fetch = async () => ({ ok: true, status: 200, json: async () => obj });
  const view = document.createElement('div');
  app.replaceChildren(view);
  await renderLesson(view, obj.id);
  return view;
}

const marksOf = (root) => root.cls('answer-mark');
const titleText = (root) => (root.cls('qprogress__title')[0] || {}).textContent;
const countText = (root) => (root.cls('qprogress__count')[0] || {}).textContent;
const qmarks = (root) => root.cls('qmark');
const heading = () => app.find((e) => e.tag === 'h1' && /正解/.test(e.textContent))[0];

/** 段階 1 の 2 問 → 段階 2 → 段階 3 の 1 問 → 結果、まで進める。 */
async function playAll(view, picks = [0, 1, 1]) {
  await view.cls('option')[picks[0]].click();
  await view.button(/^次の問題へ$/).click();
  await view.cls('option')[picks[1]].click();
  await view.button(/^次の段階へ$/).click();
  await view.button(/^次の段階へ$/).click();
  await view.cls('option')[picks[2]].click();
  await view.button(/^結果を見る$/).click();
}

// ---------------------------------------------------------------------------
// 回答時の演出
// ---------------------------------------------------------------------------
await test('正解でも不正解でも、回答の記録とコールバックは一度だけ', async () => {
  for (const [pick, want] of [[0, true], [1, false]]) {
    const view = document.createElement('div');
    app.replaceChildren(view);
    const calls = [];
    renderQuiz(view, q('x', 0), (ok) => calls.push(ok));
    const options = view.cls('option');
    await options[pick].click();
    await options[pick].click();
    await options[2].click();
    fire(document, 'keydown', { key: '3' });
    assert.deepEqual(calls, [want], `pick=${pick}`);
    assert.equal(view.cls('feedback').length, 1, '正誤の表示も 1 つ');
    assert.ok(options.every((o) => o.disabled), '全選択肢をロック');
    assert.ok(has(options[pick], 'is-pressed'), '選んだボタンに押下反応');
    clearMotion();
  }
});

await test('中央の ○・× は読み上げから外し、正誤の文字を添える', async () => {
  const view = await open(multi());
  await view.cls('option')[0].click();          // 正解
  let marks = marksOf(view);
  assert.equal(marks.length, 1);
  assert.equal(marks[0].attrs['aria-hidden'], 'true');
  assert.ok(has(marks[0], 'is-ok'));
  assert.equal(marks[0].textContent, '正解！');
  assert.ok(marks[0].find((e) => e.tag === 'circle').length, '○ は円');
  // 読み上げは既存の正誤表示が担う。
  assert.equal(view.cls('feedback')[0].attrs.role, 'status');

  await view.button(/^次の問題へ$/).click();
  await view.cls('option')[0].click();          // b の正解は 1 → 不正解
  marks = marksOf(view);
  assert.equal(marks.length, 1, '同時に 1 つまで');
  assert.ok(has(marks[0], 'is-bad'));
  assert.equal(marks[0].textContent, '不正解');
  assert.equal(marks[0].find((e) => e.tag === 'line').length, 2, '× は交差線');
  clearMotion();
});

await test('解説・根拠・次へは、演出を待たずに回答と同時に出る', async () => {
  const view = await open(multi());
  await view.cls('option')[1].click();
  assert.equal(marksOf(view).length, 1, '演出中');
  assert.ok(view.cls('reveal').length, '解説');
  const next = view.button(/^次の問題へ$/);
  assert.ok(next && !next.hidden, '次へ');
  await next.click();
  assert.equal(marksOf(view).length, 0, '次の問題へ進むと古い演出はすぐ消える');
  assert.match(view.textContent, /問い b/);
});

await test('約 800ms で自動的に消え、DOM に残らない', async () => {
  const view = await open(multi());
  await view.cls('option')[0].click();
  assert.equal(marksOf(view).length, 1);
  await sleep(MARK_MS + 60);
  assert.equal(marksOf(view).length, 0);
  assert.ok(view.cls('reveal').length, '解説は残る');
});

await test('古い演出のタイマーが、新しい演出を消さない', async () => {
  const view = await open(multi());
  await view.cls('option')[0].click();
  await view.button(/^次の問題へ$/).click();
  await sleep(MARK_MS / 2);
  await view.cls('option')[1].click();
  const second = marksOf(view)[0];
  assert.ok(second);
  await sleep(MARK_MS / 2 + 100);               // 1 つ目の予定時刻を過ぎた
  assert.equal(marksOf(view)[0], second, '2 つ目はまだ出ている');
  await sleep(MARK_MS / 2);
  assert.equal(marksOf(view).length, 0, '2 つ目も自分の時間で消える');
});

await test('段階の移動・結果・画面離脱で、演出を持ち越さない', async () => {
  let view = await open(multi());
  await view.cls('option')[0].click();
  await view.button(/^次の問題へ$/).click();
  await view.cls('option')[1].click();
  assert.equal(marksOf(view).length, 1);
  await view.button(/^次の段階へ$/).click();
  assert.equal(marksOf(view).length, 0, '次の段階');
  await view.button(/^次の段階へ$/).click();
  await view.cls('option')[1].click();
  await view.button(/^結果を見る$/).click();
  assert.equal(marksOf(app).length, 0, '結果');

  // ルーターは画面を差し替える前に clearMotion() を呼ぶ（app.js）。
  view = await open(multi());
  await view.cls('option')[0].click();
  const mark = marksOf(view)[0];
  clearMotion();
  app.replaceChildren(document.createElement('div'));
  assert.equal(mark.parent, null, '離脱後に演出が残らない');
});

await test('動きを減らす設定でも、中央の記号は出て時間で消える', async () => {
  reduce = true;
  const view = await open(multi());
  await view.cls('option')[0].click();
  assert.equal(marksOf(view).length, 1);
  assert.ok(view.cls('feedback')[0].textContent.includes('正解'), '正誤の文字は残る');
  await sleep(MARK_MS + 60);
  assert.equal(marksOf(view).length, 0);
  assert.ok(view.cls('feedback')[0].textContent.includes('正解'));
});

await test('表示できない設問の復帰経路では、× を出さない', async () => {
  const obj = multi();
  obj.stages[0].quizzes = [{ id: 'broken', options: [] }];
  const view = await open(obj);
  assert.match(view.textContent, /設問がありません/);
  assert.equal(marksOf(view).length, 0);
});

await test('証拠のない旧形式・prompt・evidence_pick でも演出と進行が動く', async () => {
  const obj = multi();
  obj.stages[0].quizzes = [
    { id: 'p', type: 'evidence_pick', prompt: 'どれですか。',
      options: [{ label: 'ログの 1 行目', evidenceId: 'ev-x' }, { label: 'ログの 2 行目', evidenceId: 'ev-y' }],
      correct: 1, explanation: 'こちら' },
  ];
  const view = await open(obj);
  await view.cls('option')[1].click();
  assert.ok(has(marksOf(view)[0], 'is-ok'));
  assert.ok(view.button(/^次の段階へ$/), '次の段階へ進める');
  clearMotion();
});

// ---------------------------------------------------------------------------
// 全体の設問進捗
// ---------------------------------------------------------------------------
await test('問題の通し番号と回答済み件数を、段階をまたいで数える', async () => {
  const view = await open(multi());
  assert.equal(titleText(view), '問題 1 / 3');
  assert.equal(countText(view), '回答済み 0 / 3');
  assert.equal(qmarks(view).length, 3, 'マークは全設問ぶん');

  await view.cls('option')[0].click();
  assert.equal(titleText(view), '問題 1 / 3', '見えている位置は変わらない');
  assert.equal(countText(view), '回答済み 1 / 3');

  await view.button(/^次の問題へ$/).click();
  assert.equal(titleText(view), '問題 2 / 3');
  assert.equal(countText(view), '回答済み 1 / 3');
  assert.ok(view.textContent.includes('この段階の設問 2 / 2'), '段階内の番号は明示して残す');

  await view.cls('option')[0].click();          // 不正解
  await view.button(/^次の段階へ$/).click();
  // 設問のない段階。分母にも回答数にも足さず、全体の件数だけを示す。
  assert.equal(titleText(view), undefined, 'この段階に「問題 n / N」は無い');
  assert.equal(countText(view), '回答済み 2 / 3');
  assert.match(view.textContent, /記録を読むだけです/);

  await view.button(/^次の段階へ$/).click();
  assert.equal(titleText(view), '問題 3 / 3', '旧形式の quiz も数える');
  await view.cls('option')[1].click();
  assert.equal(countText(view), '回答済み 3 / 3');
  clearMotion();
});

await test('マークは現在・未回答・正解・不正解を、記号と輪郭でも区別する', async () => {
  const view = await open(multi());
  await view.cls('option')[0].click();          // a 正解
  await view.button(/^次の問題へ$/).click();
  let m = qmarks(view);
  assert.ok(has(m[0], 'is-ok') && m[0].textContent === '○');
  assert.ok(has(m[1], 'is-current') && !has(m[1], 'is-ok') && m[1].textContent === '');
  assert.ok(!has(m[2], 'is-current') && m[2].textContent === '', '未回答');

  await view.cls('option')[0].click();          // b 不正解
  m = qmarks(view);
  assert.ok(has(m[1], 'is-current') && has(m[1], 'is-bad'), '回答後も現在位置と正誤の両方');
  assert.equal(m[1].textContent, '×');
  assert.ok(has(m[1], 'is-just'), '回答時に短く塗りが変わる');

  const list = view.cls('qprogress__marks')[0];
  assert.equal(list.attrs['aria-hidden'], 'true', 'マークは読み上げない（文字が伝える）');
  assert.ok(m.every((li) => li.tag === 'li' && !li._on.click), 'マークから移動はできない');
  clearMotion();
});

await test('全体 0 問は「設問なし」で、NaN や「/ 0」を出さない', async () => {
  const obj = multi();
  obj.stages = [obj.stages[1]];
  const view = await open(obj);
  const text = view.textContent;
  assert.equal(titleText(view), '設問なし');
  assert.ok(!/NaN|\/ 0|1 \/ 0/.test(text), text);
  await view.button(/^結果を見る$/).click();
  assert.equal(heading().textContent, '正解 0 / 0');
});

await test('1 問だけ・8 問未満・多い教材でも、進捗・導入・結果の総数が揃う', async () => {
  for (const n of [1, 5, 14]) {
    const obj = manyQuestions(n);
    obj.introduction = { scenario: '確かめます。' };
    const view = await open(obj);
    assert.ok(view.textContent.includes(`設問の数${n} 問`), `導入 n=${n}`);
    await view.button(/調査を始める/).click();
    assert.equal(titleText(view), `問題 1 / ${n}`);
    assert.equal(qmarks(view).length, n);
    for (let i = 0; i < n; i++) {
      await view.cls('option')[0].click();
      const next = view.button(/^次の問題へ$/);
      if (next) await next.click();
    }
    await view.button(/^結果を見る$/).click();
    assert.equal(heading().textContent, `正解 ${n} / ${n}`, `結果 n=${n}`);
    clearMotion();
  }
});

await test('段階の表示は番号・名称を残し、設問マークとは別の形にする', async () => {
  const view = await open(multi());
  assert.ok(view.cls('stage-index')[0].textContent === '段階 1/3');
  assert.equal(view.cls('progress__seg').length, 3, '段階は帯');
  assert.equal(view.cls('progress__dot').length, 0, '丸い段階ドットは出さない');
});

// ---------------------------------------------------------------------------
// 問題間のテンポと操作
// ---------------------------------------------------------------------------
await test('次へボタンの文言が状況で変わる', async () => {
  const view = await open(multi());
  await view.cls('option')[0].click();
  assert.ok(view.button(/^次の問題へ$/), '同じ段階に次の問題');
  await view.button(/^次の問題へ$/).click();
  await view.cls('option')[0].click();
  assert.ok(view.button(/^次の段階へ$/), '段階の最後');
  await view.button(/^次の段階へ$/).click();
  assert.ok(view.button(/^次の段階へ$/), '設問のない段階も先へ進める');
  await view.button(/^次の段階へ$/).click();
  await view.cls('option')[0].click();
  assert.ok(view.button(/^結果を見る$/), '最終段階');
  clearMotion();
});

await test('次へを連打しても問題を飛ばさない', async () => {
  const view = await open(multi());
  await view.cls('option')[0].click();
  const next = view.button(/^次の問題へ$/);
  await next.click();
  await next.click();
  assert.equal(titleText(view), '問題 2 / 3');
  // 2 回目のクリックが新しい選択肢に当たっても、回答しない。
  await view.cls('option')[0].click({ detail: 2 });
  assert.equal(view.cls('feedback').length, 0, '新しい問題は未回答のまま');

  await view.cls('option')[1].click();
  const cont = view.button(/^次の段階へ$/);
  await cont.click();
  await cont.click();
  assert.equal(view.cls('stage-name')[0].textContent, '通信', '1 段階だけ進む');
  clearMotion();
});

await test('連打の 2 クリック目が描き直した新しいボタンに届いても、設問のない段階を飛ばさない', async () => {
  const empty = (id, name) => ({ id, name, events: [{ type: 'process', detail: name }], quizzes: [] });
  const view = await open({
    id: 'gen-empty3', title: '設問なし 3 段階',
    stages: [empty('e1', '段階1'), empty('e2', '段階2'), empty('e3', '段階3')],
  });
  const stageName = () => view.cls('stage-name')[0].textContent;
  assert.equal(stageName(), '段階1');

  // ダブルクリックの 1 回目で段階 2 へ進み、2 回目（detail 2）は段階 2 の新しいボタンに届く。
  await view.button(/^次の段階へ$/).click({ detail: 1 });
  assert.equal(stageName(), '段階2');
  const fresh = view.button(/^次の段階へ$/);
  assert.ok(fresh && !fresh.hidden, '段階 2 のボタンは押せる状態で出ている');
  await fresh.click({ detail: 2 });
  assert.equal(stageName(), '段階2', '2 クリック目で段階 3 へ進まない');

  // 改めて押せば進む。キーボード操作の click（detail 0）も通す。
  await view.button(/^次の段階へ$/).click({ detail: 0 });
  assert.equal(stageName(), '段階3');
  await view.button(/^結果を見る$/).click({ detail: 2 });
  assert.equal(heading(), undefined, '最終段階でも 2 クリック目で結果へ飛ばない');
  await view.button(/^結果を見る$/).click({ detail: 1 });
  assert.equal(heading().textContent, '正解 0 / 0');
});

await test('フォーカス: 回答後は次へ、次の問題は設問見出し、次の段階は段階見出し、結果は結果見出し', async () => {
  const view = await open(multi());
  await view.cls('option')[0].click();
  assert.equal(globalThis.__focused, view.button(/^次の問題へ$/));
  assert.deepEqual(globalThis.__focusOpts, { preventScroll: true });
  assert.ok(has(globalThis.__scrolled, 'quiz-panel'), '見せる位置は設問の先頭');
  assert.equal(globalThis.__scrollOpts.block, 'start');

  await view.button(/^次の問題へ$/).click();
  assert.equal(globalThis.__focused, view.cls('qprogress__title')[0]);
  assert.equal(globalThis.__focused.textContent, '問題 2 / 3');

  await view.cls('option')[0].click();
  await view.button(/^次の段階へ$/).click();
  assert.equal(globalThis.__focused, view.cls('stage-name')[0]);

  await view.button(/^次の段階へ$/).click();
  await view.cls('option')[0].click();
  await view.button(/^結果を見る$/).click();
  assert.equal(globalThis.__focused, heading());
  clearMotion();
});

await test('押しっぱなしのキーで次へまで進まない', async () => {
  const view = await open(multi());
  await view.cls('option')[0].click();
  const next = view.button(/^次の問題へ$/);
  assert.ok(fire(next, 'keydown', { key: 'Enter', repeat: true }).defaultPrevented, 'Enter のリピート');
  assert.ok(fire(next, 'keyup', { key: ' ' }).defaultPrevented, '選択肢で押し始めた Space');
  assert.ok(!fire(next, 'keydown', { key: 'Enter' }).defaultPrevented, '新しく押した Enter は通す');
  fire(next, 'keydown', { key: ' ' });
  assert.ok(!fire(next, 'keyup', { key: ' ' }).defaultPrevented, 'ここで押した Space は通す');
  clearMotion();
});

await test('数字キー回答は保ち、入力欄・IME・修飾キー・リピートは妨げない', async () => {
  const view = await open(multi());
  const cases = [
    { key: '1', repeat: true },
    { key: '1', isComposing: true },
    { key: '1', keyCode: 229 },
    { key: '1', shiftKey: true },
    { key: '1', target: { tagName: 'input' } },
    { key: '1', target: { tagName: 'TEXTAREA' } },
    { key: '1', target: { tagName: 'DIV', isContentEditable: true } },
  ];
  for (const c of cases) {
    const ev = fire(document, 'keydown', c);
    assert.equal(ev.defaultPrevented, false, JSON.stringify(c));
  }
  assert.equal(view.cls('feedback').length, 0, 'どれでも回答しない');
  const ev = fire(document, 'keydown', { key: '1' });
  assert.ok(ev.defaultPrevented);
  assert.equal(view.cls('feedback').length, 1, '普通の数字キーで回答する');
  assert.ok(!fire(document, 'keydown', { key: 'Enter' }).defaultPrevented, 'Enter は横取りしない');
  clearMotion();
});

// ---------------------------------------------------------------------------
// 結果画面と復習
// ---------------------------------------------------------------------------
await test('完了メッセージ: 全問正解・それ以外・0 問', async () => {
  let view = await open(multi());
  await playAll(view, [0, 1, 1]);
  assert.ok(app.textContent.includes('全問正解！ おつかれさまでした'));
  assert.ok(app.textContent.includes('初回の成績'));

  view = await open(multi());
  await playAll(view, [0, 0, 1]);
  assert.ok(app.textContent.includes('演習完了！ おつかれさまでした'));
  assert.ok(!app.textContent.includes('全問正解'));

  const obj = multi();
  obj.stages = [obj.stages[1]];
  view = await open(obj);
  await view.button(/^結果を見る$/).click();
  assert.ok(app.textContent.includes('記録の確認が完了しました'));
  assert.ok(!app.textContent.includes('全問正解'), '0 問を全問正解と扱わない');
});

await test('間違いがあれば復習ボタンから「間違えた問題」へ移動してフォーカスする', async () => {
  let view = await open(multi());
  await playAll(view, [0, 0, 1]);
  const btn = app.button(/^間違えた問題を復習する$/);
  assert.ok(btn);
  globalThis.__focused = null;
  await btn.click();
  const box = app.cls('recap__wrong')[0];
  assert.ok(box && box.textContent.includes('間違えた問題'));
  assert.equal(globalThis.__scrolled, box);
  assert.equal(globalThis.__focused, box);
  assert.equal(box.tabIndex, -1);

  view = await open(multi());
  await playAll(view, [0, 1, 1]);
  assert.equal(app.button(/間違えた問題を復習する/), undefined, '間違いがなければ出さない');
});

await test('% は 0 から数え上げるが、読み上げと見出しは最初から最終値', async () => {
  enableFrames();
  const view = await open(multi());
  await playAll(view, [0, 0, 1]);               // 2 / 3 → 67%
  const ring = app.cls('ring')[0];
  const label = ring.cls('ring__label')[0];
  assert.equal(heading().textContent, '正解 2 / 3', '見出しは最終値');
  assert.equal(ring.attrs['aria-label'], '正答率 67%', '読み上げは最終値だけ');
  assert.equal(label.attrs['aria-hidden'], 'true', '数え上げ中の数字を読ませない');
  assert.equal(label.textContent, '0%', '0 から始まる');
  runFrames(400);
  const mid = parseInt(label.textContent, 10);
  assert.ok(mid > 0 && mid < 67, `途中 ${label.textContent}`);
  assert.equal(ring.attrs['aria-label'], '正答率 67%');
  runFrames(1200);
  assert.equal(label.textContent, '67%', '最後は最終値');
  assert.equal(frames.length, 0, '終わったらフレームを要求しない');
  const bar = ring.find((e) => e.attrs.class === 'ring__bar')[0];
  assert.equal(bar.attrs['stroke-dashoffset'], '33', '弧の終点は採点値のまま');
});

await test('動きを減らす設定では、数え上げず最終値をそのまま出す', async () => {
  enableFrames();
  reduce = true;
  const view = await open(multi());
  await playAll(view, [0, 0, 1]);
  const label = app.cls('ring__label')[0];
  assert.equal(label.textContent, '67%', '最初から最終値');
  runFrames(1200);
  assert.equal(label.textContent, '67%', 'フレームが進んでも数え直さない');
  assert.ok(!has(app.cls('recap__done')[0], 'is-animated'));
});

await test('0% は弧を置かず、100% は欠けがない', async () => {
  enableFrames();
  let view = await open(multi());
  await playAll(view, [1, 0, 0]);               // 0 / 3
  assert.equal(app.cls('ring__label')[0].textContent, '0%');
  assert.equal(app.find((e) => e.attrs.class === 'ring__bar').length, 0);

  view = await open(multi());
  await playAll(view, [0, 1, 1]);               // 3 / 3
  runFrames(1200);
  assert.equal(app.cls('ring__label')[0].textContent, '100%');
  assert.equal(app.find((e) => e.attrs.class === 'ring__bar')[0].attrs['stroke-dashoffset'], '0');
});

await test('結果を離れると数え上げを止める', async () => {
  enableFrames();
  const view = await open(multi());
  await playAll(view, [0, 0, 1]);
  const label = app.cls('ring__label')[0];
  clearMotion();
  app.replaceChildren(document.createElement('div'));
  runFrames(1200);
  assert.equal(label.textContent, '0%', '外れた画面を書き換え続けない');
});

await test('復習: 「復習中」を示し、初回の成績と進捗を変えず、結果へ直接戻れる', async () => {
  enableFrames();
  const view = await open(multi());
  await playAll(view, [0, 0, 1]);               // b だけ不正解
  runFrames(1200);
  assert.equal(heading().textContent, '正解 2 / 3');

  await app.button(/この段階へ戻って解き直す/).click();
  assert.ok(view.cls('review-badge')[0], '復習中の表示');
  assert.equal(view.cls('review-badge')[0].textContent, '復習中');
  assert.equal(countText(view), '回答済み 3 / 3（初回の記録）');

  // 初回に正解した a を、今回はわざと間違える。
  await view.cls('option')[1].click();
  assert.ok(has(marksOf(view)[0], 'is-bad'), '復習中の ×は今回の回答');
  const m = qmarks(view);
  assert.ok(has(m[0], 'is-ok') && m[0].textContent === '○', '全体マークは初回の記録のまま');
  assert.ok(!has(m[0], 'is-just'), '初回の記録は動かない');
  assert.equal(countText(view), '回答済み 3 / 3（初回の記録）');

  await view.button(/^結果に戻る$/).click();
  assert.equal(heading().textContent, '正解 2 / 3', '得点は上書き・二重加算されない');
  const ring = app.cls('ring')[0];
  assert.ok(has(ring, 'is-still'), '弧の演出を繰り返さない');
  assert.equal(ring.cls('ring__label')[0].textContent, '67%', '数え上げを繰り返さない');
  runFrames(1200);
  assert.equal(ring.cls('ring__label')[0].textContent, '67%');
  assert.ok(!has(app.cls('recap__done')[0], 'is-animated'), '完了の演出を繰り返さない');
  assert.ok(app.textContent.includes('演習完了！'), '完了の一言は残る');
});

await test('復習後に最後まで進んでも、完了演出は繰り返さない', async () => {
  const view = await open(multi());
  await playAll(view, [0, 0, 1]);
  await app.button(/この段階へ戻って解き直す/).click();
  await view.cls('option')[0].click();
  await view.button(/^次の問題へ$/).click();
  await view.cls('option')[1].click();          // 今回は正解
  await view.button(/^次の段階へ$/).click();
  assert.ok(view.cls('review-badge')[0], '続く段階も復習中');
  await view.button(/^次の段階へ$/).click();
  await view.cls('option')[1].click();
  await view.button(/^結果を見る$/).click();
  assert.equal(heading().textContent, '正解 2 / 3');
  assert.ok(has(app.cls('ring')[0], 'is-still'));

  // 結果から別の段階へ戻ると、また復習中になる。
  await app.button(/この段階へ戻って解き直す/).click();
  assert.ok(view.cls('review-badge')[0]);
  clearMotion();
});

await test('証拠ジャンプ・解説・ヒント・不可視文字の可視化は引き続き動く', async () => {
  const EV = 'ev-aaaaaaaaaaaaaaaaaaaaaaaa';
  const obj = multi({
    evidence: {
      [EV]: { id: EV, kind: 'process', confidence: 'observed',
              source: { archivePath: 'x.zip :: logs/a\tb.log', member: 'logs/a\tb.log', line: 3, excerpt: 'cmd.exe' } },
    },
  });
  obj.stages[0].quizzes[0].evidenceIds = [EV];
  obj.stages[0].quizzes[0].hint = 'ヒント‮本文';
  const view = await open(obj);
  assert.match(view.cls('quiz__hint-body')[0].textContent, /<U\+202E>/);
  await view.cls('option')[0].click();
  assert.ok(view.cls('reveal')[0].textContent.includes('解説 a'));
  const jump = view.button(/根拠ログを見る/);
  assert.ok(jump && jump.textContent.includes('<U+0009>'));
  globalThis.__scrolled = null;
  await jump.click();
  assert.equal(globalThis.__scrolled.id, `ev-stage-${EV}`);
  clearMotion();
});

// ---------------------------------------------------------------------------
let bad = 0;
for (const [status, name, why] of results) {
  if (status === 'ok') console.log(`  ok   ${name}`);
  else { bad++; console.log(`  NG   ${name}\n       ${why}`); }
}
console.log(`\n${results.length - bad} / ${results.length} 成功`);
process.exit(bad ? 1 : 0);
