// dom.js — 画面部品の共通処理。
//
// 文字列は必ず textContent で入れる。ZIP や GZF から来た名前が混ざるので、
// innerHTML には渡さない。

export const el = (tag, className, text) => {
  const node = document.createElement(tag);
  if (className) node.className = className;
  if (text != null) node.textContent = text;
  return node;
};

/**
 * 押しっぱなしのキーで、このボタンまで続けて押されないようにする。
 *
 * 選択肢を Enter で選ぶとフォーカスが「次へ」へ移る。そのまま押し続けると
 * キーリピートで「次へ」まで押され、解説を読む前に次の問題へ進んでしまう。
 * このボタンの上で押し始めたキーだけを、標準のボタン操作として通す。
 */
export function ignoreHeldKey(button) {
  let pressedHere = false;
  button.addEventListener('keydown', (e) => {
    if (e.key !== 'Enter' && e.key !== ' ') return;
    if (e.repeat) {
      e.preventDefault();
      return;
    }
    pressedHere = true;
  });
  button.addEventListener('keyup', (e) => {
    if (e.key === ' ' && !pressedHere) e.preventDefault();
    pressedHere = false;
  });
}

/**
 * ダブルクリックの 2 回目以降か（`detail` はブラウザが数える連続クリック数）。
 *
 * 押すと画面が描き直されるボタン（選択肢・次へ）では、2 回目のクリックが
 * 差し替わった新しいボタンに届く。ボタンごとのフラグでは防げないので、
 * クリックそのものの回数で見分ける。キーボード操作の click は detail 0 で通す。
 */
export const repeatedClick = (e) => !!e && e.detail > 1;

/**
 * 新しい画面（次の段階・結果）を先頭から見せる。
 *
 * 回答直後に設問の先頭へ滑らかにスクロールしている途中で進むと、Chrome では
 * 予約済みのフレームがもう一度だけ動き、先頭から数十 px ずれて止まる
 * （結果の一言が上部の固定ヘッダーに隠れた）。次のフレームでも先頭へ戻す。
 */
export function scrollToTop() {
  window.scrollTo(0, 0);
  if (typeof window.requestAnimationFrame === 'function') {
    window.requestAnimationFrame(() => window.scrollTo(0, 0));
  }
}

/** ホームへ戻る導線。どの画面からでも抜けられるように、必ず一つは置く。 */
export function homeNav() {
  const nav = el('div', 'navbtns navbtns--home');
  const home = el('button', 'btn btn-ghost', '← ホームに戻る');
  home.type = 'button';
  home.setAttribute('aria-label', 'ホームに戻る');
  home.addEventListener('click', () => {
    location.hash = '#/';
  });
  nav.append(home);
  return nav;
}
