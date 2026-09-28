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
