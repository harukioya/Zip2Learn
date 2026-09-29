// motion.js — 回答・結果の短い演出。
//
// 演出は見た目だけのもので、採点・解説・画面の進行はこれを待たない。
// 画面を離れたり描き直したりしたときは clearMotion() で全部止める。
// 止め忘れたタイマーが、後から出した新しい演出を消さないようにするため。
//
// 時間は styles/design.css の --mark-ms / --count-ms と揃える。

export const MARK_MS = 800;
export const COUNT_MS = 900;

const SVG_NS = 'http://www.w3.org/2000/svg';

/** 動きを減らす設定か。CSS だけでなく、JS の数え上げもこれで止める。 */
export function reducedMotion() {
  return (
    typeof window !== 'undefined' &&
    typeof window.matchMedia === 'function' &&
    window.matchMedia('(prefers-reduced-motion: reduce)').matches
  );
}

// 動いている演出の後片付け。どれも何度呼んでも害がない。
const running = new Set();

function track(stop) {
  const entry = () => {
    running.delete(entry);
    stop();
  };
  running.add(entry);
  return entry;
}

/** 動いている演出を全部止め、画面に残っている中央の ○・× を消す。 */
export function clearMotion() {
  [...running].forEach((stop) => stop());
}

function svgEl(tag, attrs) {
  const node = document.createElementNS(SVG_NS, tag);
  Object.entries(attrs).forEach(([k, v]) => node.setAttribute(k, String(v)));
  return node;
}

/**
 * 回答直後に画面中央へ ○「正解！」／×「不正解」を出し、約 800ms で消す。
 *
 * 読み上げは設問の正誤表示（role=status）が担うので、ここは aria-hidden に
 * して二重に読ませない。クリックも通す（pointer-events: none）。
 * 同時に出すのは 1 つだけ。前のものは出す前に消す。
 */
export function showAnswerMark(host, isCorrect) {
  clearMotion();

  const mark = document.createElement('div');
  mark.className = `answer-mark ${isCorrect ? 'is-ok' : 'is-bad'}`;
  mark.setAttribute('aria-hidden', 'true');

  const icon = svgEl('svg', { class: 'answer-mark__icon', viewBox: '0 0 100 100', focusable: 'false' });
  if (isCorrect) {
    icon.append(svgEl('circle', { class: 'answer-mark__stroke', cx: 50, cy: 50, r: 34, pathLength: 100 }));
  } else {
    icon.append(
      svgEl('line', { class: 'answer-mark__stroke', x1: 28, y1: 28, x2: 72, y2: 72, pathLength: 100 }),
      svgEl('line', { class: 'answer-mark__stroke answer-mark__stroke--late', x1: 72, y1: 28, x2: 28, y2: 72, pathLength: 100 })
    );
  }
  const text = document.createElement('span');
  text.className = 'answer-mark__text';
  text.textContent = isCorrect ? '正解！' : '不正解';
  mark.append(icon, text);
  host.appendChild(mark);

  // CSS の終了イベントには頼らない。来なくても時間で必ず消す。
  let timer = null;
  const stop = track(() => {
    clearTimeout(timer);
    mark.remove();
  });
  timer = setTimeout(stop, MARK_MS);
  return mark;
}

/**
 * 数字を 0 から最終値まで数え上げる（見た目だけ）。
 *
 * 最終値は呼び出し側が先に読み上げ用へ渡しておく。ここは表示の文字だけを
 * 書き換える。動きを減らす設定や、フレームの API が無い環境では最終値を
 * そのまま出す。
 */
export function countUp(node, to, format) {
  const done = () => { node.textContent = format(to); };
  const raf = typeof window !== 'undefined' && window.requestAnimationFrame;
  if (reducedMotion() || typeof raf !== 'function' || to <= 0) {
    done();
    return;
  }
  node.textContent = format(0);
  let frame = null;
  let start = null;
  const stop = track(() => {
    if (frame !== null && typeof window.cancelAnimationFrame === 'function') {
      window.cancelAnimationFrame(frame);
    }
    frame = null;
  });
  const step = (now) => {
    frame = null;
    if (!node.isConnected) { stop(); return; }
    if (start === null) start = now;
    const t = Math.min(1, (now - start) / COUNT_MS);
    // CSS 側の弧（cubic-bezier(.33,1,.68,1)）と同じ減速にする。
    const eased = 1 - Math.pow(1 - t, 3);
    if (t >= 1) {
      done();
      stop();
      return;
    }
    node.textContent = format(Math.round(to * eased));
    frame = window.requestAnimationFrame(step);
  };
  frame = window.requestAnimationFrame(step);
}
