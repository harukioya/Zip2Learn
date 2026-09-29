// recap.js — 最終調査レポート。
//
// 得点と ATT&CK の一覧だけでは、「何が観測され、どの順で記録され、何がまだ
// 分からないか」を説明できるようにならない。ここは、回答結果（利用者ごとに
// 変わる）と、教材に保存された静的なレポート（誰が解いても同じ）を、画面で
// 結合して見せる。教材へ得点を書き戻さないのは、同じ教材を複数人が解くため。
//
// ZIP 由来の文字列は textContent でのみ描く。原文の不可視文字は evidence.js
// の visible() を通す。

import {
  citedEvidence,
  evidenceCard,
  evidenceMap,
  jumpButtons,
  visible,
} from './evidence.js';
import { glossary, staticGlossary } from './intro.js';
import { profileLine, profileOfLesson } from './profile.js';
import { el } from './dom.js';
import { clearMotion, countUp, reducedMotion } from './motion.js';

let foldSeq = 0;

const STATUS_LABEL = {
  observed: '観測された事実',
  correlated: '複数記録からの関連付け',
  hypothesis: '未確定（追加調査が必要）',
};

const CATEGORY_LABEL = {
  'log-reading': 'ログの意味を読む',
  evidence: '根拠を特定する',
  correlation: '二つの証拠を関連付ける',
  attck: '観測を手法に対応させる',
  limits: '断定できない理由を説明する',
  'static-string': '命令が参照する文字列を読む',
  'static-call': '直接呼び出しの行き先を読む',
  'static-external': '外部関数を見分ける',
  'static-limits': '記録から言えないことを分ける',
};

// このレポート画面の id 空間。演習の段階とは別に持つ。レポートは mount を
// 丸ごと差し替えて描かれるので、段階側のカードはもう頁に無い。同じ id を
// 探していたために、レポートの「根拠ログを見る」は押しても何も起きなかった。
const SCOPE = 'report';

/** 見出し付きの区画。中身が空なら null を返し、空の箱を並べない。 */
function section(title, build) {
  const box = el('section', 'panel');
  box.append(el('div', 'panel__label', title));
  const filled = build(box);
  return filled === false ? null : box;
}

/** 成績の直下とレポート末尾に、同じ操作を独立したボタンとして置く。 */
function resultNav(lesson, nearScores = false) {
  const nav = el('div', nearScores ? 'navbtns navbtns--wrap recap__actions' : 'navbtns');
  const back = el('button', 'btn btn-ghost', '演習の一覧に戻る');
  back.type = 'button';
  back.setAttribute('aria-label', '演習の一覧に戻る');
  back.addEventListener('click', () => { location.hash = '#/'; });
  const replay = el('button', 'btn btn-primary', 'もう一度');
  replay.type = 'button';
  replay.setAttribute('aria-label', 'この演習を最初からやり直す');
  replay.addEventListener('click', () => {
    // 初回の成績も含めて、演習を最初からやり直す。
    const target = `#/lesson/${lesson.id}`;
    if (location.hash === target) {
      window.dispatchEvent(new HashChangeEvent('hashchange'));
    } else {
      location.hash = target;
    }
  });
  nav.append(back, replay);
  return nav;
}

/**
 * 一覧の 1 件目だけを見せ、残りは「続きを読む」で開く。
 *
 * レポートは長く、どの区画も全件を並べると先の区画へたどり着けない。1 件目で
 * 何が書いてあるかを示し、続きは読みたい人が開く。開くと上のボタンは
 * 「閉じる」に変わり、最後の項目の下にも「閉じる」を置く（長い一覧を読み
 * 終えた位置から戻れるように）。
 *
 * `makeList` は項目を入れる器（ol / ul / div）を作る。null なら区画へ直接並べる。
 * `numbered` の一覧（ol）は、続きの器を 2 から数え始める。
 *
 * 続きの器には `revealFold()` を持たせる。レポート内の「根拠ログを見る」は、
 * 飛び先のカードが畳まれていればこれで開いてから移動する（evidence.js）。
 */
function foldList(box, items, makeList, numbered = false) {
  const into = (target, nodes, start) => {
    if (!makeList) {
      target.append(...nodes);
      return;
    }
    const list = makeList();
    if (numbered && start > 1) list.setAttribute('start', String(start));
    list.append(...nodes);
    target.append(list);
  };
  into(box, items.slice(0, 1), 1);
  if (items.length <= 1) return;

  const rest = el('div', 'fold-rest');
  rest.id = `fold-rest-${++foldSeq}`;
  rest.hidden = true;
  into(rest, items.slice(1), 2);

  const moreLabel = `続きを読む（残り ${items.length - 1} 件）`;
  const toggle = el('button', 'btn btn-primary fold-toggle', moreLabel);
  toggle.type = 'button';
  toggle.setAttribute('aria-controls', rest.id);
  toggle.setAttribute('aria-expanded', 'false');

  const close = el('button', 'btn btn-primary fold-toggle', '閉じる');
  close.type = 'button';
  close.setAttribute('aria-controls', rest.id);
  const closeNav = el('div', 'fold-end');
  closeNav.append(close);
  rest.append(closeNav);

  const setOpen = (open) => {
    rest.hidden = !open;
    toggle.textContent = open ? '閉じる' : moreLabel;
    toggle.setAttribute('aria-expanded', String(open));
  };
  rest.revealFold = () => setOpen(true);
  toggle.addEventListener('click', () => setOpen(rest.hidden));
  close.addEventListener('click', () => {
    setOpen(false);
    // 下の「閉じる」で畳むと、読んでいた位置の中身が消える。上のボタンまで
    // 戻し、そこへフォーカスを移す。
    toggle.scrollIntoView({ block: 'nearest', behavior: reducedMotion() ? 'auto' : 'smooth' });
    toggle.focus({ preventScroll: true });
  });
  box.append(toggle, rest);
}

const SVG_NS = 'http://www.w3.org/2000/svg';

/**
 * 正答率のリング。中央に % を出し、開いたときに弧が伸びる。
 *
 * 伸びる動きは CSS の keyframes（`from` だけを書く）で付ける。終点は
 * `stroke-dashoffset` 属性に置いた値で、アニメーションが終わるとそこへ
 * 落ち着く。中央の % は同じ時間で 0 から数え上げる（motion.js）。どちらも
 * 見た目だけで、動きを減らす設定や `animate` が偽のときは最終値で止まって出る。
 *
 * 数字は見出しの「正解 X / Y」と同じ値から出す。読み上げでは円は 1 枚の
 * 画像として「正答率 N%」とだけ伝え、中の図形も数え上げの途中も読ませない。
 */
function scoreRing(correct, total, animate) {
  const pct = total > 0 ? Math.round((correct / total) * 100) : 0;

  const wrap = el('div', animate ? 'ring' : 'ring is-still');
  wrap.setAttribute('role', 'img');
  wrap.setAttribute('aria-label', `正答率 ${pct}%`);

  const svg = document.createElementNS(SVG_NS, 'svg');
  svg.setAttribute('viewBox', '0 0 120 120');
  svg.setAttribute('aria-hidden', 'true');
  svg.setAttribute('focusable', 'false');

  const circle = (cls) => {
    const c = document.createElementNS(SVG_NS, 'circle');
    c.setAttribute('class', cls);
    c.setAttribute('cx', '60');
    c.setAttribute('cy', '60');
    c.setAttribute('r', '50');
    // 円周を 100 と見なす。% をそのまま長さとして使える。
    c.setAttribute('pathLength', '100');
    return c;
  };
  svg.append(circle('ring__track'));
  // 0% のときは弧を描かない。端が丸いので、長さ 0 でも点が 1 つ残る。
  if (pct > 0) {
    const bar = circle('ring__bar');
    bar.setAttribute('stroke-dasharray', '100');
    bar.setAttribute('stroke-dashoffset', String(100 - pct));
    svg.append(bar);
  }
  wrap.append(svg);
  const label = el('span', 'ring__label', `${pct}%`);
  label.setAttribute('aria-hidden', 'true');
  wrap.append(label);
  return { wrap, start: () => { if (animate) countUp(label, pct, (n) => `${n}%`); } };
}

/** 結果の上に出す完了の一言。0 問の演習は「全問正解」と扱わない。 */
function doneMessage(correct, total) {
  if (total <= 0) return ['記録の確認が完了しました'];
  return [correct >= total ? '全問正解！ ' : '演習完了！ ', 'おつかれさまでした'];
}

/**
 * @param {HTMLElement} mount
 * @param {object} lesson
 * @param {{correct:number,total:number,answers?:Array,goToStage?:Function}} stats
 */
export function renderRecap(mount, lesson, stats) {
  clearMotion();
  const recap = lesson.recap || {};
  const report = lesson.report || {};
  const evidence = evidenceMap(lesson);
  const correct = Number(stats && stats.correct) || 0;
  const total = Number(stats && stats.total) || 0;
  const answers = (stats && stats.answers) || [];
  const goToStage = stats && stats.goToStage;
  // 完了の演出（数え上げ・弧・一言の出方）は最初の 1 回だけ。復習から
  // 戻ったときは最終値のまま出す。
  const animate = !!(stats && stats.animate) && !reducedMotion();
  // 静的解析の教材には時系列が無い。記録の順序や ATT&CK の代わりに、静的に
  // 確かめられた事実と、実行しないと分からないことを並べる。
  const staticLesson = lesson.kind === 'static';
  const staticFacts = staticLesson && Array.isArray(report.facts) ? report.facts : [];

  const root = document.createElement('section');
  root.className = 'recap';

  // ---- 完了の一言と得点 ----
  // 句ごとに分けて並べる。狭い画面では「！」の後で折り返し、語の途中で切れない。
  const done = el('p', animate ? 'recap__done is-animated' : 'recap__done');
  doneMessage(correct, total).forEach((t) => done.append(el('span', 'recap__done-part', t)));
  root.appendChild(done);
  root.appendChild(el('p', 'eyebrow', '調査レポート'));
  // 復習で解き直しても、ここは初回の回答のまま。そう書いておく。
  if (total > 0) {
    root.appendChild(
      el('p', 'recap__first muted', '初回の成績（復習で解き直した回答は含みません）')
    );
  }
  const scoreRow = el('div', 'recap__score');
  const heading = document.createElement('h1');
  heading.textContent = `正解 ${correct} / ${total}`;
  heading.tabIndex = -1;
  const ring = scoreRing(correct, total, animate);
  scoreRow.append(heading, ring.wrap);
  root.appendChild(scoreRow);

  // 間違いがあれば、下の「間違えた問題」へすぐ移れるようにする。
  const wrong = answers.filter((a) => !a.correct);
  let wrongBox = null;
  if (wrong.length) {
    const toReview = el('button', 'btn btn-ghost btn-sm recap__review', '間違えた問題を復習する');
    toReview.type = 'button';
    toReview.addEventListener('click', () => {
      if (!wrongBox) return;
      wrongBox.scrollIntoView({ block: 'start', behavior: reducedMotion() ? 'auto' : 'smooth' });
      wrongBox.focus({ preventScroll: true });
    });
    const reviewNav = el('div', 'navbtns navbtns--wrap');
    reviewNav.append(toReview);
    root.appendChild(reviewNav);
  }

  // どのデータセット形式として読んだ教材か。データセット画面・導入画面と
  // 同じ 1 行を出す。レポートだけを見た人にも、分類の前提が分かるように。
  const profile = profileOfLesson(lesson);
  if (profile) {
    root.appendChild(el('p', 'muted', profileLine(profile)));
  }

  if (recap.summary) {
    root.appendChild(el('p', 'muted', visible(recap.summary)));
  }

  // ---- 段階別・カテゴリ別 ----
  if (answers.length) {
    const byStage = new Map();
    const byCategory = new Map();
    answers.forEach((a) => {
      for (const [map, key, label] of [
        [byStage, a.stageId || a.stageName, a.stageName || a.stageId],
        [byCategory, a.category, CATEGORY_LABEL[a.category] || a.category],
      ]) {
        const row = map.get(key) || { label, correct: 0, total: 0 };
        row.total += 1;
        if (a.correct) row.correct += 1;
        map.set(key, row);
      }
    });
    const scores = section('段階別・カテゴリ別の成績', (box) => {
      [['段階別', byStage], ['学習カテゴリ別', byCategory]].forEach(([name, map]) => {
        box.append(el('p', 'muted', name));
        const list = el('div', 'scorelist');
        [...map.values()].forEach((row) => {
          const line = el('div', 'scorelist__row');
          line.append(el('span', 'scorelist__name', visible(row.label)));
          line.append(el('span', 'scorelist__val mono', `${row.correct} / ${row.total}`));
          list.append(line);
        });
        box.append(list);
      });
    });
    root.appendChild(scores);
  }
  root.appendChild(resultNav(lesson, true));

  // ---- 観測された時系列 ----
  const timeline = Array.isArray(report.timeline) ? report.timeline : [];
  const techniques = Array.isArray(report.techniques) ? report.techniques : [];
  if (staticLesson) {
    root.appendChild(
      section('静的に確認できた事実', (box) => {
        box.append(
          el('p', 'muted',
            'Ghidra が GZF に保存した記録から、直接確かめられたことの一覧です。どれも「そういう命令・記録がある」という事実で、実行時に起きたことではありません。')
        );
        if (!staticFacts.length) {
          box.append(el('p', 'muted', '示せる事実がありませんでした。'));
          return;
        }
        const items = staticFacts.map((row) => {
          const item = el('li', 'timeline__row');
          item.append(el('span', 'timeline__status', CATEGORY_LABEL[row.category] || ''));
          item.append(el('span', 'timeline__title', visible(row.title || '')));
          const jump = jumpButtons(row.evidenceIds, evidence, SCOPE, '根拠の記録を見る');
          if (jump) item.append(jump);
          return item;
        });
        foldList(box, items, () => el('ol', 'timeline'), true);
      })
    );
  }

  if (!staticLesson) root.appendChild(
    section('記録された順序', (box) => {
      box.append(
        el('p', 'muted',
          'ログにこの順で記録された、という一覧です。記録の前後は、一方が他方を引き起こしたことを意味しません。')
      );
      if (!timeline.length) {
        box.append(el('p', 'muted', '時刻を読み取れた記録がありませんでした。'));
        return;
      }
      const items = [];
      timeline.forEach((row) => {
        const item = el('li', 'timeline__row');
        const when = el('span', 'timeline__time mono',
          row.timeKnown ? visible(row.timestamp) : '時刻不明');
        item.append(when);
        // タイムゾーンが読めなかった行は、同じログの中でしか前後を比べ
        // られない。一本の軸に並んでいる見た目に引きずられないよう、行に
        // そう書く。教材側の相関も、この札が同じ行どうししか結ばない。
        if (row.timeKnown && row.timeComparable === false) {
          const mark = el('span', 'timeline__basis', '基準不明');
          mark.setAttribute(
            'title',
            'タイムゾーンが書かれていません。同じログの中でのみ前後を比べられます。'
          );
          when.append(mark);
        }
        item.append(el('span', 'timeline__title', visible(row.title || '')));
        // 状態は色だけでなく文言でも出す。
        item.append(
          el('span', 'timeline__status',
            STATUS_LABEL[row.status] || row.status || '')
        );
        item.append(
          el('span', 'timeline__src mono',
            `${visible(row.member || '')} : ${row.line} 行目`)
        );
        const jump = jumpButtons(row.evidenceIds, evidence, SCOPE);
        if (jump) item.append(jump);
        items.push(item);
      });
      foldList(box, items, () => el('ol', 'timeline'), true);
    })
  );

  // ---- このレポートが参照する記録 ----
  //
  // レポートの中から「根拠ログを見る」で飛べる先は、ここに置いたカードだけ
  // である。だから、レポートのどこかが指している証拠は、ひとつ残らずここに
  // 並べなければならない。以前は回答が指したものだけを並べ、しかも
  // anchor=false で id を付けていなかったので、時系列と ATT&CK のボタンは
  // 押しても何も起きなかった。
  //
  // 集める順は、時系列（記録された順）、ATT&CK、回答。先頭を時系列にして
  // おくと、一覧そのものが読み下せる並びになる。
  const keyIds = [];
  const addId = (i) => {
    if (evidence[i] && !keyIds.includes(i)) keyIds.push(i);
  };
  timeline.forEach((row) => (row.evidenceIds || []).forEach(addId));
  staticFacts.forEach((row) => (row.evidenceIds || []).forEach(addId));
  techniques.forEach((t) => {
    (t.evidenceIds || []).forEach(addId);
    (t.reasons || []).forEach((r) => (r.evidenceIds || []).forEach(addId));
  });
  answers.forEach((a) => (a.evidenceIds || []).forEach(addId));
  if (keyIds.length) {
    root.appendChild(
      section('判断の根拠になった記録', (box) => {
        box.append(
          el('p', 'muted',
            staticLesson
              ? 'このレポートの「根拠の記録を見る」は、すべてこの一覧の記録を指しています。'
              : 'このレポートの「根拠ログを見る」は、すべてこの一覧の記録を指しています。')
        );
        const cards = keyIds.map((i) => evidenceCard(evidence[i], null, true, SCOPE));
        foldList(box, cards, () => el('div', 'evidence-list'));
      })
    );
  }

  // ---- ATT&CK ----
  if (!staticLesson) root.appendChild(
    section('MITRE ATT&CK との対応', (box) => {
      if (!techniques.length) {
        box.append(
          el('p', 'muted',
            '根拠を説明できる対応が見つかりませんでした。推測で手法を当てはめていません。')
        );
        // 旧形式の recap.chain があれば、そちらは従来どおり出す。
        return;
      }
      techniques.forEach((t) => {
        const card = el('div', 'technique');
        const head = el('div', 'technique__head');
        head.append(el('span', 'attck-badge', `${visible(t.id)} · ${visible(t.name)}`));
        head.append(
          el('span', 'technique__status',
            `${STATUS_LABEL[t.status] || t.status || ''}／確信度 ${visible(t.confidence || '')}`)
        );
        card.append(head);

        // 同じ手法でも、理由が違えば根拠も違う。vssadmin と bcdedit は
        // どちらも T1490 だが、観測しているものは別である。理由ごとに
        // その理由を支える記録だけを並べ、まとめて 1 つの説明に押し込まない。
        const reasons = Array.isArray(t.reasons) && t.reasons.length
          ? t.reasons
          : [{ reason: t.reason || '', evidenceIds: t.evidenceIds || [] }];
        let linked = false;
        reasons.forEach((r) => {
          card.append(el('p', 'technique__reason', visible(r.reason || '')));
          const jump = jumpButtons(r.evidenceIds, evidence, SCOPE);
          if (jump) {
            card.append(jump);
            linked = true;
          }
        });
        if (!linked) card.append(el('p', 'muted', '根拠の記録を特定できませんでした。'));
        card.append(
          el('p', 'technique__rule mono', `対応規則 ${visible(t.ruleVersion || '')}`)
        );
        box.append(card);
      });
    })
  );

  // ---- 旧形式のキルチェーン ----
  const chain = Array.isArray(recap.chain) ? recap.chain : [];
  if (chain.length) {
    const killchain = el('div', 'killchain');
    chain.forEach((step) => {
      const kc = el('div', 'kc-step');
      kc.append(
        el('div', 'kc-step__name',
          step.stage ? `${visible(step.stage)}: ${visible(step.name || '')}`
                     : visible(step.name || ''))
      );
      if (step.desc) kc.append(el('p', 'kc-step__desc', visible(step.desc)));
      (Array.isArray(step.attck) ? step.attck : []).forEach((t) => {
        kc.append(
          el('span', 'attck-badge',
            t && t.name ? `${visible(t.id)} · ${visible(t.name)}` : visible((t && t.id) || ''))
        );
      });
      killchain.append(kc);
    });
    root.appendChild(killchain);
  }

  // ---- 間違えた問題と復習 ----
  wrongBox = section('間違えた問題', (box) => {
    if (!answers.length) {
      box.append(el('p', 'muted', '回答の記録がありません。'));
      return;
    }
    if (!wrong.length) {
      box.append(el('p', 'muted', '間違えた問題はありません。'));
      return;
    }
    const rows = wrong.map((a) => {
      const row = el('div', 'review');
      row.append(
        el('div', 'review__q',
          visible((a.quiz && (a.quiz.q || a.quiz.prompt)) || a.questionId))
      );
      row.append(
        el('p', 'muted',
          `${visible(a.stageName || '')}／${CATEGORY_LABEL[a.category] || a.category}`)
      );
      // 根拠をその場で再表示する。戻らなくても確かめられるようにする。
      const cited = citedEvidence(a.evidenceIds, evidence);
      if (cited) row.append(cited);

      const nav = el('div', 'navbtns navbtns--wrap');
      if (goToStage && a.stageId) {
        const back = el('button', 'btn btn-ghost btn-sm', 'この段階へ戻って解き直す');
        back.type = 'button';
        back.addEventListener('click', () => goToStage(a.stageId));
        nav.append(back);
      }
      const jump = jumpButtons(
        a.evidenceIds, evidence, SCOPE,
        staticLesson ? '根拠の記録を見る' : '根拠ログを見る'
      );
      if (jump) nav.append(...jump.children);
      if (nav.children.length) row.append(nav);
      return row;
    });
    foldList(box, rows, null);
  });
  // 「間違えた問題を復習する」の移動先。
  wrongBox.tabIndex = -1;
  wrongBox.classList.add('recap__wrong');
  root.appendChild(wrongBox);

  // ---- 未確定事項 ----
  const unknowns = Array.isArray(report.unknowns) ? report.unknowns : [];
  if (unknowns.length) {
    root.appendChild(
      section('断定できなかったこと', (box) => {
        // 件数が少なく、どれも結論の限界を示すので畳まずに全件を出す。
        unknowns.forEach((u) => {
          const item = el('div', 'unknown');
          item.append(el('div', 'unknown__topic', visible(u.topic || '')));
          item.append(el('p', 'unknown__detail', visible(u.detail || '')));
          box.append(item);
        });
      })
    );
  }

  // ---- 追加調査 ----
  const next = Array.isArray(report.nextInvestigations) ? report.nextInvestigations : [];
  if (next.length) {
    root.appendChild(
      section('次に調べるとよいこと', (box) => {
        // 短い一行ずつなので、畳まずに全件を出す。
        const ul = el('ul', 'bullets');
        next.forEach((t) => ul.append(el('li', null, visible(t))));
        box.append(ul);
      })
    );
  }

  root.appendChild(staticLesson ? staticGlossary() : glossary());

  // 何も無い教材でも白画面にしない。
  if (!timeline.length && !techniques.length && !answers.length && !chain.length
      && !staticFacts.length) {
    root.appendChild(
      el('p', 'muted',
        'この演習からは、まとめとして示せる記録が得られませんでした。読み取れたログが少ないか、根拠が不足しています。')
    );
  }

  // ---- 導線 ----
  root.appendChild(resultNav(lesson));

  mount.replaceChildren(root);
  heading.focus({ preventScroll: true });
  ring.start();
}
