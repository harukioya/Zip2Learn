// http.js — サーバーとのやり取りの共通処理。
//
// 変更を伴う要求には、サーバーがページに埋め込んだトークンを付ける。

/** ページの meta に埋め込まれたトークン。無ければ空文字。 */
export function token() {
  const meta = document.querySelector('meta[name="zip2learn-token"]');
  return meta ? meta.content : '';
}

/** トークン付きの JSON 用ヘッダー。 */
export function authHeaders() {
  return { 'Content-Type': 'application/json', 'X-Zip2Learn-Token': token() };
}

/** 応答を JSON で返す。失敗は Error として投げる（本文の error を文言に使う）。 */
export async function api(path, options) {
  const res = await fetch(path, { ...options, headers: authHeaders() });
  if (!res.ok) {
    const body = await res.json().catch(() => ({}));
    throw new Error(body.error || `通信に失敗しました（${res.status}）`);
  }
  return res.json();
}

/** 応答を JSON で読む。失敗しても投げず、{ok, status, body} の形に揃えて返す。 */
export async function call(path, options = {}) {
  let res;
  try {
    res = await fetch(path, {
      ...options,
      headers: { ...authHeaders(), ...(options.headers || {}) },
    });
  } catch (err) {
    if (err && err.name === 'AbortError') {
      return { ok: false, status: 0, aborted: true, body: { error: '送信を取り消しました。' } };
    }
    return { ok: false, status: 0, body: { error: 'サーバーに接続できません。python3 backend/api.py で起動しているか確かめてください。' } };
  }
  const body = await res.json().catch(() => ({}));
  return { ok: res.ok, status: res.status, body };
}
