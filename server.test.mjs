// node --test — 로그인 문(비밀번호 + OTP)이 제대로 잠기는지 확인한다
import { test } from 'node:test';
import assert from 'node:assert/strict';
import { mkdtempSync, existsSync, statSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import { createApp, totp, verifyTotp, b32encode, b32decode } from './server.mjs';

const PW = 'correct-horse-battery';
const newCfg = () => ({ DASH_USER: 'admin', DASH_PASSWORD: PW, HOOK_TOKEN: 't', NO_SYNC: '1', TOTP_FILE: join(mkdtempSync(join(tmpdir(), 'dash-')), '.totp-secret') });

async function withServer(cfg, fn) {
  const srv = createApp(cfg);
  await new Promise(r => srv.listen(0, '127.0.0.1', r));
  try { await fn(`http://127.0.0.1:${srv.address().port}`); } finally { srv.close(); }
}
const post = (base, path, body, headers = {}) => fetch(base + path, {
  method: 'POST', redirect: 'manual',
  headers: { 'Content-Type': 'application/x-www-form-urlencoded', ...headers },
  body: new URLSearchParams(body),
});
const ck = (r, name) => (r.headers.getSetCookie().find(c => c.startsWith(name + '=')) || '').split(';')[0];
const nowCode = s => totp(s, Math.floor(Date.now() / 30000));

test('TOTP 는 RFC 6238 테스트 값과 같다', () => {
  const s = b32encode(Buffer.from('12345678901234567890'));
  assert.equal(b32decode(s).toString(), '12345678901234567890');
  assert.equal(totp(s, 1), '287082');              // T=59
  assert.equal(totp(s, 37037036), '081804');       // T=1111111109
  const t = 59 * 1000;
  assert.equal(verifyTotp(s, '287082', t), 1);
  assert.equal(verifyTotp(s, '287082', t + 30000), 1);   // 30초 뒤(±1)까지 허용
  assert.equal(verifyTotp(s, '287082', t + 60000), -1);  // 60초 뒤는 거절
  assert.equal(verifyTotp(s, '287082', t, 1), -1);       // 이미 쓴 코드 재사용 거절
});

test('로그인 전에는 화면이 잠겨 있고 파비콘만 열린다', () => withServer(newCfg(), async base => {
  const r = await fetch(base + '/', { redirect: 'manual' });
  assert.equal(r.headers.get('location'), '/login');
  assert.equal((await fetch(base + '/bg.jpg', { redirect: 'manual' })).status, 401);
  assert.equal((await fetch(base + '/login/otp', { redirect: 'manual' })).headers.get('location'), '/login');
  assert.equal((await fetch(base + '/login/setup', { redirect: 'manual' })).headers.get('location'), '/login');
  assert.notEqual((await fetch(base + '/favicon-32.png')).status, 401);
}));

test('비밀번호만으로는 세션을 주지 않는다', () => withServer(newCfg(), async base => {
  const r = await post(base, '/login', { user: 'admin', password: PW });
  assert.equal(r.headers.get('location'), '/login/setup');
  assert.equal(ck(r, 'dash_sid'), '');
  assert.equal((await fetch(base + '/', { redirect: 'manual', headers: { cookie: ck(r, 'dash_pre') } })).status, 303);
}));

test('최초 등록 → 로그아웃 → 다시 로그인은 OTP 를 묻는다', async () => {
  const cfg = newCfg();
  await withServer(cfg, async base => {
    const r1 = await post(base, '/login', { user: 'admin', password: PW });
    const pre = ck(r1, 'dash_pre');
    const html = await (await fetch(base + '/login/setup', { headers: { cookie: pre } })).text();
    assert.match(html, /JEFF AGENTS/);
    const secret = html.match(/secret=([A-Z2-7]+)/)[1];
    assert.equal((await post(base, '/login/setup', { code: '000000' }, { cookie: pre })).headers.get('location'), '/login/setup?e=1');
    const r2 = await post(base, '/login/setup', { code: nowCode(secret) }, { cookie: pre });
    assert.equal(r2.headers.get('location'), '/');
    assert.ok(existsSync(cfg.TOTP_FILE));
    assert.equal(statSync(cfg.TOTP_FILE).mode & 0o777, 0o600);
    const sid = ck(r2, 'dash_sid');
    const pg = await fetch(base + '/', { headers: { cookie: sid } });
    assert.equal(pg.status, 200);
    assert.equal((await fetch(base + '/server.mjs', { headers: { cookie: sid } })).status, 404);
    assert.equal((await fetch(base + '/.totp-secret', { headers: { cookie: sid } })).status, 404);
    await post(base, '/logout', {}, { cookie: sid });
    assert.equal((await fetch(base + '/', { redirect: 'manual', headers: { cookie: sid } })).status, 303);

    // 등록 후에는 setup 으로 갈 수 없고 OTP 를 묻는다
    const r3 = await post(base, '/login', { user: 'admin', password: PW });
    assert.equal(r3.headers.get('location'), '/login/otp');
    const pre3 = ck(r3, 'dash_pre');
    assert.equal((await fetch(base + '/login/setup', { redirect: 'manual', headers: { cookie: pre3 } })).headers.get('location'), '/login/otp');
    // 등록 때 쓴 코드는 다시 못 쓴다
    const c = nowCode(secret);
    const ok = await post(base, '/login/otp', { code: c }, { cookie: pre3 });
    assert.notEqual(ok.headers.get('location'), '/');
  });
});

test('OTP 를 5번 틀리면 처음부터, IP 는 잠긴다', async () => {
  const cfg = newCfg();
  const secret = b32encode(Buffer.from('abcdefghijabcdefghij'));
  cfg.DASH_TOTP_SECRET = secret;
  await withServer(cfg, async base => {
    const pre = ck(await post(base, '/login', { user: 'admin', password: PW }), 'dash_pre');
    let r;
    for (let i = 0; i < 5; i++) r = await post(base, '/login/otp', { code: '000000' }, { cookie: pre });
    assert.equal(r.headers.get('location'), '/login?e=locked');
    const again = await post(base, '/login', { user: 'admin', password: PW });
    assert.equal(again.headers.get('location'), '/login?e=locked');
  });
});

test('같은 주소에서 보낸 로그인은 통과하고, 다른 사이트에서 보낸 건 거절한다', () => withServer(newCfg(), async base => {
  assert.equal((await post(base, '/login', { user: 'admin', password: PW }, { Origin: base })).headers.get('location'), '/login/setup');
  assert.equal((await post(base, '/login', { user: 'admin', password: PW }, { Origin: 'https://evil.example' })).status, 403);
  assert.equal((await fetch(base + '/login')).headers.get('referrer-policy'), 'same-origin');
}));

test('훅 이벤트로 세션 · 서브에이전트 · 승인 상태가 바뀐다', async () => {
  const { createStore } = await import('./agents.mjs');
  const st = createStore({ capture: async () => 'Do you want to proceed?\n❯ 1. Yes' });
  const base = { session_id: 'S1', cwd: '/home/dev/project/my-workspace', permission_mode: 'bypassPermissions' };
  const ev = (name, x = {}) => st.ingest({ ...base, hook_event_name: name, ...x }, '%7');
  ev('UserPromptSubmit', { prompt: '공지 API 확인' });
  ev('PreToolUse', { tool_name: 'Agent', tool_use_id: 't1', tool_input: { subagent_type: 'backend', description: '스펙 조회', prompt: 'GET /notice 찾기' } });
  ev('PostToolUse', { tool_name: 'Agent', tool_use_id: 't1', tool_response: { isAsync: true } });
  ev('PreToolUse', { tool_name: 'Grep', tool_use_id: 't2', agent_id: 'A1', agent_type: 'backend', tool_input: { pattern: 'notice' } });
  let s = st.snapshot().sessions[0];
  assert.equal(s.pane, '%7'); assert.equal(s.status, 'run'); assert.equal(s.dispatch.backend, 1);
  assert.equal(s.agents.A1.status, 'run'); assert.equal(s.agents.A1.tool, 'Grep'); assert.equal(s.agents.A1.task, 'GET /notice 찾기');
  ev('SubagentStop', { agent_id: 'A1', agent_type: 'backend', last_assistant_message: 'src/notice.controller.ts:18' });
  s = st.snapshot().sessions[0];
  assert.equal(s.agents.A1.status, 'done'); assert.equal(s.agents.A1.result, 'src/notice.controller.ts:18');
  ev('PreToolUse', { tool_name: 'Bash', tool_use_id: 't3', tool_input: { command: 'rm -rf /tmp/x', description: '정리' } });
  ev('Notification', { notification_type: 'permission_prompt', message: 'Claude needs your permission' });
  await new Promise(r => setTimeout(r, 10));
  s = st.snapshot().sessions[0];
  assert.equal(s.status, 'appr'); assert.equal(s.approval.cmd, 'rm -rf /tmp/x'); assert.match(s.approval.screen, /proceed/);
  ev('PostToolUse', { tool_name: 'Bash', tool_use_id: 't3', tool_response: { stdout: 'ok', stderr: '' } });
  ev('PreToolUse', { tool_name: 'Edit', tool_use_id: 't4', tool_input: { file_path: '/a/b.ts', old_string: 'x', new_string: 'y\nz' } });
  ev('PostToolUse', { tool_name: 'Edit', tool_use_id: 't4', tool_input: { file_path: '/a/b.ts', old_string: 'x', new_string: 'y\nz' } });
  ev('Stop', { last_assistant_message: '끝', background_tasks: [] });
  s = st.snapshot().sessions[0];
  assert.equal(s.status, 'done'); assert.equal(s.answer, '끝'); assert.equal(s.approval, null);
  assert.deepEqual([s.files[0].a, s.files[0].r], [2, 1]);
  ev('UserPromptSubmit', { prompt: '<task-notification>\n<task-id>x</task-id>' });
  assert.equal(st.snapshot().sessions[0].prompt, '공지 API 확인');          // 완료 알림은 지시가 아니다
  ev('SubagentStop', { agent_id: 'INTERNAL', last_assistant_message: '추천 질문' });
  assert.equal(st.snapshot().sessions[0].agents.INTERNAL, undefined);     // 종류 없는 내부 에이전트는 숨긴다
  ev('SessionEnd'); assert.equal(st.snapshot().sessions.length, 0);
});

test('훅은 토큰이 맞고 서버 안에서 온 것만 받는다', () => withServer({ ...newCfg(), HOOK_TOKEN: 'tok', NO_SYNC: '1' }, async base => {
  const hook = (h, b = { session_id: 'Z', hook_event_name: 'UserPromptSubmit', prompt: 'hi', cwd: '/x' }) =>
    fetch(base + '/hook', { method: 'POST', headers: { 'Content-Type': 'application/json', ...h }, body: JSON.stringify(b) });
  assert.equal((await hook({ 'X-Hook-Token': 'nope' })).status, 403);
  assert.equal((await hook({ 'X-Hook-Token': 'tok', 'X-Real-IP': '1.2.3.4' })).status, 403); // 리버스 프록시 경유
  assert.equal((await hook({ 'X-Hook-Token': 'tok' })).status, 204);
  assert.equal((await fetch(base + '/api/state')).status, 401);       // 상태는 로그인해야 보인다
  assert.equal((await fetch(base + '/events')).status, 401);
  assert.equal((await fetch(base + '/api/send', { method: 'POST', headers: { 'Content-Type': 'application/json' }, body: '{}' })).status, 401);
}));

test('git diff 를 파일별 +/- 와 줄로 바꾼다', async () => {
  const { parseDiff } = await import('./agents.mjs');
  const f = parseDiff('diff --git a/src/a.ts b/src/a.ts\nindex 1..2 100644\n--- a/src/a.ts\n+++ b/src/a.ts\n@@ -1,2 +1,2 @@ fn\n keep\n-old\n+new\n+more', 'home/');
  assert.equal(f.length, 1); assert.equal(f[0].path, 'home/src/a.ts');
  assert.deepEqual([f[0].a, f[0].r], [2, 1]);
  assert.deepEqual(f[0].diff, [['c', '⋯ fn'], ['c', 'keep'], ['r', 'old'], ['a', 'new'], ['a', 'more']]);
});

test('파일 업로드는 로그인 · 같은 사이트만, 이름은 안전하게 바꿔 600 으로 저장한다', async () => {
  const cfg = newCfg(); cfg.DASH_TOTP_SECRET = b32encode(Buffer.from('uploaduploadupload12'));
  cfg.UPLOAD_DIR = mkdtempSync(join(tmpdir(), 'up-'));
  await withServer(cfg, async base => {
    const up = (h = {}) => fetch(base + '/api/upload', { method: 'POST', headers: { 'X-File-Name': encodeURIComponent('../캡처 1.png'), ...h }, body: Buffer.from([137, 80, 78, 71]) });
    assert.equal((await up()).status, 401);
    const pre = ck(await post(base, '/login', { user: 'admin', password: PW }), 'dash_pre');
    const sid = ck(await post(base, '/login/otp', { code: nowCode(cfg.DASH_TOTP_SECRET) }, { cookie: pre }), 'dash_sid');
    assert.equal((await up({ cookie: sid, Origin: 'https://evil.example' })).status, 403);
    const r = await up({ cookie: sid });
    assert.equal(r.status, 200);
    const { path } = await r.json();
    assert.ok(path.startsWith(cfg.UPLOAD_DIR + '/'));
    assert.match(path, /-_캡처_1\.png$|-캡처_1\.png$/);
    assert.equal(statSync(path).mode & 0o777, 0o600);
  });
});

test('지시 뒤에 커밋한 변경도 이번 지시의 변경으로 보인다', async () => {
  const { gitHeads, gitChanges } = await import('./agents.mjs');
  const { execFileSync } = await import('node:child_process');
  const { writeFileSync } = await import('node:fs');
  const dir = mkdtempSync(join(tmpdir(), 'repo-'));
  const g = (...a) => execFileSync('git', ['-C', dir, '-c', 'user.name=t', '-c', 'user.email=t@t', ...a]);
  g('init', '-q'); writeFileSync(join(dir, 'a.txt'), 'one\n'); g('add', '.'); g('commit', '-qm', 'init');
  const base = await gitHeads(dir);
  writeFileSync(join(dir, 'a.txt'), 'one\ntwo\n'); g('commit', '-qam', 'edit');
  assert.deepEqual(await gitChanges(dir), []);                       // HEAD 기준이면 안 보인다
  const f = await gitChanges(dir, base);
  assert.equal(f.length, 1); assert.equal(f[0].path, 'a.txt'); assert.deepEqual([f[0].a, f[0].r], [1, 0]);
});

test('모델은 정해진 것만, 쉬는 세션에서만 바꾸고, 전역 기본값은 되돌린다', async () => {
  const { createStore, lastModel, restoreDefault } = await import('./agents.mjs');
  const { writeFileSync, readFileSync } = await import('node:fs');
  const dir = mkdtempSync(join(tmpdir(), 'm-'));
  const tr = join(dir, 't.jsonl');
  writeFileSync(tr, '{"message":{"model":"claude-opus-5-5"}}\n{"message":{"model":"<synthetic>"}}\n{"message":{"model":"claude-haiku-5-5"}}\n');
  assert.equal(lastModel(tr), 'claude-haiku-5-5');
  assert.equal(lastModel(join(dir, 'none')), '');
  const st = createStore({ settings: join(dir, 's.json') });
  st.ingest({ session_id: 'S1', cwd: dir, hook_event_name: 'Stop', transcript_path: tr }, '%1');
  assert.equal(st.snapshot().sessions[0].model, 'claude-haiku-5-5');
  assert.ok(st.snapshot().models.includes('claude-fable-5-2'));
  await assert.rejects(st.setModel('S1', 'gpt-4'), /고를 수 없는/);
  st.ingest({ session_id: 'S1', cwd: dir, hook_event_name: 'UserPromptSubmit', prompt: 'x' }, '%1');
  await assert.rejects(st.setModel('S1', 'claude-opus-5-5'), /끝난 뒤/);
  const f = join(dir, 's.json');
  writeFileSync(f, JSON.stringify({ hooks: {}, model: 'claude-opus-5-5' }));
  restoreDefault(f, undefined);
  assert.deepEqual(JSON.parse(readFileSync(f, 'utf8')), { hooks: {} });
  writeFileSync(f, JSON.stringify({ model: 'claude-haiku-5-5' }));
  restoreDefault(f, 'sonnet');
  assert.equal(JSON.parse(readFileSync(f, 'utf8')).model, 'sonnet');
});

test('미리보기 주소 · 헤더 · 로그인 확인', async () => {
  const { previewOf, upstreamHeaders } = await import('./preview.mjs');
  const list = [{ name: 'web', port: 5254 }];
  assert.equal(previewOf('web.dash.example.com', 'dash.example.com', list)?.port, 5254);
  assert.equal(previewOf('WEB.dash.example.com:443', 'dash.example.com', list)?.port, 5254);
  assert.equal(previewOf('dash.example.com', 'dash.example.com', list), null);
  assert.equal(previewOf('web.evil.com', 'dash.example.com', list), null);
  assert.equal(previewOf('other.dash.example.com', 'dash.example.com', list), null);
  assert.equal(previewOf('web.dash.example.com', '', list), null);
  const h = upstreamHeaders({ host: 'web.dash.example.com', origin: 'https://web.dash.example.com', cookie: 'dash_sid=abc; a=1; dash_pre=x' }, 5254);
  assert.equal(h.host, 'localhost:5254'); assert.equal(h.origin, 'http://localhost:5254'); assert.equal(h.cookie, 'a=1');
  assert.equal(upstreamHeaders({ cookie: 'dash_sid=abc' }, 1).cookie, undefined);
  const dir = mkdtempSync(join(tmpdir(), 'pv-'));
  const { writeFileSync } = await import('node:fs');
  writeFileSync(join(dir, 'p.json'), JSON.stringify([{ name: 'web', port: 1 }]));
  await withServer({ ...newCfg(), PREVIEW_DOMAIN: 'dash.example.com', PREVIEWS_FILE: join(dir, 'p.json') }, async base => {
    const { request } = await import('node:http'); // fetch 는 Host 를 못 바꾼다
    const r = await new Promise(ok => request(base + '/', { headers: { Host: 'web.dash.example.com' } }, ok).end());
    assert.equal(r.statusCode, 303); assert.equal(r.headers.location, 'http://dash.example.com/login');
    assert.equal((await fetch(base + '/api/previews')).status, 401);
  });
});

test("usageLimits: 요금제 한도를 이름 · 사용률로 바꾼다", async () => {
  const { usageLimits } = await import("./server.mjs");
  const r = "2026-11-18T16:00:00Z";
  assert.deepEqual(usageLimits({ limits: [
    { group: "weekly", percent: 32, resets_at: r, scope: null },
    { group: "weekly", percent: 16, resets_at: r, scope: { model: { display_name: "Fable" } } },
    { group: "session", percent: 5, resets_at: r },
  ] }).map(l => [l.label, l.used]), [["주간", 32], ["주간 · Fable", 16], ["5시간", 5]]);
  assert.deepEqual(usageLimits({ five_hour: { utilization: 40, resets_at: r }, seven_day: null }), [{ label: "5시간", used: 40, resets_at: r }]);
});

test('새 세션은 이름 · 모델 · 홈 아래 폴더만 받는다', async () => {
  const cfg = newCfg(); cfg.DASH_TOTP_SECRET = b32encode(Buffer.from('sessionsessionsessio'));
  await withServer(cfg, async base => {
    const pre = ck(await post(base, '/login', { user: 'admin', password: PW }), 'dash_pre');
    const sid = ck(await post(base, '/login/otp', { code: nowCode(cfg.DASH_TOTP_SECRET) }, { cookie: pre }), 'dash_sid');
    const ns = async b => { const r = await fetch(base + '/api/session', { method: 'POST', headers: { cookie: sid, 'Content-Type': 'application/json' }, body: JSON.stringify(b) }); return [r.status, (await r.json().catch(() => ({}))).error || '']; };
    assert.match((await ns({ name: 'Bad Name', dir: tmpdir(), model: 'claude-opus-5-5' }))[1], /이름/);
    assert.match((await ns({ name: 'preview-x', dir: tmpdir(), model: 'claude-opus-5-5' }))[1], /이름/);
    assert.match((await ns({ name: 'ok', dir: tmpdir(), model: 'gpt-4' }))[1], /모델/);
    assert.match((await ns({ name: 'ok', dir: '/etc', model: 'claude-opus-5-5' }))[1], /홈 폴더/);
    assert.match((await ns({ name: 'ok', dir: '/nope/x', model: 'claude-opus-5-5' }))[1], /없는 폴더/);
    const d = await (await fetch(base + '/api/dirs', { headers: { cookie: sid } })).json();
    assert.ok(Array.isArray(d.dirs) && d.models.includes('claude-fable-5-2'));
  });
});
test(".env 설정으로 총괄 폴더 · 에이전트 별칭 · 읽기 전용을 정한다", async () => {
  const { uiConfig } = await import("./server.mjs");
  assert.deepEqual(uiConfig({}), { lead: "", nick: {}, ro: [], name: "" });
  assert.deepEqual(uiConfig({ LEAD_DIR: " my-workspace ", AGENT_NICKNAMES: "web:웹, api : 백엔드,bad,:x", READONLY_AGENTS: "api, ", SERVER_NAME: " dev-box " }),
    { lead: "my-workspace", nick: { web: "웹", api: "백엔드" }, ro: ["api"], name: "dev-box" });
});
test("미리보기 중계는 압축 안 된 텍스트·wasm 만 gzip 한다", async () => {
  const { shouldGzip } = await import("./preview.mjs");
  const gz = { "accept-encoding": "gzip, deflate, br" };
  assert.equal(shouldGzip(gz, { "content-type": "application/wasm" }, "GET"), true);
  assert.equal(shouldGzip(gz, { "content-type": "text/javascript; charset=utf-8" }, "GET"), true);
  assert.equal(shouldGzip(gz, { "content-type": "application/wasm", "content-encoding": "br" }, "GET"), false);
  assert.equal(shouldGzip(gz, { "content-type": "text/event-stream" }, "GET"), false);
  assert.equal(shouldGzip(gz, { "content-type": "image/png" }, "GET"), false);
  assert.equal(shouldGzip({}, { "content-type": "application/wasm" }, "GET"), false);
  assert.equal(shouldGzip(gz, { "content-type": "application/wasm" }, "HEAD"), false);
});
