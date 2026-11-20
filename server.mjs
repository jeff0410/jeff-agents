// 대시보드 서버 — 아이디·비밀번호 + OTP(TOTP) 2단계 로그인, Claude Code 세션 연동. 외부 패키지 없음.
import http from 'node:http';
import { readFileSync, writeFileSync, existsSync, mkdirSync, realpathSync, statSync, readdirSync } from 'node:fs';
import { randomBytes, timingSafeEqual, createHash, createHmac } from 'node:crypto';
import { join, dirname } from 'node:path';
import { fileURLToPath } from 'node:url';
import { homedir, cpus, totalmem, freemem } from 'node:os';
import { execFile } from 'node:child_process';
import { createStore, hookToken, tmux, MODELS } from './agents.mjs';
import { loadPreviews, previewOf, proxy, proxyUpgrade, isUp } from './preview.mjs';

const ROOT = dirname(fileURLToPath(import.meta.url));
const BRAND = 'JEFF AGENTS';
const SESSION_TTL = 12 * 3600;  // 초
const PENDING_TTL = 5 * 60 * 1000; // 비밀번호 통과 후 OTP 입력까지 허용 시간
const MAX_FAILS = 5;
const FAIL_WINDOW = 15 * 60 * 1000;
const PRIVATE = { '/': ['index.html', 'text/html; charset=utf-8'], '/bg.jpg': ['bg.jpg', 'image/jpeg'] };
const PUBLIC = { '/favicon-16.png': 'favicon-16.png', '/favicon-32.png': 'favicon-32.png', '/apple-touch-icon.png': 'apple-touch-icon.png' };

export function loadEnv(file) {
  const env = {};
  if (!existsSync(file)) return env;
  for (const line of readFileSync(file, 'utf8').split(/\r?\n/)) {
    const m = line.match(/^\s*([A-Z0-9_]+)\s*=\s*(.*?)\s*$/);
    if (!m) continue;
    let v = m[2];
    if (/^(['"]).*\1$/.test(v)) v = v.slice(1, -1);
    env[m[1]] = v;
  }
  return env;
}

// 길이가 달라도 시간 차이가 안 나게 해시끼리 비교한다
const same = (a, b) => timingSafeEqual(createHash('sha256').update(String(a)).digest(), createHash('sha256').update(String(b)).digest());

/* ---------- TOTP (RFC 6238, SHA1 · 6자리 · 30초) ---------- */
const B32 = 'ABCDEFGHIJKLMNOPQRSTUVWXYZ234567';
export function b32encode(buf) {
  let bits = 0, val = 0, out = '';
  for (const b of buf) { val = (val << 8) | b; bits += 8; while (bits >= 5) { out += B32[(val >>> (bits - 5)) & 31]; bits -= 5; } }
  if (bits > 0) out += B32[(val << (5 - bits)) & 31];
  return out;
}
export function b32decode(s) {
  s = s.replace(/=+$/, '').replace(/\s/g, '').toUpperCase();
  let bits = 0, val = 0; const out = [];
  for (const c of s) {
    const i = B32.indexOf(c); if (i < 0) throw new Error('bad base32');
    val = (val << 5) | i; bits += 5;
    if (bits >= 8) { out.push((val >>> (bits - 8)) & 255); bits -= 8; }
  }
  return Buffer.from(out);
}
export function totp(secret, counter) {
  const msg = Buffer.alloc(8); msg.writeBigUInt64BE(BigInt(counter));
  const h = createHmac('sha1', b32decode(secret)).update(msg).digest();
  const o = h[19] & 15;
  const n = ((h[o] & 127) << 24) | (h[o + 1] << 16) | (h[o + 2] << 8) | h[o + 3];
  return String(n % 1e6).padStart(6, '0');
}
// 맞으면 사용한 counter, 틀리면 -1. 앞뒤 30초(±1) 허용, 이미 쓴 코드는 재사용 불가.
export function verifyTotp(secret, code, now = Date.now(), lastUsed = -1) {
  if (!/^\d{6}$/.test(String(code))) return -1;
  const c = Math.floor(now / 30000);
  for (const k of [c - 1, c, c + 1]) if (k > lastUsed && same(totp(secret, k), code)) return k;
  return -1;
}

export function createApp(cfg) {
  const sessions = new Map(); // token -> 만료 시각(ms)
  const pending = new Map();  // 비밀번호 통과 토큰 -> { exp, tries, secret? }
  const fails = new Map();    // ip -> { n, first }
  const secure = cfg.COOKIE_SECURE === '1';
  const trustProxy = cfg.TRUST_PROXY === '1';
  const secretFile = cfg.TOTP_FILE || join(ROOT, '.totp-secret');
  // 개발 서버 미리보기: <이름>.PREVIEW_DOMAIN. 설정하면 로그인 쿠키도 하위 도메인에 같이 쓰인다.
  const pvDomain = cfg.PREVIEW_DOMAIN || '';
  const previews = () => loadPreviews(cfg.PREVIEWS_FILE || join(ROOT, 'previews.json'));
  const scheme = cfg.COOKIE_SECURE === '1' ? 'https' : 'http';
  let lastUsed = -1;
  // 세션 상태: 훅으로 받고, 화면에는 SSE 로 밀어준다
  const clients = new Set();
  let tmr = null;
  const stateFile = cfg.STATE_FILE || join(homedir(), '.agent-dash', 'state.json');
  let initial = null;
  if (!cfg.NO_SYNC) try { initial = JSON.parse(readFileSync(stateFile, 'utf8')); } catch {}
  const store = createStore({ initial, onChange: () => { clearTimeout(tmr); tmr = setTimeout(() => {
    const snap = store.snapshot(), d = `data: ${JSON.stringify(snap)}\n\n`;
    for (const c of clients) c.write(d);
    if (!cfg.NO_SYNC) try { writeFileSync(stateFile, JSON.stringify(snap), { mode: 0o600 }); } catch {}
  }, 250); } });
  const hookTok = cfg.HOOK_TOKEN || hookToken();
  if (!cfg.NO_SYNC) setInterval(() => store.sync(), 10000).unref();
  // 훅은 이 서버 안(127.0.0.1)에서 직접 온 것만 받는다. 리버스 프록시를 거친 요청은 X-Real-IP 가 붙어 있어 거절된다.
  const loopback = req => ['127.0.0.1', '::1', '::ffff:127.0.0.1'].includes(req.socket.remoteAddress) && !req.headers['x-real-ip'] && !req.headers['x-forwarded-for'];
  const readBuf = (req, max) => new Promise((ok, no) => {
    const bs = []; let n = 0;
    req.on('data', c => { n += c.length; if (n > max) { no(new Error('too large')); req.destroy(); } else bs.push(c); });
    req.on('end', () => ok(Buffer.concat(bs))); req.on('error', no);
  });
  const upDir = cfg.UPLOAD_DIR || join(homedir(), '.agent-dash', 'uploads');
  const readRaw = (req, max) => new Promise((ok, no) => {
    let b = '', n = 0; req.setEncoding('utf8');
    req.on('data', c => { n += c.length; if (n > max) { no(new Error('too large')); req.destroy(); } else b += c; });
    req.on('end', () => ok(b)); req.on('error', no);
  });
  const getSecret = () => cfg.DASH_TOTP_SECRET || (existsSync(secretFile) ? readFileSync(secretFile, 'utf8').trim() : '');

  const ipOf = req => (trustProxy && (req.headers['x-real-ip'] || String(req.headers['x-forwarded-for'] || '').split(',')[0].trim())) || req.socket.remoteAddress;
  const cookies = req => Object.fromEntries(String(req.headers.cookie || '').split(';').map(c => c.trim().split('=')).filter(p => p[0]));
  const cookieStr = (name, val, age) => `${name}=${val}; Path=/; HttpOnly; SameSite=Strict; Max-Age=${age}${secure ? '; Secure' : ''}${pvDomain ? `; Domain=${pvDomain}` : ''}`;
  // Claude Code 요금제 사용량(/usage 와 같은 값). 토큰은 Claude Code 가 갱신하는 credentials 파일에서 매번 읽는다.
  // 화면에는 이름 · 사용률 · 초기화 시각만 보낸다. 1분 캐시.
  let usageCache = { at: 0, v: { limits: [] } };
  const usage = async () => {
    if (Date.now() - usageCache.at < 60000) return usageCache.v;
    let v = { limits: [] };
    try {
      const tok = JSON.parse(readFileSync(join(homedir(), '.claude/.credentials.json'), 'utf8')).claudeAiOauth.accessToken;
      const r = await fetch('https://api.anthropic.com/api/oauth/usage', { headers: { Authorization: `Bearer ${tok}`, 'anthropic-beta': 'oauth-2025-04-20' }, signal: AbortSignal.timeout(8000) });
      if (r.ok) v = { limits: usageLimits(await r.json()) };
    } catch {}
    usageCache = { at: Date.now(), v };
    return v;
  };
  const authed = req => {
    const t = cookies(req).dash_sid, exp = t && sessions.get(t);
    if (!exp) return false;
    if (exp < Date.now()) { sessions.delete(t); return false; }
    return true;
  };
  const pendingOf = req => {
    const t = cookies(req).dash_pre, p = t && pending.get(t);
    if (!p) return null;
    if (p.exp < Date.now()) { pending.delete(t); return null; }
    return { t, p };
  };
  const blocked = ip => { const f = fails.get(ip); if (!f) return false; if (Date.now() - f.first > FAIL_WINDOW) { fails.delete(ip); return false; } return f.n >= MAX_FAILS; };
  const fail = ip => { const f = fails.get(ip); if (!f || Date.now() - f.first > FAIL_WINDOW) fails.set(ip, { n: 1, first: Date.now() }); else f.n++; };
  // 다른 사이트에서 보낸 POST 차단
  const hostOf = req => (trustProxy && req.headers['x-forwarded-host']) || req.headers.host;
  const sameOrigin = req => {
    const o = req.headers.origin; if (!o) return true;
    const host = hostOf(req);
    try { return new URL(o).host === host; } catch { return false; }
  };
  const send = (res, code, body = '', headers = {}) => {
    res.writeHead(code, { 'X-Frame-Options': 'DENY', 'X-Content-Type-Options': 'nosniff', 'Referrer-Policy': 'same-origin', 'Cache-Control': 'no-store', ...headers });
    res.end(body);
  };
  const go = (res, to, headers = {}) => send(res, 303, '', { Location: to, ...headers });
  const file = name => { const p = join(ROOT, name); return existsSync(p) ? readFileSync(p) : null; };
  const esc = s => String(s).replace(/[&<>"']/g, c => ({ '&': '&amp;', '<': '&lt;', '>': '&gt;', '"': '&quot;', "'": '&#39;' }[c]));
  const page = (res, mode, extra = {}) => {
    const vars = { MODE: mode, BRAND, SECRET: '', URI: '', ...extra };
    const html = String(file('login.html')).replace(/\{\{(\w+)\}\}/g, (_, k) => esc(vars[k] ?? ''));
    return send(res, 200, html, { 'Content-Type': 'text/html; charset=utf-8' });
  };
  const readBody = req => new Promise((ok, no) => {
    let b = ''; req.on('data', c => { b += c; if (b.length > 4096) { no(new Error('too large')); req.destroy(); } });
    req.on('end', () => ok(new URLSearchParams(b))); req.on('error', no);
  });
  const slow = () => new Promise(r => setTimeout(r, 400)); // 무차별 대입 속도 늦추기
  const startSession = (res, req, preToken) => {
    if (preToken) pending.delete(preToken);
    fails.delete(ipOf(req));
    const t = randomBytes(32).toString('hex');
    sessions.set(t, Date.now() + SESSION_TTL * 1000);
    console.log(`[login] 성공 ip=${ipOf(req)}`);
    res.setHeader('Set-Cookie', [cookieStr('dash_sid', t, SESSION_TTL), cookieStr('dash_pre', '', 0)]);
    return go(res, '/');
  };
  // OTP 단계 공통 실패 처리: IP 카운트 + 이 토큰 시도 5번 넘으면 비밀번호부터 다시
  const otpFail = async (res, req, pre, back) => {
    fail(ipOf(req)); pre.p.tries++;
    console.log(`[login] OTP 실패 ip=${ipOf(req)}`);
    await slow();
    if (blocked(ipOf(req)) || pre.p.tries >= MAX_FAILS) { pending.delete(pre.t); return go(res, '/login?e=' + (blocked(ipOf(req)) ? 'locked' : 'retry'), { 'Set-Cookie': cookieStr('dash_pre', '', 0) }); }
    return go(res, back + '?e=1');
  };

  const startPreview = async name => {
    const p = previews().find(x => x.name === name);
    if (!p || !p.dir || !p.cmd) throw new Error('모르는 미리보기');
    if (await isUp(p.port)) return;
    const ses = `preview-${p.name}`;
    try { await tmux('has-session', '-t', ses); throw new Error('켜는 중이에요. 잠시 뒤 다시 확인하세요'); } catch (e) { if (e.message.startsWith('켜는')) throw e; }
    await tmux('new-session', '-d', '-s', ses, '-c', p.dir, 'bash', '-lc', p.cmd);
    console.log(`[preview] ${p.name} 켜기`);
  };
  // 새 세션: 홈 아래 있는 폴더에서만, 정해진 모델로만 Claude Code 를 띄운다.
  const home = homedir();
  const startClaude = async ({ name, dir, model }) => {
    if (!/^[a-z0-9][a-z0-9-]{0,30}$/.test(name || '') || /^(preview-|dashboard$)/.test(name)) throw new Error('이름은 영문 소문자 · 숫자 · - 만 (preview-, dashboard 제외)');
    if (!MODELS.includes(model)) throw new Error('고를 수 없는 모델');
    let real;
    try { real = realpathSync(String(dir || '')); } catch { throw new Error('없는 폴더'); }
    if (!(real === home || real.startsWith(home + '/')) || !statSync(real).isDirectory()) throw new Error('홈 폴더 아래 폴더만 가능');
    try { await tmux('has-session', '-t', '=' + name); } catch { await tmux('new-session', '-d', '-s', name, '-c', real, 'bash', '-lc', `exec claude --model ${model}`); console.log(`[session] ${name} 시작 ${real} ${model}`); return; }
    throw new Error('같은 이름의 세션이 이미 있어요');
  };
  const sessionDirs = () => {
    const sub = d => { try { return readdirSync(d, { withFileTypes: true }).filter(e => e.isDirectory() && !e.name.startsWith('.')).map(e => join(d, e.name)); } catch { return []; } };
    const pr = join(home, 'project');
    return [...new Set([...sub(pr), ...(cfg.LEAD_DIR ? sub(join(pr, cfg.LEAD_DIR)) : []), ...sub(home).filter(d => d !== pr)])].sort();
  };
  const srv = http.createServer(async (req, res) => {
    const path = new URL(req.url, 'http://x').pathname;
    const isGet = req.method === 'GET' || req.method === 'HEAD';
    const pv = previewOf(hostOf(req), pvDomain, previews());
    if (pv) return authed(req) ? proxy(req, res, pv, `${scheme}://${pvDomain}`) : go(res, `${scheme}://${pvDomain}/login`);
    try {
      if (path === '/healthz') return send(res, 200, 'ok');
      if (path === '/hook' && req.method === 'POST') {
        if (!loopback(req) || !same(req.headers['x-hook-token'] || '', hookTok)) return send(res, 403, 'forbidden');
        try { store.ingest(JSON.parse(await readRaw(req, 2_000_000)), String(req.headers['x-tmux-pane'] || '')); } catch (e) { console.error('[hook]', e.message); }
        return send(res, 204);
      }
      if (isGet && PUBLIC[path]) { const b = file(PUBLIC[path]); return b ? send(res, 200, b, { 'Content-Type': 'image/png', 'Cache-Control': 'public, max-age=86400' }) : send(res, 404, 'not found'); }
      if (req.method === 'POST' && !sameOrigin(req)) return send(res, 403, 'forbidden');

      // 1단계: 아이디·비밀번호
      if (path === '/login' && isGet) return authed(req) ? go(res, '/') : page(res, 'password');
      if (path === '/login' && req.method === 'POST') {
        const ip = ipOf(req);
        if (blocked(ip)) return go(res, '/login?e=locked');
        const p = await readBody(req);
        const ok = same(p.get('user') || '', cfg.DASH_USER) & same(p.get('password') || '', cfg.DASH_PASSWORD);
        if (!ok) { fail(ip); console.log(`[login] 실패 ip=${ip}`); await slow(); return go(res, blocked(ip) ? '/login?e=locked' : '/login?e=1'); }
        const t = randomBytes(32).toString('hex');
        const enrolled = !!getSecret();
        pending.set(t, { exp: Date.now() + PENDING_TTL, tries: 0, secret: enrolled ? null : b32encode(randomBytes(20)) });
        return go(res, enrolled ? '/login/otp' : '/login/setup', { 'Set-Cookie': cookieStr('dash_pre', t, PENDING_TTL / 1000) });
      }

      // 2단계: OTP 코드
      if (path === '/login/otp') {
        const pre = pendingOf(req);
        if (!pre || !getSecret()) return go(res, '/login');
        if (isGet) return page(res, 'otp');
        if (req.method === 'POST') {
          if (blocked(ipOf(req))) return go(res, '/login?e=locked');
          const k = verifyTotp(getSecret(), ((await readBody(req)).get('code') || '').trim(), Date.now(), lastUsed);
          if (k < 0) return otpFail(res, req, pre, '/login/otp');
          lastUsed = k;
          return startSession(res, req, pre.t);
        }
      }

      // 최초 1회: QR 등록 (등록된 시크릿이 없을 때만)
      if (path === '/login/setup') {
        const pre = pendingOf(req);
        if (getSecret()) return go(res, pre ? '/login/otp' : '/login');
        if (!pre || !pre.p.secret) return go(res, '/login');
        const s = pre.p.secret;
        if (isGet) return page(res, 'setup', { SECRET: s.replace(/(.{4})/g, '$1 ').trim(), URI: `otpauth://totp/${encodeURIComponent(BRAND + ':' + cfg.DASH_USER)}?secret=${s}&issuer=${encodeURIComponent(BRAND)}&algorithm=SHA1&digits=6&period=30` });
        if (req.method === 'POST') {
          if (blocked(ipOf(req))) return go(res, '/login?e=locked');
          const k = verifyTotp(s, ((await readBody(req)).get('code') || '').trim());
          if (k < 0) return otpFail(res, req, pre, '/login/setup');
          writeFileSync(secretFile, s + '\n', { mode: 0o600 });
          lastUsed = k;
          console.log('[login] OTP 등록 완료');
          return startSession(res, req, pre.t);
        }
      }

      if (path === '/logout' && req.method === 'POST') {
        sessions.delete(cookies(req).dash_sid);
        return go(res, '/login', { 'Set-Cookie': cookieStr('dash_sid', '', 0) });
      }

      if (!authed(req)) return isGet && path === '/' ? go(res, '/login') : send(res, 401, 'login required');

      if (path === '/api/dirs' && isGet) return send(res, 200, JSON.stringify({ dirs: sessionDirs(), models: MODELS }), { 'Content-Type': 'application/json' });
      if (path === '/api/config' && isGet) return send(res, 200, JSON.stringify(uiConfig(cfg)), { 'Content-Type': 'application/json' });
      if (path === '/api/sys' && isGet) return send(res, 200, JSON.stringify(await sysStats()), { 'Content-Type': 'application/json', 'Cache-Control': 'no-store' });
      if (path === '/api/usage' && isGet) return send(res, 200, JSON.stringify(await usage()), { 'Content-Type': 'application/json' });
      if (path === '/api/previews' && isGet) {
        const list = await Promise.all(previews().map(async p => ({ name: p.name, url: `${scheme}://${p.name}.${pvDomain}/`, up: await isUp(p.port) })));
        return send(res, 200, JSON.stringify(pvDomain ? list : []), { 'Content-Type': 'application/json' });
      }
      if (path === '/api/state' && isGet) return send(res, 200, JSON.stringify(store.snapshot()), { 'Content-Type': 'application/json' });
      if (path === '/events' && isGet) {
        res.writeHead(200, { 'Content-Type': 'text/event-stream', 'Cache-Control': 'no-store', 'X-Accel-Buffering': 'no', 'X-Content-Type-Options': 'nosniff' });
        res.write(`data: ${JSON.stringify(store.snapshot())}\n\n`);
        clients.add(res);
        const hb = setInterval(() => res.write(': ping\n\n'), 25000);
        req.on('close', () => { clients.delete(res); clearInterval(hb); });
        return;
      }
      // 붙여넣기 · 끌어놓기 파일 → 서버에 저장하고 경로를 돌려준다. 그 경로를 지시에 넣으면 Claude 가 읽는다.
      // ponytail: 오래된 파일은 지우지 않는다. 쌓이면 uploads 폴더를 비운다.
      if (path === '/api/upload' && req.method === 'POST') {
        const buf = await readBuf(req, 20 << 20);
        if (!buf.length) return send(res, 400, 'empty');
        const name = decodeURIComponent(String(req.headers['x-file-name'] || 'file')).replace(/[^\w.\-가-힣]/g, '_').replace(/^\.+/, '').slice(-80) || 'file';
        mkdirSync(upDir, { recursive: true, mode: 0o700 });
        const f = join(upDir, `${new Date().toISOString().replace(/\D/g, '').slice(0, 14)}-${randomBytes(3).toString('hex')}-${name}`);
        writeFileSync(f, buf, { mode: 0o600 });
        console.log(`[api] /api/upload ${buf.length}B ip=${ipOf(req)}`);
        return send(res, 200, JSON.stringify({ path: f }), { 'Content-Type': 'application/json' });
      }
      if (path.startsWith('/api/') && req.method === 'POST') {
        if (!String(req.headers['content-type'] || '').startsWith('application/json')) return send(res, 415, 'json only');
        const b = JSON.parse((await readRaw(req, 20000)) || '{}');
        try {
          if (path === '/api/send') await store.send(b.session, b.text);
          else if (path === '/api/approve') await store.approve(b.session, b.choice, b.reason);
          else if (path === '/api/stop') await store.stop(b.session);
          else if (path === '/api/preview') await startPreview(b.name);
          else if (path === '/api/model') await store.setModel(b.session, b.model);
          else if (path === '/api/session') await startClaude(b);
          else return send(res, 404, 'not found');
          console.log(`[api] ${path} ip=${ipOf(req)}`);
          return send(res, 200, '{"ok":true}', { 'Content-Type': 'application/json' });
        } catch (e) { return send(res, 409, JSON.stringify({ error: e.message }), { 'Content-Type': 'application/json' }); }
      }

      const s = isGet && PRIVATE[path];
      const body = s && file(s[0]);
      if (!body) return send(res, 404, 'not found');
      return send(res, 200, body, { 'Content-Type': s[1] });
    } catch (e) {
      console.error('[error]', e.message);
      return send(res, 400, 'bad request');
    }
  });
  // HMR 웹소켓도 로그인한 사람만 개발 서버로 넘긴다
  srv.on('upgrade', (req, socket, head) => {
    const pv = previewOf(hostOf(req), pvDomain, previews());
    if (!pv || !authed(req)) return socket.destroy();
    proxyUpgrade(req, socket, head, pv);
  });
  return srv;
}

// 서버 상태: CPU(직전 호출과의 차이), 메모리(MemAvailable 기준), NVIDIA GPU(nvidia-smi 가 있을 때만)
let cpuPrev = null;
const cpuTimes = () => cpus().reduce((a, c) => { const t = c.times; a.idle += t.idle; a.all += t.user + t.nice + t.sys + t.idle + t.irq; return a; }, { idle: 0, all: 0 });
export function cpuPercent(prev, cur) {
  const all = cur.all - prev.all;
  return all > 0 ? Math.round((1 - (cur.idle - prev.idle) / all) * 100) : 0;
}
// /proc/meminfo 의 MemAvailable 이 실제로 쓸 수 있는 양(캐시 제외). 없으면 os.freemem
export function memInfo(text) {
  const kb = k => +((String(text || '').match(new RegExp(`^${k}:\\s+(\\d+)`, 'm')) || [])[1] || 0) * 1024;
  const total = kb('MemTotal') || totalmem(), avail = kb('MemAvailable') || freemem();
  return { used: total - avail, total };
}
const gpuInfo = () => new Promise(ok => execFile('nvidia-smi', ['--query-gpu=name,utilization.gpu,memory.used,memory.total,temperature.gpu', '--format=csv,noheader,nounits'], { timeout: 2000 }, (e, out) => {
  if (e) return ok(null);
  const [name, util, used, total, temp] = String(out).split('\n')[0].split(',').map(s => s.trim());
  ok(name ? { name, util: +util, used: +used * 1048576, total: +total * 1048576, temp: +temp } : null);
}));
async function sysStats() {
  const cur = cpuTimes(), cpu = cpuPrev ? cpuPercent(cpuPrev, cur) : null;
  cpuPrev = cur;
  let mi = ''; try { mi = readFileSync('/proc/meminfo', 'utf8'); } catch {}
  return { cpu, cores: cpus().length, mem: memInfo(mi), gpu: await gpuInfo() };
}
// .env → 화면 설정: LEAD_DIR=총괄 폴더 이름, AGENT_NICKNAMES=type:별칭,..., READONLY_AGENTS=type,..., SERVER_NAME=화면의 서버 이름
export function uiConfig(cfg) {
  const list = v => String(v || '').split(',').map(x => x.trim()).filter(Boolean);
  const nick = Object.fromEntries(list(cfg.AGENT_NICKNAMES).map(x => x.split(':').map(y => y.trim())).filter(([k, v]) => k && v));
  return { lead: String(cfg.LEAD_DIR || '').trim(), nick, ro: list(cfg.READONLY_AGENTS), name: String(cfg.SERVER_NAME || '').trim() };
}
// /api/oauth/usage 응답 → [{label, used, resets_at}]
export function usageLimits(u) {
  const name = l => (l.group === 'weekly' ? '주간' : '5시간') + (l.scope?.model?.display_name ? ' · ' + l.scope.model.display_name : '');
  if (Array.isArray(u.limits) && u.limits.length) return u.limits.map(l => ({ label: name(l), used: l.percent, resets_at: l.resets_at }));
  return [['5시간', u.five_hour], ['주간', u.seven_day]].filter(([, x]) => x).map(([label, x]) => ({ label, used: x.utilization, resets_at: x.resets_at }));
}
if (process.argv[1] === fileURLToPath(import.meta.url)) {
  const cfg = { ...loadEnv(join(ROOT, '.env')), ...process.env };
  if (!cfg.DASH_USER || !cfg.DASH_PASSWORD) { console.error('.env 에 DASH_USER, DASH_PASSWORD 를 넣어 주세요 (.env.example 참고)'); process.exit(1); }
  if (cfg.DASH_PASSWORD.length < 12) { console.error('DASH_PASSWORD 는 12자 이상이어야 합니다'); process.exit(1); }
  const port = +(cfg.PORT || 4545), host = cfg.HOST || '127.0.0.1';
  createApp(cfg).listen(port, host, () => console.log(`jeff-agents → http://${host}:${port}`));
}
