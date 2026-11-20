// 개발 서버 미리보기 — <이름>.<PREVIEW_DOMAIN> 으로 온 요청을 이 서버 127.0.0.1:<포트> 개발 서버로 넘긴다.
import http from 'node:http';
import net from 'node:net';
import { readFileSync } from 'node:fs';

// previews.json: [{ "name": "web", "port": 5254, "dir": "/절대/경로", "cmd": "corepack pnpm dev" }]
export function loadPreviews(file) {
  try {
    return JSON.parse(readFileSync(file, 'utf8'))
      .filter(p => /^[a-z0-9-]+$/.test(p.name) && Number.isInteger(p.port) && p.port > 0 && p.port < 65536);
  } catch { return []; }
}
// 요청 Host 가 미리보기 주소면 그 항목
export function previewOf(host, domain, list) {
  if (!domain || !host) return null;
  const h = String(host).toLowerCase().replace(/:\d+$/, ''), suf = '.' + domain.toLowerCase();
  return h.endsWith(suf) ? list.find(p => p.name === h.slice(0, -suf.length)) || null : null;
}
// 개발 서버로 넘길 헤더: Host·Origin 은 localhost 로(webpack-dev-server 의 Host 검사), 대시보드 쿠키는 뺀다
export function upstreamHeaders(h, port) {
  const out = { ...h, host: `localhost:${port}` };
  if (out.origin) out.origin = `http://localhost:${port}`;
  const c = String(out.cookie || '').split(';').map(s => s.trim()).filter(s => s && !/^dash_(sid|pre)=/.test(s)).join('; ');
  if (c) out.cookie = c; else delete out.cookie;
  delete out['x-forwarded-host'];
  return out;
}
export function proxy(req, res, p, parent) {
  const up = http.request({ host: '127.0.0.1', port: p.port, method: req.method, path: req.url, headers: upstreamHeaders(req.headers, p.port) }, r => {
    const h = { ...r.headers };
    delete h['x-frame-options'];
    h['content-security-policy'] = `frame-ancestors ${parent}`; // 대시보드 안 iframe 으로만 띄울 수 있게
    res.writeHead(r.statusCode, h);
    r.pipe(res);
  });
  up.on('error', () => {
    if (res.headersSent) return res.destroy();
    res.writeHead(502, { 'Content-Type': 'text/html; charset=utf-8', 'Cache-Control': 'no-store' });
    res.end(`<p style="font:16px sans-serif;padding:40px">${p.name} 개발 서버가 꺼져 있어요. 대시보드의 「화면 확인」에서 켜 주세요.</p>`);
  });
  req.pipe(up);
}
// HMR 웹소켓
export function proxyUpgrade(req, socket, head, p) {
  const up = net.connect(p.port, '127.0.0.1', () => {
    const h = upstreamHeaders(req.headers, p.port);
    up.write(`${req.method} ${req.url} HTTP/1.1\r\n${Object.entries(h).map(([k, v]) => `${k}: ${v}`).join('\r\n')}\r\n\r\n`);
    if (head?.length) up.write(head);
    up.pipe(socket); socket.pipe(up);
  });
  up.on('error', () => socket.destroy());
  socket.on('error', () => up.destroy());
}
export const isUp = port => new Promise(ok => {
  const s = net.connect(port, '127.0.0.1');
  s.setTimeout(800);
  s.on('connect', () => { s.destroy(); ok(true); });
  s.on('error', () => ok(false));
  s.on('timeout', () => { s.destroy(); ok(false); });
});
