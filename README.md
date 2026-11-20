# jeff-agents

여러 Claude Code 세션(총괄 1개 + 저장소별 에이전트)을 브라우저 한 화면에서 보고, 지시하고, 승인하는 대시보드.

## 지금 상태

- `index.html` — 화면 샘플. 데이터는 예시이고 실제 세션과는 아직 연결되지 않았다.
- `server.mjs` — 로그인한 사용자에게만 화면을 내주는 서버(외부 패키지 없음, Node 20+).

## 실행

```bash
cp .env.example .env && chmod 600 .env   # DASH_USER, DASH_PASSWORD(12자 이상) 채우기
npm start                                # → http://127.0.0.1:4545 (계속 켜 두기: tmux new -d -s dashboard ./bin/run.sh)
npm test                                 # 로그인 잠금 확인
```

- 로그인은 아이디·비밀번호 다음 Google OTP 6자리(30초, 앞뒤 1칸 허용). 첫 로그인 때 QR 로 한 번 등록한다(`.totp-secret`, git 제외).
- 비밀번호·OTP 합쳐 5번 실패하면 그 IP 는 15분 동안 막힌다. 세션은 12시간 유지되고 서버를 다시 켜면 모두 로그아웃된다.
- HTTPS 서브도메인 뒤에 둘 때는 `.env` 에 `COOKIE_SECURE=1`, `TRUST_PROXY=1`, `HOST=0.0.0.0` 을 넣는다.

## 화면

- **조직도 / 라이브 그리드** — `G` 로 전환. 그리드는 모든 세션의 실시간 로그를 동시에 보여 준다.
- **상태** — 작업 중(회전 테두리·이퀄라이저·경과 시간), 승인 필요, 응답 없음(60초 이상 출력 없음), 대기, 완료.
- **승인** — 위험도 표시, `1` 허용 · `2` 이 세션에서 항상 허용 · `Esc` 거절(이유 함께 전달).
- **명령 팔레트** — `⌘K` / `Ctrl+K`. `J`/`K` 세션 이동, `/` 검색.

## 내 프로젝트에 맞추기
각자 `.env` 에만 넣는다(저장소에는 올리지 않는다).
- `LEAD_DIR` — 총괄 세션을 띄우는 폴더 이름(`~/project/<이름>`). 이 폴더의 세션이 「총괄」로 보인다.
- `AGENT_NICKNAMES` — 서브에이전트 type 별 화면 이름. 예: `web:웹,api:백엔드`
- `READONLY_AGENTS` — 읽기 전용 표시를 붙일 서브에이전트 type. 예: `api`
- `SERVER_NAME` — 화면에 보이는 서버 이름. 비우면 `SERVER`
- 개발 서버 미리보기는 `previews.example.json` 을 `previews.json` 으로 복사해서 쓴다.
## 배경 이미지 · 파비콘

`bg.jpg`, `favicon-16.png`, `favicon-32.png`, `apple-touch-icon.png` 를 `index.html` 옆에 두면 쓴다. 저작권 문제로 저장소에는 넣지 않는다(`.gitignore`).
