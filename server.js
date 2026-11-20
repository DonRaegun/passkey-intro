// 패스키(WebAuthn) 인증 서버. 비밀번호 없음. 서버에는 공개키·자격증명ID 등 공개 메타데이터만 저장.
const express = require('express');
const cookieParser = require('cookie-parser');
const crypto = require('crypto');
const fs = require('fs');
const path = require('path');
const { generateRegistrationOptions, verifyRegistrationResponse,
  generateAuthenticationOptions, verifyAuthenticationResponse } = require('@simplewebauthn/server');

const PORT = process.env.PORT || 3000;
// 주소는 환경변수가 없으면 요청 헤더(프록시 뒤 https)에서 읽는다
const origin = (req) => process.env.ORIGIN || `${req.protocol}://${req.get('host')}`;
const rpId = (req) => process.env.RP_ID || new URL(origin(req)).hostname;
const DB_FILE = process.env.DB_FILE || path.join(__dirname, 'data.json');
const secure = (req) => origin(req).startsWith('https');

// ---- 저장소 (users: 계정 + 패스키 공개키 + 가상의 비공개 자료) ----
// DATABASE_URL(axhub PostgreSQL)이 있으면 한 행(JSONB)에 저장, 없으면 로컬 파일. 서버 폴더 파일은 재배포 때 사라지므로 배포에서는 DB 사용.
// shortcut: 전체를 한 행에 덮어씀(동시 쓰기 경합 무시), 사용자가 늘면 테이블 분리.
const pool = process.env.DATABASE_URL ? new (require('pg').Pool)({ connectionString: process.env.DATABASE_URL }) : null;
let db = { users: {} };
const save = () => pool
  ? pool.query(`INSERT INTO kv(k, v) VALUES('db', $1) ON CONFLICT (k) DO UPDATE SET v = $1`, [JSON.stringify(db)])
  : fs.writeFileSync(DB_FILE, JSON.stringify(db, null, 2));
async function load() {
  if (pool) {
    await pool.query('CREATE TABLE IF NOT EXISTS kv(k text PRIMARY KEY, v jsonb NOT NULL)');
    const r = await pool.query("SELECT v FROM kv WHERE k = 'db'");
    if (r.rows[0]) db = r.rows[0].v;
    for (const u of Object.values(db.users)) if (u.seed === undefined) u.seed = (u.private && u.private[0].includes('날씨 보드')) ? 0 : 1; // 이전 방식으로 만든 계정
  } else if (fs.existsSync(DB_FILE)) db = JSON.parse(fs.readFileSync(DB_FILE, 'utf8'));
}
const b64 = (u8) => Buffer.from(u8).toString('base64url');

// 모두 직접 지어낸 가상의 내용. 실제 개인정보 아님. (계정 순서대로 서로 다른 내용을 넣음)
const SEEDS = [
  ['[가상] 프로젝트 메모: 날씨 보드에 시간대별 강수 그래프 추가 예정', '[가상] 프로젝트 메모: 외부 날씨 API 호출이 실패하면 마지막 성공 값을 보여 주기', '[가상] 지원 예정: 가상기업 알파 · 서류 마감 6/12 · 상태: 자기소개서 초안', '[가상] 지원 예정: 가상기업 베타 · 서류 마감 6/20 · 상태: 포트폴리오 보완 중', '[가상] 회고(11/17): 이번 주는 인증 흐름을 말로 설명하는 연습이 부족했다', '[가상] 회고(11/19): 요청 기록을 표로 정리하니 "됐다"는 말이 줄었다'],
  ['[가상] 프로젝트 메모: 가계부 앱에 월별 카테고리 차트 붙이기', '[가상] 프로젝트 메모: 정산 막대는 원래 값과 정산을 뺀 값을 나란히 보여 주기', '[가상] 지원 예정: 가상기업 감마 · 서류 마감 6/15 · 상태: 직무 기술서 읽는 중', '[가상] 지원 예정: 가상기업 델타 · 서류 마감 6/22 · 상태: 지원 보류', '[가상] 지원 예정: 가상기업 엡실론 · 서류 마감 6/30 · 상태: 포트폴리오 5쪽 버전 제출 예정', '[가상] 회고(11/18): 에러 메시지를 먼저 읽는 습관이 생겼다', '[가상] 메모: 포트폴리오 PDF 5쪽 버전 다듬기'],
];
// 비공개 자료는 계정에 복사해 두지 않고 seed 번호로 가져온다 (내용을 고치면 기존 계정에도 반영)
const privateOf = (u) => SEEDS[u.seed];

// ---- 일회용 챌린지: 발급 시 서버에 보관, 검증 시 꺼내면서 즉시 삭제 ----
const challenges = new Map(); // cid -> {challenge, kind, userId, exp}
function issue(res, kind, challenge, userId) {
  const cid = crypto.randomBytes(16).toString('base64url');
  challenges.set(cid, { challenge, kind, userId, exp: Date.now() + 5 * 60e3 });
  res.cookie('cid', cid, { httpOnly: true, sameSite: 'strict', secure: secure(res.req), maxAge: 5 * 60e3 });
}
function take(req, kind) {
  const c = challenges.get(req.cookies.cid);
  challenges.delete(req.cookies.cid); // 성공·실패 상관없이 한 번 쓰면 폐기
  return c && c.kind === kind && c.exp > Date.now() ? c : null;
}

// ---- 세션: 서버 메모리의 랜덤 토큰, HttpOnly 쿠키 'sid' ----
const sessions = new Map(); // sid -> userId
function login(res, userId) {
  const sid = crypto.randomBytes(32).toString('base64url');
  sessions.set(sid, userId);
  res.cookie('sid', sid, { httpOnly: true, sameSite: 'strict', secure: secure(res.req), maxAge: 8 * 3600e3 });
}
function requireAuth(req, res, next) { // 비공개 자료의 단일 관문
  const uid = sessions.get(req.cookies.sid);
  if (!uid || !db.users[uid]) return res.status(401).json({ error: '패스키 로그인이 필요합니다' });
  req.user = db.users[uid];
  next();
}

// 안드로이드 일부 브라우저(삼성 인터넷 등)는 출처를 android:apk-key-hash:<43자>로 보낸다. 형식이 맞는 것만 추가로 허용.
// shortcut: 해시 값 자체는 고정 목록과 비교하지 않음, 허용할 앱을 좁히려면 ANDROID_ORIGINS 환경변수 목록으로 교체.
function origins(req, response) {
  const list = [origin(req)];
  try {
    const o = JSON.parse(Buffer.from(response.response.clientDataJSON, 'base64url').toString()).origin;
    if (/^android:apk-key-hash:[A-Za-z0-9_-]{43}$/.test(o)) list.push(o);
  } catch {}
  return list;
}

const app = express();
app.set('trust proxy', true);
app.use(express.json());
app.use(cookieParser());
app.use(express.static(path.join(__dirname, 'public')));
app.get('/lib/webauthn-browser.js', (_, res) =>
  res.sendFile(path.join(__dirname, 'node_modules/@simplewebauthn/browser/dist/bundle/index.umd.min.js')));

// ---------- 등록 ----------
const pendingNew = new Map(); // 검증 전 신규 계정: 디스크에 쓰지 않음(취소하면 아무것도 저장되지 않음)

app.post('/api/register/options', async (req, res) => {
  const sessionUser = sessions.get(req.cookies.sid);
  let user;
  if (sessionUser && db.users[sessionUser]) user = db.users[sessionUser]; // 로그인 상태: 내 계정에 패스키 추가
  else {
    const name = String(req.body.username || '').trim().slice(0, 20);
    if (!name) return res.status(400).json({ error: '계정 이름을 입력하세요' });
    if (Object.values(db.users).some((u) => u.name === name))
      return res.status(409).json({ error: '이미 있는 계정입니다. 기존 계정에 추가하려면 먼저 로그인하세요' });
    user = { id: crypto.randomUUID(), name, passkeys: [] };
    pendingNew.set(user.id, user);
  }
  const options = await generateRegistrationOptions({
    rpName: '공해성 소개', rpID: rpId(req), userName: user.name,
    userID: new TextEncoder().encode(user.id), attestationType: 'direct',
    excludeCredentials: user.passkeys.map((p) => ({ id: p.id, transports: p.transports })),
    authenticatorSelection: { residentKey: 'preferred', userVerification: 'preferred',
      ...(['platform', 'cross-platform'].includes(req.body.attachment) && { authenticatorAttachment: req.body.attachment }) },
  });
  issue(res, 'reg', options.challenge, user.id);
  res.json(options);
});

app.post('/api/register/verify', async (req, res) => {
  const c = take(req, 'reg');
  if (!c) return res.status(400).json({ error: '챌린지가 없거나 이미 사용되었습니다' });
  const user = db.users[c.userId] || pendingNew.get(c.userId);
  if (!user) return res.status(400).json({ error: '등록 요청을 찾을 수 없습니다' });
  try {
    const v = await verifyRegistrationResponse({ response: req.body.response, expectedChallenge: c.challenge,
      expectedOrigin: origins(req, req.body.response), expectedRPID: rpId(req) });
    if (!v.verified) throw new Error('검증 실패');
    const { credential } = v.registrationInfo;
    if (!db.users[user.id]) {
      const n = Object.keys(db.users).length;
      db.users[user.id] = { id: user.id, name: user.name, passkeys: [], seed: n % SEEDS.length };
      pendingNew.delete(user.id);
    }
    db.users[user.id].passkeys.push({
      id: credential.id, publicKey: b64(credential.publicKey), counter: credential.counter,
      transports: credential.transports, name: String(req.body.name || '이름 없는 패스키').slice(0, 30),
      createdAt: new Date().toISOString(),
    });
    await save();
    login(res, user.id);
    res.json({ ok: true });
  } catch (e) { res.status(400).json({ error: '등록 검증 실패: ' + e.message }); }
});

// ---------- 로그인 ----------
app.post('/api/login/options', async (req, res) => {
  const options = await generateAuthenticationOptions({ rpID: rpId(req), userVerification: 'preferred' });
  issue(res, 'auth', options.challenge);
  res.json(options);
});
app.post('/api/login/verify', async (req, res) => {
  const c = take(req, 'auth');
  if (!c) return res.status(400).json({ error: '챌린지가 없거나 이미 사용되었습니다' });
  const credId = req.body.response && req.body.response.id;
  const user = Object.values(db.users).find((u) => u.passkeys.some((p) => p.id === credId));
  if (!user) return res.status(401).json({ error: '등록되지 않았거나 삭제된 패스키입니다' });
  const pk = user.passkeys.find((p) => p.id === credId);
  try {
    const v = await verifyAuthenticationResponse({ response: req.body.response, expectedChallenge: c.challenge,
      expectedOrigin: origins(req, req.body.response), expectedRPID: rpId(req),
      credential: { id: pk.id, publicKey: Buffer.from(pk.publicKey, 'base64url'), counter: pk.counter, transports: pk.transports } });
    if (!v.verified) throw new Error('서명 불일치');
    pk.counter = v.authenticationInfo.newCounter; await save();
    login(res, user.id);
    res.json({ ok: true });
  } catch (e) { res.status(401).json({ error: '서명 검증 실패: ' + e.message }); }
});

app.post('/api/logout', (req, res) => { sessions.delete(req.cookies.sid); res.clearCookie('sid'); res.json({ ok: true }); });

// ---------- 비공개 영역 (모두 requireAuth 뒤) ----------
app.get('/api/me', requireAuth, (req, res) => res.json({ name: req.user.name }));
// 쿼리·본문에 다른 계정을 적어도 무시하고 세션 계정의 자료만 반환
app.get('/api/private', requireAuth, (req, res) => res.json({ owner: req.user.name, items: privateOf(req.user) }));
// 주소에 계정 이름을 쓰는 형태: 내 것이 아니면 403
app.get('/api/users/:name/private', requireAuth, (req, res) =>
  req.params.name === req.user.name ? res.json({ owner: req.user.name, items: privateOf(req.user) })
    : res.status(403).json({ error: '다른 계정의 자료입니다' }));
app.get('/api/passkeys', requireAuth, (req, res) =>
  res.json(req.user.passkeys.map(({ id, name, createdAt }) => ({ id, name, createdAt }))));
app.delete('/api/passkeys/:id', requireAuth, async (req, res) => {
  const ps = req.user.passkeys;
  if (!ps.some((p) => p.id === req.params.id)) return res.status(404).json({ error: '없는 패스키' });
  if (ps.length === 1) return res.status(409).json({ error: '마지막 패스키는 지울 수 없습니다 (지우면 로그인할 방법이 없어집니다)' });
  req.user.passkeys = ps.filter((p) => p.id !== req.params.id);
  await save(); res.json({ ok: true });
});

load().then(() => app.listen(PORT, () => console.log(`listening :${PORT} (${pool ? 'postgres' : 'file'})`)));
