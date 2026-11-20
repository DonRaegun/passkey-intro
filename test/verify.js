// 소프트웨어 인증기로 등록·로그인·차단 4종을 자동 확인하고 기록을 출력한다. 사용: node test/verify.js <서버주소>
const crypto = require('crypto');
const BASE = process.argv[2] || 'http://localhost:3100';
const ORIGIN = BASE, RPID = new URL(BASE).hostname;
const b64 = (b) => Buffer.from(b).toString('base64url');
const sha = (b) => crypto.createHash('sha256').update(b).digest();

// --- 최소 CBOR (맵·바이트·문자열·정수) ---
function cbor(v) {
  const head = (mt, n) => n < 24 ? Buffer.from([mt << 5 | n]) : n < 256 ? Buffer.from([mt << 5 | 24, n]) : Buffer.from([mt << 5 | 25, n >> 8, n & 255]);
  if (Buffer.isBuffer(v)) return Buffer.concat([head(2, v.length), v]);
  if (typeof v === 'string') { const b = Buffer.from(v); return Buffer.concat([head(3, b.length), b]); }
  if (typeof v === 'number') return v >= 0 ? head(0, v) : head(1, -1 - v);
  const e = v instanceof Map ? [...v] : Object.entries(v);
  return Buffer.concat([head(5, e.length), ...e.flatMap(([k, x]) => [cbor(k), cbor(x)])]);
}
class Authenticator { // 개인키는 이 객체 안에만 있고 서버로 나가지 않는다
  constructor() { this.keys = new Map(); this.counter = 0; }
  register(opts) {
    const { publicKey, privateKey } = crypto.generateKeyPairSync('ec', { namedCurve: 'P-256' });
    const jwk = publicKey.export({ format: 'jwk' });
    const credId = crypto.randomBytes(32);
    this.keys.set(b64(credId), privateKey);
    const cose = cbor(new Map([[1, 2], [3, -7], [-1, 1], [-2, Buffer.from(jwk.x, 'base64url')], [-3, Buffer.from(jwk.y, 'base64url')]]));
    const len = Buffer.alloc(2); len.writeUInt16BE(credId.length);
    const authData = Buffer.concat([sha(RPID), Buffer.from([0x45]), Buffer.alloc(4), Buffer.alloc(16), len, credId, cose]);
    const clientData = Buffer.from(JSON.stringify({ type: 'webauthn.create', challenge: opts.challenge, origin: ORIGIN }));
    return { id: b64(credId), rawId: b64(credId), type: 'public-key', clientExtensionResults: {},
      response: { clientDataJSON: b64(clientData), attestationObject: b64(cbor({ fmt: 'none', attStmt: {}, authData })), transports: ['internal'] } };
  }
  sign(opts, credIdB64, tamper) {
    const key = this.keys.get(credIdB64);
    const c = Buffer.alloc(4); c.writeUInt32BE(++this.counter);
    const authData = Buffer.concat([sha(RPID), Buffer.from([0x05]), c]);
    const clientData = Buffer.from(JSON.stringify({ type: 'webauthn.get', challenge: opts.challenge, origin: ORIGIN }));
    let sig = crypto.sign('sha256', Buffer.concat([authData, sha(clientData)]), key);
    if (tamper) sig = crypto.sign('sha256', Buffer.from('forged'), key); // 다른 내용에 서명 = 위조
    return { id: credIdB64, rawId: credIdB64, type: 'public-key', clientExtensionResults: {},
      response: { clientDataJSON: b64(clientData), authenticatorData: b64(authData), signature: b64(sig) } };
  }
}

// --- 쿠키 보관 클라이언트 ---
class Client {
  constructor(name) { this.name = name; this.jar = {}; }
  async call(method, path, body, show = true) {
    const headers = { 'Content-Type': 'application/json', Cookie: Object.entries(this.jar).map(([k, v]) => `${k}=${v}`).join('; ') };
    const r = await fetch(BASE + path, { method, headers, body: body && JSON.stringify(body) });
    for (const sc of r.headers.getSetCookie()) { const [kv] = sc.split(';'); const i = kv.indexOf('='); this.jar[kv.slice(0, i)] = kv.slice(i + 1); }
    const text = await r.text(); let j; try { j = JSON.parse(text); } catch { j = text; }
    if (show) console.log(`  [${this.name}] ${method} ${path}${body ? ' body=' + mask(JSON.stringify(body)).slice(0, 140) : ''}\n      -> ${r.status} ${mask(JSON.stringify(j)).slice(0, 220)}`);
    return { status: r.status, json: j };
  }
  sid() { return this.jar.sid; }
}
const mask = (s) => s.replace(/("(?:sid|signature|attestationObject|authenticatorData|clientDataJSON)":")[^"]{6,}/g, '$1***가려짐***');
const h = (t) => console.log('\n=== ' + t + ' ===');
const ok = (c, m) => { console.log((c ? '  ✔ ' : '  ✘ ') + m); if (!c) process.exitCode = 1; };

async function registerAcct(cl, auth, username, label) {
  const o = (await cl.call('POST', '/api/register/options', { username })).json;
  const resp = auth.register(o);
  console.log(`  챌린지=${o.challenge.slice(0, 12)}…  (요청 본문에는 공개키가 든 attestationObject만 있고 개인키 필드 없음)`);
  const v = await cl.call('POST', '/api/register/verify', { response: resp, name: label });
  return { credId: resp.id, challenge: o.challenge, status: v.status };
}
async function loginWith(cl, auth, credId, tamper) {
  const o = (await cl.call('POST', '/api/login/options')).json;
  const resp = auth.sign(o, credId, tamper);
  const v = await cl.call('POST', '/api/login/verify', { response: resp });
  return { o, resp, v };
}

(async () => {
  const authA = new Authenticator(), authB = new Authenticator();
  const A = new Client('계정A'), B = new Client('계정B'), anon = new Client('로그인없음');

  h('0. 로그인 없이 비공개 자료 직접 요청 (T08-C16/C17)');
  const r0 = await anon.call('GET', '/api/private'); ok(r0.status === 401, '401로 거절');
  const page = await (await fetch(BASE + '/')).text();
  ok(!/\[가상\]/.test(page) && !/프로젝트 메모/.test(page), '로그인 전 받은 페이지 소스에 비공개 내용 없음');

  h('1. 계정 두 개 + 패스키 등록 (C19~C21, C36)');
  const a1 = await registerAcct(A, authA, '계정A', 'A의 첫 패스키');
  const b1 = await registerAcct(B, authB, '계정B', 'B의 첫 패스키');
  ok(a1.status === 200 && b1.status === 200, '두 계정 등록 성공');
  ok(a1.challenge !== b1.challenge, `등록 챌린지가 서로 다름: ${a1.challenge.slice(0, 10)}… ≠ ${b1.challenge.slice(0, 10)}…`);

  h('2. 로그인: 성공 vs 서명 위조 실패, 챌린지 재사용 (C27~C31)');
  const good = await loginWith(anon, authA, a1.credId, false);
  ok(good.v.status === 200, '정상 서명 → 200');
  const bad = await loginWith(new Client('위조'), authA, a1.credId, true);
  ok(bad.v.status === 401, '위조 서명 → 401');
  const o2 = (await anon.call('POST', '/api/login/options', null, false)).json;
  ok(o2.challenge !== good.o.challenge, '로그인 챌린지도 매번 다름');
  console.log('  -- 이미 사용한 챌린지로 같은 응답을 다시 제출');
  const replayClient = new Client('재사용');
  const o3 = (await replayClient.call('POST', '/api/login/options', null, false)).json;
  const resp3 = authA.sign(o3, a1.credId);
  const first = await replayClient.call('POST', '/api/login/verify', { response: resp3 });
  replayClient.jar.sid = undefined; delete replayClient.jar.sid;
  const second = await replayClient.call('POST', '/api/login/verify', { response: resp3 });
  ok(first.status === 200 && second.status === 400, '첫 제출 200, 재제출 400(거절)');

  h('3. 취소하면 서버에 아무것도 저장되지 않음 (C25)');
  const C = new Client('취소');
  await C.call('POST', '/api/register/options', { username: '취소계정' }); // 인증기 단계에서 취소 → verify 호출 없음
  const lg = await (async () => { const o = (await C.call('POST', '/api/register/options', { username: '취소계정' }, false)); return o.status; })();
  ok(lg === 200, '같은 이름으로 다시 등록 시도 가능 = 서버에 계정이 만들어지지 않았음');

  h('4. 두 번째 패스키 등록, 삭제, 삭제한 패스키로 로그인 (C42~C46)');
  await loginWith(A, authA, a1.credId); // A 세션 확보
  const authA2 = new Authenticator();
  const o4 = (await A.call('POST', '/api/register/options', {})).json;
  const resp4 = authA2.register(o4);
  await A.call('POST', '/api/register/verify', { response: resp4, name: 'A의 두번째 패스키' });
  const list = (await A.call('GET', '/api/passkeys')).json; ok(list.length === 2, `패스키 2개 목록: ${list.map((x) => x.name + ' ' + x.createdAt.slice(0, 10)).join(', ')}`);
  await A.call('DELETE', '/api/passkeys/' + encodeURIComponent(a1.credId));
  const afterDel = await loginWith(new Client('삭제후-남은키'), authA2, resp4.id); ok(afterDel.v.status === 200, '남은 패스키로 로그인 200');
  const deleted = await loginWith(new Client('삭제후-지운키'), authA, a1.credId); ok(deleted.v.status === 401, '지운 패스키로 로그인 401');
  const last = await A.call('DELETE', '/api/passkeys/' + encodeURIComponent(resp4.id)); ok(last.status === 409, '마지막 하나는 삭제 거절 409');

  h('5. 계정 간 접근 차단 (C37~C40)');
  const A2 = new Client('계정A'); await loginWith(A2, authA2, resp4.id);
  const B2 = new Client('계정B'); await loginWith(B2, authB, b1.credId);
  const aItems = (await A2.call('GET', '/api/private', null, false)).json, bItems = (await B2.call('GET', '/api/private', null, false)).json;
  console.log(`  거절 전: A 자료 ${aItems.items.length}건, B 자료 ${bItems.items.length}건 (서로 다른 내용: ${aItems.items[0] !== bItems.items[0]})`);
  const x1 = await A2.call('GET', '/api/users/계정B/private'); ok(x1.status === 403, 'A→B 요청 403');
  const x2 = await B2.call('GET', '/api/users/계정A/private'); ok(x2.status === 403, 'B→A 요청 403');
  const aAfter = (await A2.call('GET', '/api/private', null, false)).json, bAfter = (await B2.call('GET', '/api/private', null, false)).json;
  ok(aAfter.items.length === aItems.items.length && bAfter.items.length === bItems.items.length, `거절 뒤에도 건수 동일: A ${aAfter.items.length}, B ${bAfter.items.length}`);
  const sp = await A2.call('GET', '/api/private?account=계정B&owner=계정B'); ok(sp.json.owner === '계정A', '쿼리에 계정B를 써도 계정A 자료만 반환');

  h('6. 로그아웃 후 같은 세션 값 재사용 (C33)');
  const oldSid = A2.sid();
  await A2.call('POST', '/api/logout');
  const re = new Client('로그아웃후'); re.jar.sid = oldSid;
  const r6 = await re.call('GET', '/api/private'); ok(r6.status === 401, '로그아웃 전 쓰던 sid로 요청 → 401');
  console.log('\n(세션·서명 값은 위 기록에서 ***가려짐*** 처리됨)');
})();
