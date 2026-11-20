// 가상 인증기(Chrome CDP)로 화면 전체 흐름을 시험한다. 사전 준비: npm i playwright-core / 사용: node test/e2e.js <주소> (서버는 새 DB로 띄울 것)
const { chromium } = require('playwright-core');
const BASE = process.argv[2] || 'http://localhost:3000';
const EXE = 'C:\\Program Files\\Google\\Chrome\\Application\\chrome.exe';
let fail = 0;
const ok = (c, m) => { console.log((c ? '  ✔ ' : '  ✘ ') + m); if (!c) fail++; };
const sleep = (ms) => new Promise((r) => setTimeout(r, ms));

async function newUser(browser, label) {
  const ctx = await browser.newContext({ viewport: { width: 900, height: 900 } });
  const page = await ctx.newPage();
  const errors = [];
  page.on('pageerror', (e) => errors.push(e.message));
  const cdp = await ctx.newCDPSession(page);
  await cdp.send('WebAuthn.enable');
  const addAuth = async (transport = 'internal') => (await cdp.send('WebAuthn.addVirtualAuthenticator', { options: { protocol: 'ctap2', transport, hasResidentKey: true, hasUserVerification: true, isUserVerified: true, automaticPresenceSimulation: true } })).authenticatorId;
  const setPresence = (id, on) => cdp.send('WebAuthn.setAutomaticPresenceSimulation', { authenticatorId: id, enabled: on });
  const setUV = (id, v) => cdp.send('WebAuthn.setUserVerified', { authenticatorId: id, isUserVerified: v });
  return { label, ctx, page, errors, addAuth, setPresence, setUV };
}
const msg = (p) => p.locator('#msg').innerText();
async function waitMsg(p, re, t = 8000) { const end = Date.now() + t; while (Date.now() < end) { const m = await msg(p); if (re.test(m)) return m; await sleep(150); } return await msg(p); }

(async () => {
  const browser = await chromium.launch({ executablePath: EXE, headless: true });
  const stamp = Date.now().toString(36).slice(-4);
  const nameA = 'e2eA' + stamp, nameB = 'e2eB' + stamp;

  console.log('\n=== 1. 페이지 로드: 스크립트 오류 없음, 버튼이 살아 있음 ===');
  const A = await newUser(browser, 'A');
  await A.page.goto(BASE); await A.page.waitForLoadState('networkidle');
  ok(A.errors.length === 0, '스크립트 오류 없음 ' + JSON.stringify(A.errors));
  ok(await A.page.evaluate(() => typeof api === 'function' && !!document.getElementById('btnLogin').onclick), '로그인 버튼에 동작이 붙어 있음');
  ok(!(await A.page.locator('#items li').count()), '로그인 전에는 비공개 자료가 화면에 없음');
  ok(!(await A.page.content()).includes('가상기업'), '로그인 전 페이지 소스에 비공개 내용 없음');

  console.log('\n=== 2. 새 계정 + 첫 패스키 등록 ===');
  const a1 = await A.addAuth();
  await A.page.fill('#username', nameA); await A.page.fill('#pkname', 'A-첫번째');
  await A.page.click('#btnReg');
  await A.page.waitForSelector('#member:not([hidden])', { timeout: 8000 }).catch(() => {});
  ok(await A.page.locator('#member').isVisible(), '등록 성공 → 비공개 영역이 열림: ' + await msg(A.page));
  ok((await A.page.locator('#items li').count()) >= 3, '비공개 자료 ' + await A.page.locator('#items li').count() + '건 표시');
  ok((await A.page.locator('#keys li').count()) === 1, '패스키 목록 1개: ' + (await A.page.locator('#keys li').first().innerText()).replace(/\s+/g, ' '));

  console.log('\n=== 3. 두 번째 패스키 추가 → 목록에 두 개 ===');
  const a2 = await A.addAuth('usb'); await A.setPresence(a1, false); // 첫 인증기는 응답하지 않게 해서 두 번째가 만들어지게 함
  await A.page.evaluate(() => (document.getElementById('msg').textContent = ''));
  await A.page.fill('#pkname2', 'A-두번째'); await A.page.click('#btnAdd');
  await A.page.waitForFunction(() => document.querySelectorAll('#keys li').length === 2 || /실패|취소/.test(document.getElementById('msg').textContent), null, { timeout: 8000 }).catch(() => {});
  ok((await A.page.locator('#keys li').count()) === 2, '패스키 목록 2개: ' + (await A.page.locator('#keys li').allInnerTexts()).map((t) => t.replace(/\s+/g, ' ').replace('삭제', '').trim()).join(' / '));
  ok(/\d{4}-\d{2}-\d{2}/.test(await A.page.locator('#keys').innerText()), '각 패스키에 이름과 등록 날짜 표시');

  console.log('\n=== 4. 로그아웃 → 패스키로 로그인 ===');
  await A.setPresence(a1, true);
  await A.page.click('#btnLogout'); await A.page.waitForSelector('#guest:not([hidden])');
  ok((await A.page.locator('#items li').count()) === 0, '로그아웃 후 비공개 자료가 화면에서 사라짐');
  await A.page.click('#btnLogin'); await A.page.waitForSelector('#member:not([hidden])', { timeout: 8000 }).catch(() => {});
  ok(await A.page.locator('#member').isVisible(), '패스키 로그인 성공: ' + await msg(A.page));

  console.log('\n=== 5. 패스키 하나 삭제 → 남은 것으로 로그인, 지운 것으로는 거절 ===');
  await A.page.locator('#keys li').first().locator('button').click(); await waitMsg(A.page, /삭제했습니다|마지막/);
  ok((await A.page.locator('#keys li').count()) === 1, '삭제 후 목록 1개: ' + await msg(A.page));
  const remainingText = await A.page.locator('#keys li').first().innerText();
  const deletedWasFirst = !remainingText.includes('A-첫번째');
  // 어느 인증기가 지워진 패스키를 갖고 있는지: 이름으로 판단 (목록 첫 줄=A-첫번째=a1)
  const goneAuth = deletedWasFirst ? a1 : a2, keptAuth = deletedWasFirst ? a2 : a1;
  await A.page.click('#btnLogout'); await A.page.waitForSelector('#guest:not([hidden])');
  await A.setPresence(goneAuth, false); await A.setPresence(keptAuth, true);
  await A.page.click('#btnLogin'); await A.page.waitForSelector('#member:not([hidden])', { timeout: 8000 }).catch(() => {});
  ok(await A.page.locator('#member').isVisible(), '남은 패스키로 로그인 성공');
  await A.page.click('#btnLogout'); await A.page.waitForSelector('#guest:not([hidden])');
  await A.setPresence(goneAuth, true); await A.setPresence(keptAuth, false);
  await A.page.click('#btnLogin'); const m5 = await waitMsg(A.page, /실패|삭제된|취소/);
  ok(!(await A.page.locator('#member').isVisible()) && /삭제된|실패/.test(m5), '지운 패스키로는 로그인 거절: ' + m5);

  console.log('\n=== 6. 마지막 패스키 삭제 거절 / 등록 취소 ===');
  await A.setPresence(goneAuth, false); await A.setPresence(keptAuth, true);
  await A.page.click('#btnLogin'); await A.page.waitForSelector('#member:not([hidden])', { timeout: 8000 }).catch(() => {});
  await A.page.locator('#keys li').first().locator('button').click(); const m6 = await waitMsg(A.page, /마지막/);
  ok(/마지막/.test(m6) && (await A.page.locator('#keys li').count()) === 1, '마지막 하나는 삭제 거절: ' + m6);
  await A.setUV(keptAuth, false); await A.setUV(goneAuth, false);
  await A.page.fill('#pkname2', '취소시험'); await A.page.click('#btnAdd');
  const m7 = await waitMsg(A.page, /취소|실패|등록했습니다/);
  ok(/취소|실패/.test(m7) && (await A.page.locator('#keys li').count()) === 1, '등록을 중간에 막으면 안내가 나오고 목록은 그대로(저장 안 됨): ' + m7);
  await A.setUV(keptAuth, true);

  console.log('\n=== 7. 두 번째 계정 + 접근 차단 확인 칸 ===');
  const B = await newUser(browser, 'B');
  await B.page.goto(BASE); await B.addAuth();
  await B.page.fill('#username', nameB); await B.page.fill('#pkname', 'B-첫번째'); await B.page.click('#btnReg');
  await B.page.waitForSelector('#member:not([hidden])', { timeout: 8000 }).catch(() => {});
  const bn = await B.page.locator('#items li').count(), an = await A.page.locator('#items li').count();
  ok(bn >= 3 && B.errors.length === 0, `계정B 등록 성공, 자료 ${bn}건 (계정A ${an}건)`);
  ok((await B.page.locator('#items li').first().innerText()) !== (await A.page.locator('#items li').first().innerText()), '두 계정의 비공개 내용이 서로 다름');
  await A.page.fill('#other', nameB); await A.page.click('#btnProbe');
  await A.page.waitForFunction(() => document.getElementById('probe').textContent.includes('요청 후'), null, { timeout: 8000 }).catch(() => {});
  const probe = await A.page.locator('#probe').innerText();
  console.log(probe.split('\n').map((l) => '      ' + l.slice(0, 150)).join('\n'));
  ok(/users\/.*\/private → 403/.test(probe), 'A→B 요청 403');
  ok(/전 내 자료 건수: (\d+)[\s\S]*후 내 자료 건수: \1/.test(probe), '거절 전후 건수 동일');
  await B.page.fill('#other', nameA); await B.page.click('#btnProbe');
  await B.page.waitForFunction(() => document.getElementById('probe').textContent.includes('요청 후'), null, { timeout: 8000 }).catch(() => {});
  ok(/users\/.*\/private → 403/.test(await B.page.locator('#probe').innerText()), 'B→A 요청 403');
  ok(A.errors.length === 0 && B.errors.length === 0, '모든 과정에서 스크립트 오류 없음');

  await browser.close();
  console.log('\n' + (fail ? `실패 ${fail}개` : '모두 통과'));
  process.exit(fail ? 1 : 0);
})().catch((e) => { console.error('시험 중단:', e); process.exit(2); });
