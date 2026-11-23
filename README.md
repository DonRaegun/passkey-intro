# 패스키 로그인 소개 페이지 (과제 8)

공개 소개 페이지에 패스키(WebAuthn) 로그인과 계정별 비공개 자료 영역을 붙인 Node 서버 앱입니다. 비밀번호는 받지 않습니다. 로그인한 계정은 자기 자료만 볼 수 있고, 다른 계정 자료를 요청하면 403으로 거절됩니다. 자료는 모두 `[가상]` 표시의 지어낸 내용입니다.

## 주소

- 결과물: https://gsg-passkey-intro-1gvp.axhub.app/ (비공개 영역은 맨 아래 노란 띠 아래)
- 소스: https://github.com/DonRaegun/passkey-intro

## 더 보기

- [인증 구현 설명서](docs/인증-구현-설명서.md)
- [제출문](docs/T08-제출문.md)
- 요청·응답 기록: [test/evidence.txt](test/evidence.txt)

## 로컬 실행

```bash
npm install
node server.js   # http://localhost:3000
```
