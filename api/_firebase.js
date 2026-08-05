// 두 함수(admin-login, notify-app-update)가 공유하는 Firebase Admin 초기화.
// 파일명이 _ 로 시작하면 Vercel이 라우트로 노출하지 않는다.
const { initializeApp, getApps, cert } = require("firebase-admin/app");
const { getAuth } = require("firebase-admin/auth");
const { getFirestore } = require("firebase-admin/firestore");

// gw.mdl.kr과 동일한 Firebase 웹 API 키. 클라이언트에 공개되는 값이라 비밀이 아니다
// (admin/index.html에도 같은 값이 들어 있다).
const FIREBASE_API_KEY = "AIzaSyB7YGie98rhJNHRoQritGBEyM15WtGq6A4";
const MAIL_DOMAIN = "mdl.kr";

function ensureApp() {
  if (getApps().length) return;

  const json = process.env.FIREBASE_ADMIN_SERVICE_ACCOUNT;
  if (json) {
    initializeApp({ credential: cert(JSON.parse(json)) });
    return;
  }

  const projectId = process.env.FIREBASE_ADMIN_PROJECT_ID;
  const clientEmail = process.env.FIREBASE_ADMIN_CLIENT_EMAIL;
  const privateKey = process.env.FIREBASE_ADMIN_PRIVATE_KEY;
  if (!projectId || !clientEmail || !privateKey) {
    throw new Error("FIREBASE_ADMIN_* 환경변수가 설정되지 않았습니다.");
  }

  initializeApp({
    credential: cert({
      projectId,
      clientEmail,
      privateKey: privateKey.replace(/\\n/g, "\n").trim(),
    }),
  });
}

module.exports = {
  ensureApp,
  getAuth,
  getFirestore,
  FIREBASE_API_KEY,
  MAIL_DOMAIN,
};
