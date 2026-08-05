const crypto = require("crypto");
const { getMessaging } = require("firebase-admin/messaging");
const { ensureApp, getAuth, getFirestore } = require("./_firebase");

// mailer-and(안드로이드) 앱이 시작 시 구독하는 FCM 토픽.
// data-only 메시지만 보낸다(top-level notification 블록 금지) — 넣으면 앱이 백그라운드일 때
// 시스템이 기본 알림을 그려버려서, 탭 시 Play 스토어 링크로 보내는
// MailerMessagingService.showUpdateNotification()의 커스텀 처리가 무시된다.
const TOPIC = "app_updates";
const DEFAULT_URL = "https://play.google.com/store/apps/details?id=kr.mdl.mailer";

// gw.mdl.kr의 assertAdmin(src/lib/firebase-admin.ts)과 동일한 판정 —
// isAdmin 커스텀 클레임이 있으면 통과, 없으면 Firestore members/{메일주소}.isAdmin 확인.
async function verifyAdmin(idToken) {
  const decoded = await getAuth().verifyIdToken(idToken);
  const email = decoded.mailEmail || decoded.email || null;
  if (decoded.isAdmin === true) return { ok: true, email };
  if (!email) return { ok: false, email: null };
  const doc = await getFirestore().collection("members").doc(email).get();
  return { ok: doc.exists && doc.data()?.isAdmin === true, email };
}

function passwordMatches(given) {
  const expected = process.env.ADMIN_PASSWORD || "";
  if (!expected || typeof given !== "string" || !given) return false;
  const a = Buffer.from(given);
  const b = Buffer.from(expected);
  if (a.length !== b.length) return false;
  return crypto.timingSafeEqual(a, b);
}

module.exports = async (req, res) => {
  if (req.method !== "POST") {
    res.setHeader("Allow", "POST");
    return res.status(405).json({ error: "POST만 허용됩니다." });
  }

  if (!process.env.ADMIN_PASSWORD) {
    return res.status(500).json({ error: "서버에 ADMIN_PASSWORD가 설정되지 않았습니다." });
  }

  // 1단계: Firebase 관리자 계정 검증 (gw.mdl.kr과 같은 관리자 명단)
  const idToken = (req.headers.authorization || "").replace(/^Bearer\s+/i, "").trim();
  if (!idToken) {
    return res.status(401).json({ error: "로그인이 필요합니다." });
  }

  // 서버 자격증명 문제와 토큰 문제를 구분한다 — 뭉치면 환경변수가 깨졌을 때도
  // "로그인이 만료되었습니다"만 떠서 원인을 찾을 수 없다.
  try {
    ensureApp();
  } catch (e) {
    console.error("[notify-app-update] Firebase 초기화 실패:", e.message);
    return res.status(500).json({ error: "서버 Firebase 자격증명이 올바르지 않습니다. FIREBASE_ADMIN_SERVICE_ACCOUNT를 확인하세요." });
  }

  let admin;
  try {
    admin = await verifyAdmin(idToken);
  } catch (e) {
    console.error("[notify-app-update] 토큰 검증 실패:", e.message);
    return res.status(401).json({ error: "로그인이 만료되었습니다. 다시 로그인해 주세요." });
  }
  if (!admin.ok) {
    console.warn("[notify-app-update] 관리자 아님:", admin.email);
    return res.status(403).json({ error: "관리자 권한이 없습니다." });
  }

  // 2단계: 발송 전용 키
  if (!passwordMatches(req.headers["x-admin-password"])) {
    console.warn("[notify-app-update] 발송 키 불일치:", admin.email);
    return res.status(401).json({ error: "발송 키가 올바르지 않습니다." });
  }

  const body = typeof req.body === "string" ? JSON.parse(req.body || "{}") : req.body || {};
  const version = String(body.version || "").trim();
  const notes = String(body.notes || "").trim();

  if (!version || !notes) {
    return res.status(400).json({ error: "버전과 변경 내용을 입력하세요." });
  }
  if (version.length > 20 || notes.length > 300) {
    return res.status(400).json({ error: "버전은 20자, 변경 내용은 300자 이내여야 합니다." });
  }

  try {
    const messageId = await getMessaging().send({
      topic: TOPIC,
      // url은 호출자에게서 받지 않는다. 앱이 data["url"]을 그대로 ACTION_VIEW로 열기 때문에
      // 임의 URL을 받으면 "MailXC 업데이트" 알림으로 아무 사이트나 열게 만들 수 있다(피싱).
      data: {
        type: "update",
        title: `MailXC v${version} 업데이트`,
        body: notes,
        url: DEFAULT_URL,
      },
      android: { priority: "high" },
    });
    // 누가 언제 무엇을 보냈는지 남긴다(Vercel 함수 로그에서 조회).
    console.log(`[notify-app-update] 발송 by=${admin.email} v=${version} messageId=${messageId}`);
    return res.status(200).json({ ok: true, messageId, sentBy: admin.email });
  } catch (e) {
    console.error("[notify-app-update] 발송 실패:", e);
    return res.status(500).json({ error: e.message || "발송에 실패했습니다." });
  }
};
