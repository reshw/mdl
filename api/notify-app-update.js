const crypto = require("crypto");
const { initializeApp, getApps, cert } = require("firebase-admin/app");
const { getMessaging } = require("firebase-admin/messaging");

// mailer-and(안드로이드) 앱이 시작 시 구독하는 FCM 토픽.
// data-only 메시지만 보낸다(top-level notification 블록 금지) — 넣으면 앱이 백그라운드일 때
// 시스템이 기본 알림을 그려버려서, 탭 시 Play 스토어 링크로 보내는
// MailerMessagingService.showUpdateNotification()의 커스텀 처리가 무시된다.
const TOPIC = "app_updates";
const DEFAULT_URL = "https://play.google.com/store/apps/details?id=kr.mdl.mailer";

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

  if (!passwordMatches(req.headers["x-admin-password"])) {
    return res.status(401).json({ error: "비밀번호가 올바르지 않습니다." });
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
    ensureApp();
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
    return res.status(200).json({ ok: true, messageId });
  } catch (e) {
    console.error("[notify-app-update] 발송 실패:", e);
    return res.status(500).json({ error: e.message || "발송에 실패했습니다." });
  }
};
