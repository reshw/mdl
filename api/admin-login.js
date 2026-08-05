// gw.mdl.kr의 /api/auth/login(src/app/api/auth/login/route.ts)과 같은 구조.
//   아이디(username) → Firestore members/{아이디}@mdl.kr → personalEmail 로 실제 인증
// 사용자는 Firebase Auth 계정 이메일을 몰라도 되고, 브라우저가 Firebase에 직접
// 비밀번호를 보내지 않는다. isAdmin은 members 문서에서 읽어 커스텀 토큰 클레임에 넣는다.
const {
  ensureApp,
  getAuth,
  getFirestore,
  FIREBASE_API_KEY,
  MAIL_DOMAIN,
} = require("./_firebase");

module.exports = async (req, res) => {
  if (req.method !== "POST") {
    res.setHeader("Allow", "POST");
    return res.status(405).json({ error: "POST만 허용됩니다." });
  }

  const body = typeof req.body === "string" ? JSON.parse(req.body || "{}") : req.body || {};
  const id = String(body.id || "").trim().toLowerCase();
  const password = String(body.password || "");

  if (!id || !password) {
    return res.status(400).json({ error: "아이디와 비밀번호를 입력해주세요." });
  }
  if (!/^[a-z0-9._-]{1,64}$/.test(id)) {
    return res.status(401).json({ error: "아이디 또는 비밀번호가 올바르지 않습니다." });
  }

  try {
    ensureApp();
  } catch (e) {
    console.error("[admin-login] Firebase 초기화 실패:", e.message);
    return res.status(500).json({ error: "서버 Firebase 자격증명이 올바르지 않습니다." });
  }

  const mailEmail = `${id}@${MAIL_DOMAIN}`;

  try {
    const doc = await getFirestore().collection("members").doc(mailEmail).get();
    if (!doc.exists) {
      return res.status(401).json({ error: "아이디 또는 비밀번호가 올바르지 않습니다." });
    }

    const { personalEmail, isAdmin = false } = doc.data();
    if (!personalEmail) {
      return res.status(401).json({ error: "계정 정보가 올바르지 않습니다." });
    }

    // 관리자 전용 페이지 — 비관리자는 비밀번호가 맞아도 토큰을 발급하지 않는다.
    if (isAdmin !== true) {
      console.warn("[admin-login] 관리자 아님:", mailEmail);
      return res.status(403).json({ error: "관리자 권한이 없습니다." });
    }

    const r = await fetch(
      `https://identitytoolkit.googleapis.com/v1/accounts:signInWithPassword?key=${FIREBASE_API_KEY}`,
      {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify({ email: personalEmail, password, returnSecureToken: true }),
      }
    );
    const auth = await r.json();

    if (auth.error) {
      if (auth.error.message === "USER_DISABLED") {
        return res.status(401).json({ error: "비활성화된 계정입니다." });
      }
      return res.status(401).json({ error: "아이디 또는 비밀번호가 올바르지 않습니다." });
    }

    const token = await getAuth().createCustomToken(auth.localId, { mailEmail, isAdmin: true });
    console.log("[admin-login] 로그인 성공:", mailEmail);
    return res.status(200).json({ token, mailEmail });
  } catch (e) {
    console.error("[admin-login] 실패:", e);
    return res.status(500).json({ error: "로그인 처리 중 오류가 발생했습니다." });
  }
};
