// gw.mdl.kr의 /api/auth/login(src/app/api/auth/login/route.ts)과 같은 구조.
//   아이디(username) → Firestore members/{아이디}@mdl.kr → personalEmail 로 실제 인증
// 사용자는 Firebase Auth 계정 이메일을 몰라도 되고, 브라우저가 Firebase에 직접
// 비밀번호를 보내지 않는다. isAdmin은 members 문서에서 읽어 커스텀 토큰 클레임에 넣는다.
const crypto = require("crypto");
const {
  ensureApp,
  getAuth,
  getFirestore,
  FIREBASE_API_KEY,
  MAIL_DOMAIN,
} = require("./_firebase");

// IP 기준 실패 횟수 제한. 아이디 기준으로 잠그면 "이 아이디는 존재해서 잠겼다"는
// 신호가 새므로, 계정 존재 여부와 무관하게 요청 IP만 본다.
const ATTEMPTS_COLLECTION = "admin_login_attempts";
const WINDOW_MS = 15 * 60 * 1000;
const LOCK_MS = 15 * 60 * 1000;
const MAX_FAILURES = 7;

function clientIp(req) {
  const fwd = req.headers["x-forwarded-for"];
  const ip = (Array.isArray(fwd) ? fwd[0] : fwd || "").split(",")[0].trim();
  return ip || req.socket?.remoteAddress || "unknown";
}

function ipKey(ip) {
  return crypto.createHash("sha256").update(ip).digest("hex").slice(0, 40);
}

async function checkLock(db, key) {
  const ref = db.collection(ATTEMPTS_COLLECTION).doc(key);
  const snap = await ref.get();
  const now = Date.now();
  if (snap.exists) {
    const { lockedUntil } = snap.data();
    if (lockedUntil && lockedUntil > now) {
      return { ref, locked: true, retryAfterMin: Math.ceil((lockedUntil - now) / 60000) };
    }
  }
  return { ref, locked: false };
}

async function recordFailure(ref) {
  const now = Date.now();
  await ref.firestore.runTransaction(async (tx) => {
    const snap = await tx.get(ref);
    const d = snap.exists ? snap.data() : {};
    const windowStart = d.windowStart && now - d.windowStart < WINDOW_MS ? d.windowStart : now;
    const count = (windowStart === d.windowStart ? d.count || 0 : 0) + 1;
    const patch = { count, windowStart, updatedAt: now };
    if (count >= MAX_FAILURES) {
      patch.lockedUntil = now + LOCK_MS;
      patch.count = 0;
      patch.windowStart = now;
    }
    tx.set(ref, patch, { merge: true });
  });
}

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

  const db = getFirestore();
  const key = ipKey(clientIp(req));
  const lock = await checkLock(db, key);
  if (lock.locked) {
    console.warn(`[admin-login] IP 잠김 (${lock.retryAfterMin}분 남음)`);
    return res.status(429).json({ error: `너무 많이 시도했습니다. ${lock.retryAfterMin}분 후 다시 시도해 주세요.` });
  }

  const mailEmail = `${id}@${MAIL_DOMAIN}`;

  // 실패 응답은 원인과 무관하게 항상 동일하다. 없는 아이디 / 비관리자 / 틀린 비밀번호를
  // 구분해서 답하면 비밀번호 없이도 "누가 존재하고 누가 관리자인지" 열거할 수 있다.
  const DENIED = { status: 401, body: { error: "아이디 또는 비밀번호가 올바르지 않습니다." } };
  const deny = async (reason) => {
    console.warn(`[admin-login] 거부(${reason}):`, mailEmail);
    await recordFailure(lock.ref).catch((e) => console.error("[admin-login] 실패 기록 오류:", e.message));
    return res.status(DENIED.status).json(DENIED.body);
  };

  try {
    const doc = await getFirestore().collection("members").doc(mailEmail).get();
    if (!doc.exists) return deny("문서 없음");

    const { personalEmail, isAdmin = false } = doc.data();
    if (!personalEmail) return deny("personalEmail 없음");

    const r = await fetch(
      `https://identitytoolkit.googleapis.com/v1/accounts:signInWithPassword?key=${FIREBASE_API_KEY}`,
      {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify({ email: personalEmail, password, returnSecureToken: true }),
      }
    );
    const auth = await r.json();
    if (auth.error) return deny(`Firebase Auth: ${auth.error.message}`);

    // 비밀번호까지 맞은 뒤에야 admin 여부를 가른다 — 순서가 바뀌면 관리자 계정을
    // 응답으로 구분할 수 있게 된다.
    if (isAdmin !== true) return deny("관리자 아님");

    const token = await getAuth().createCustomToken(auth.localId, { mailEmail, isAdmin: true });
    console.log("[admin-login] 로그인 성공:", mailEmail);
    await lock.ref.delete().catch(() => {});
    return res.status(200).json({ token, mailEmail });
  } catch (e) {
    console.error("[admin-login] 실패:", e);
    return res.status(500).json({ error: "로그인 처리 중 오류가 발생했습니다." });
  }
};
