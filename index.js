const express = require("express");
const cors = require("cors");
const jwt = require("jsonwebtoken");

const app = express();
app.use(cors());
app.use(express.json());

// Render 배포까지 고려한 PORT
const PORT = process.env.PORT || 4000;

// 실전이면 env로 빼야 함. 지금은 학습/테스트용으로 기본값 제공
const SECRET_KEY = process.env.SECRET_KEY || "DEV_SECRET_KEY_CHANGE_ME";

// --------------------
// 메모리 DB (서버 재시작하면 초기화됨)
// --------------------
const users = []; // { id, username, password, email, birth }
const historiesByUserId = new Map(); // userId -> [{id, from, to, amount, result}]

let userAutoId = 1;
let historyAutoId = 1;

// --------------------
// JWT 인증 미들웨어
// --------------------
function auth(req, res, next) {
  const header = req.headers.authorization; // "Bearer xxx"
  if (!header) return res.status(401).json({ success: false, message: "Authorization 헤더 없음" });

  const [type, token] = header.split(" ");
  if (type !== "Bearer" || !token) {
    return res.status(401).json({ success: false, message: "Bearer 토큰 형식 아님" });
  }

  try {
    const decoded = jwt.verify(token, SECRET_KEY); // { userId, username }
    req.user = decoded;
    next();
  } catch (e) {
    return res.status(401).json({ success: false, message: "토큰 검증 실패" });
  }
}

// --------------------
// 1) 회원가입: POST /register
// Body: { username, password, email, birth }
// Res: { success: true }
// --------------------
app.post("/register", (req, res) => {
  const { username, password, email, birth } = req.body || {};

  if (!username || !password || !email || !birth) {
    return res.status(400).json({ success: false, message: "필수값 누락" });
  }

  const exists = users.find((u) => u.username === username);
  if (exists) {
    return res.status(409).json({ success: false, message: "이미 존재하는 username" });
  }

  const newUser = {
    id: userAutoId++,
    username,
    password, // 실전이면 해싱해야 함 (bcrypt)
    email,
    birth,
  };
  users.push(newUser);
  historiesByUserId.set(newUser.id, []);

  return res.json({ success: true });
});

// --------------------
// 2) 로그인: POST /login
// Body: { username, password }
// Res: { success: true, accessToken: "..." }
// --------------------
app.post("/login", (req, res) => {
  const { username, password } = req.body || {};
  if (!username || !password) {
    return res.status(400).json({ success: false, message: "필수값 누락" });
  }

  const user = users.find((u) => u.username === username && u.password === password);
  if (!user) {
    return res.status(401).json({ success: false, message: "아이디/비번 불일치" });
  }

  const accessToken = jwt.sign(
    { userId: user.id, username: user.username },
    SECRET_KEY,
    { expiresIn: "2h" }
  );

  return res.json({ success: true, accessToken });
});

// --------------------
// 3) 마이페이지: GET /mypage
// Header: Authorization: Bearer {accessToken}
// Res: { username, email, birth }
// --------------------
app.get("/mypage", auth, (req, res) => {
  const user = users.find((u) => u.id === req.user.userId);
  if (!user) return res.status(404).json({ success: false, message: "유저 없음" });

  return res.json({
    username: user.username,
    email: user.email,
    birth: user.birth,
  });
});

// --------------------
// 4) 메인(기록 조회): GET /main
// Header: Authorization: Bearer {token}
// Res: { history: [...] }
// --------------------
app.get("/main", auth, (req, res) => {
  const list = historiesByUserId.get(req.user.userId) || [];
  return res.json({ history: list });
});

// --------------------
// 5) 검색 기록 생성: POST /main
// Header: Authorization: Bearer {accessToken}
// Body: { from, to, amount, result }
// Res: { success: true }
// --------------------
app.post("/main", auth, (req, res) => {
  const { from, to, amount, result } = req.body || {};
  if (!from || !to || amount === undefined || result === undefined) {
    return res.status(400).json({ success: false, message: "필수값 누락" });
  }

  const list = historiesByUserId.get(req.user.userId) || [];
  list.push({
    id: historyAutoId++,
    from,
    to,
    amount,
    result,
  });
  historiesByUserId.set(req.user.userId, list);

  return res.json({ success: true });
});

// --------------------
// 6) 환율 변환 기록 삭제: DELETE /main/{historyId}
// Header: Authorization: Bearer {accessToken}
// Res: { success: true }
// --------------------
app.delete("/main/:historyId", auth, (req, res) => {
  const historyId = Number(req.params.historyId);
  const list = historiesByUserId.get(req.user.userId) || [];

  const idx = list.findIndex((h) => h.id === historyId);
  if (idx === -1) return res.status(404).json({ success: false, message: "기록 없음" });

  list.splice(idx, 1);
  historiesByUserId.set(req.user.userId, list);

  return res.json({ success: true });
});

// --------------------
app.listen(PORT, () => {
  console.log(`Server running on port ${PORT}`);
});
