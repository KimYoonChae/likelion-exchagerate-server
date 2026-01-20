require("dotenv").config();
const express = require("express");
const cors = require("cors");
const jwt = require("jsonwebtoken");
const axios = require("axios");

const app = express();
app.use(cors());
app.use(express.json());

const PORT = process.env.PORT || 4000;
const SECRET_KEY = process.env.SECRET_KEY;

// --------------------
// 메모리 DB
// --------------------
const users = []; // { id, username, password, name, picture }
let userAutoId = 1;

// --------------------
// JWT 인증 미들웨어
// --------------------
function auth(req, res, next) {
  const header = req.headers.authorization;
  if (!header) return res.status(401).json({ message: "Authorization 헤더 없음" });

  const [type, token] = header.split(" ");
  if (type !== "Bearer" || !token) {
    return res.status(401).json({ message: "Bearer 토큰 형식 아님" });
  }

  try {
    const decoded = jwt.verify(token, SECRET_KEY);
    req.user = decoded;
    next();
  } catch {
    return res.status(401).json({ message: "토큰 검증 실패" });
  }
}

// --------------------
// 1️⃣ 회원가입
// POST /register
// --------------------
app.post("/register", (req, res) => {
  const { username, password } = req.body || {};
  if (!username || !password) {
    return res.status(400).json({ message: "필수값 누락" });
  }

  if (users.find(u => u.username === username)) {
    return res.status(409).json({ message: "이미 존재하는 유저" });
  }

  users.push({
    id: userAutoId++,
    username,
    password,
    name: username,
    picture: ""
  });

  return res.json({ success: true });
});

// --------------------
// 2️⃣ 일반 로그인
// POST /login
// --------------------
app.post("/login", (req, res) => {
  const { username, password } = req.body || {};
  if (!username || !password) {
    return res.status(400).json({ message: "필수값 누락" });
  }

  const user = users.find(
    u => u.username === username && u.password === password
  );

  if (!user) {
    return res.status(401).json({ message: "아이디/비밀번호 불일치" });
  }

  const token = jwt.sign(
    { userId: user.id },
    SECRET_KEY,
    { expiresIn: "2h" }
  );

  return res.json({
    token,
    user: {
      name: user.name,
      picture: user.picture
    }
  });
});

// --------------------
// 3️⃣ 로그인 유저 정보
// GET /auth/me
// --------------------
app.get("/auth/me", auth, (req, res) => {
  const user = users.find(u => u.id === req.user.userId);
  if (!user) return res.status(404).json({ message: "유저 없음" });

  return res.json({
    username: user.username,
    picture: user.picture
  });
});

// --------------------
// 4️⃣ 구글 로그인 (실전 OAuth)
// POST /auth/google
// --------------------
app.post("/auth/google", async (req, res) => {
  const { code } = req.body || {};
  if (!code) {
    return res.status(400).json({ message: "authorization code 없음" });
  }

  try {
    // 1) code → access token
    const tokenRes = await axios.post(
      "https://oauth2.googleapis.com/token",
      {
        code,
        client_secret: process.env.GOOGLE_CLIENT_SECRET,
        client_id: req.body.clientId, // 프론트가 사용한 clientId
        redirect_uri: process.env.GOOGLE_REDIRECT_URI,
        grant_type: "authorization_code",
      },
      { headers: { "Content-Type": "application/json" } }
    );

    const { access_token } = tokenRes.data;

    // 2) 유저 정보 조회
    const userRes = await axios.get(
      "https://www.googleapis.com/oauth2/v2/userinfo",
      {
        headers: {
          Authorization: `Bearer ${access_token}`,
        },
      }
    );

    const { name, email, picture } = userRes.data;

    // 3) 유저 생성 or 조회
    let user = users.find(u => u.username === email);
    if (!user) {
      user = {
        id: userAutoId++,
        username: email,
        password: null,
        name,
        picture,
      };
      users.push(user);
    }

    // 4) JWT 발급
    const token = jwt.sign(
      { userId: user.id },
      SECRET_KEY,
      { expiresIn: "2h" }
    );

    // 5) 명세 그대로 응답
    return res.json({
      token,
      user: {
        name: user.name,
        picture: user.picture
      }
    });

  } catch (err) {
    console.error(err.response?.data || err.message);
    return res.status(500).json({ message: "Google OAuth 실패" });
  }
});

// --------------------
app.listen(PORT, () => {
  console.log(`Server running on port ${PORT}`);
});
