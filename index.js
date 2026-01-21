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

const users = [];
let userAutoId = 1;

// --------------------
// JWT 미들웨어
// --------------------
function auth(req, res, next) {
  const header = req.headers.authorization;
  if (!header) return res.status(401).json({ message: "Authorization 없음" });

  const [type, token] = header.split(" ");
  if (type !== "Bearer" || !token) {
    return res.status(401).json({ message: "Bearer 형식 아님" });
  }

  try {
    req.user = jwt.verify(token, SECRET_KEY);
    next();
  } catch {
    return res.status(401).json({ message: "토큰 검증 실패" });
  }
}

// --------------------
// 1️⃣ 회원가입 (명세 기준)
// --------------------
app.post("/register", (req, res) => {
  const { username, password, user } = req.body;

  if (!username || !password || !user?.name) {
    return res.status(400).json({ message: "필수 값 누락" });
  }

  if (users.find(u => u.username === username)) {
    return res.status(400).json({ message: "이미 존재" });
  }

  users.push({
    id: userAutoId++,
    username,
    password,
    name: user.name,
    picture: null,
  });

  return res.json({ success: true });
});

// --------------------
// 2️⃣ 로그인
// --------------------
app.post("/login", (req, res) => {
  const { username, password } = req.body;

  const user = users.find(
    u => u.username === username && u.password === password
  );

  if (!user) {
    return res.status(401).json({ message: "로그인 실패" });
  }

  const token = jwt.sign(
    { userId: user.id, username: user.username },
    SECRET_KEY,
    { expiresIn: "2h" }
  );

  return res.json({
    token,
    user: {
      name: user.name,
      picture: user.picture,
    },
  });
});

// --------------------
// 3️⃣ 마이페이지
// --------------------
app.get("/mypage", auth, (req, res) => {
  const user = users.find(u => u.id === req.user.userId);
  if (!user) return res.status(404).json({ message: "유저 없음" });

  return res.json({
    user: {
      name: user.name,
      picture: user.picture,
    },
    data: {
      properties: "잔금",
    },
  });
});

// --------------------
// 4️⃣ 구글 로그인 (핵심 수정)
// --------------------
app.post("/auth/google", async (req, res) => {
  const { code } = req.body;
  if (!code) {
    return res.status(400).json({ message: "code 없음" });
  }

  try {
    const tokenRes = await axios.post(
      "https://oauth2.googleapis.com/token",
      {
        code,
        client_id: process.env.GOOGLE_CLIENT_ID,
        client_secret: process.env.GOOGLE_CLIENT_SECRET,
        redirect_uri: process.env.GOOGLE_REDIRECT_URI, // ⭐️ 반드시 프론트와 동일
        grant_type: "authorization_code",
      },
      {
        headers: { "Content-Type": "application/json" },
      }
    );

    const { access_token } = tokenRes.data;

    const userRes = await axios.get(
      "https://www.googleapis.com/oauth2/v2/userinfo",
      {
        headers: { Authorization: `Bearer ${access_token}` },
      }
    );

    const { name, email, picture } = userRes.data;

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

    const jwtToken = jwt.sign(
      { userId: user.id, username: user.username },
      SECRET_KEY,
      { expiresIn: "2h" }
    );

    return res.json({
      token: jwtToken,
      user: {
        name: user.name,
        picture: user.picture,
      },
    });

  } catch (err) {
    console.error("Google OAuth 실패:", err.response?.data || err.message);
    return res.status(500).json({ message: "Google OAuth 실패" });
  }
});

app.listen(PORT, () => {
  console.log(`Server running on port ${PORT}`);
});
