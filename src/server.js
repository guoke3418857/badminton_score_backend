require("dotenv").config();
const express = require("express");
const cors = require("cors");
const crypto = require("crypto");
const { z } = require("zod");
const { v4: uuid } = require("uuid");
const { pool, migrate, withTransaction, addScore, mapActivity } = require("./db");

const PORT = process.env.PORT || 4000;
const CORS_ORIGINS = process.env.CORS_ORIGINS?.split(",").map((s) => s.trim()).filter(Boolean);
const ADMIN_EMAILS =
  process.env.ADMIN_EMAILS?.split(",").map((s) => s.trim()).filter(Boolean) || ["guoke@foryou56.com"];

const app = express();
// 先处理 application/json
app.use(
  express.json({
    verify: (req, _res, buf) => {
      req.rawBody = buf.toString();
    },
  })
);
// 再处理 text/plain（前端若错误地以 text/plain 发送 JSON，这里兜底）
app.use(
  express.text({
    type: "text/plain",
    verify: (req, _res, buf) => {
      req.rawBody = buf.toString();
    },
  })
);
// 如果 body 还是字符串，保存原文，后续路由里再解析
app.use((req, _res, next) => {
  if (!req.rawBody && typeof req.body === "string") {
    req.rawBody = req.body;
  }
  next();
});
app.use(
  cors({
    origin: CORS_ORIGINS && CORS_ORIGINS.length > 0 ? CORS_ORIGINS : "*",
  })
);

// ---------- Schemas ----------
const userSchema = z.object({
  id: z.string().min(1),
  name: z.string().optional(),
  department: z.string().optional(),
  avatar: z.string().optional(),
  isAdmin: z.boolean().optional(),
  totalScore: z.number().int().optional(),
  winCount: z.number().int().optional(),
  matchCount: z.number().int().optional(),
});

const activitySchema = z.object({
  title: z.string().min(1),
  startTime: z.string().optional(),
  endTime: z.string().optional(),
  location: z.string().optional(),
  courtCount: z.number().int().default(0),
  allowSingle: z.boolean().default(true),
  allowDouble: z.boolean().default(true),
  description: z.string().optional(),
  maxParticipants: z.number().int().optional(),
});

const signupSchema = z.object({
  userId: z.string().min(1),
});

const registerSchema = z.object({
  email: z.string().email(),
  password: z.string().min(6),
  name: z.string().min(1),
  department: z.string().optional(),
  avatar: z.string().optional(),
});

const loginSchema = z.object({
  email: z.string().email(),
  password: z.string().min(1),
});

const scoreRequestSchema = z.object({
  activityId: z.string().min(1),
  type: z.enum(["single", "double"]),
  initiatorId: z.string().min(1),
  teammateId: z.string().optional(),
  opponentIds: z.array(z.string().min(1)).nonempty(),
  // 单局比分（胜方与败方最终得分），用于按规则精细结算
  winnerScore: z.number().int().min(0).max(30),
  loserScore: z.number().int().min(0).max(30),
});

const confirmSchema = z.object({
  userId: z.string().min(1),
  accept: z.boolean().default(true),
});

const groupSchema = z.object({
  activityId: z.string().min(1),
  courtNo: z.number().int().positive(),
  matchType: z.enum(["single", "double"]),
  playerIds: z.array(z.string().min(1)).nonempty(),
});

// ---------- Helpers ----------
function computePending(statusString) {
  return statusString ? statusString.split(",").filter(Boolean) : [];
}

function formatUser(row) {
  if (!row) return null;
  return {
    id: row.id,
    name: row.name ?? "",
    department: row.department ?? "",
    avatar: row.avatar ?? "",
    totalScore: row.total_score ?? 0,
    winCount: row.win_count ?? 0,
    matchCount: row.match_count ?? 0,
    isAdmin: !!row.is_admin,
  };
}

function hashPassword(password) {
  const salt = crypto.randomBytes(16).toString("hex");
  const hash = crypto.pbkdf2Sync(password, salt, 10_000, 64, "sha512").toString("hex");
  return `${salt}:${hash}`;
}

function verifyPassword(password, storedHash) {
  const [salt, hash] = (storedHash || "").split(":");
  if (!salt || !hash) return false;
  const verify = crypto.pbkdf2Sync(password, salt, 10_000, 64, "sha512").toString("hex");
  const hashBuffer = Buffer.from(hash, "hex");
  const verifyBuffer = Buffer.from(verify, "hex");
  if (hashBuffer.length !== verifyBuffer.length) return false;
  return crypto.timingSafeEqual(hashBuffer, verifyBuffer);
}

async function ensureUser(id, extra = {}) {
  const isAdmin = extra.isAdmin ?? ADMIN_EMAILS.includes(id);
  await pool.query(
    `
      INSERT INTO users (id, name, department, avatar, total_score, win_count, match_count, is_admin)
      VALUES ($1, $2, $3, $4, $5, $6, $7, $8)
      ON CONFLICT (id) DO UPDATE SET
        name = COALESCE(EXCLUDED.name, users.name),
        department = COALESCE(EXCLUDED.department, users.department),
        avatar = COALESCE(EXCLUDED.avatar, users.avatar),
        is_admin = COALESCE(EXCLUDED.is_admin, users.is_admin)
    `,
    [
      id,
      extra.name ?? null,
      extra.department ?? null,
      extra.avatar ?? null,
      extra.totalScore ?? 0,
      extra.winCount ?? 0,
      extra.matchCount ?? 0,
      isAdmin,
    ]
  );
}

async function validateActivityExists(activityId) {
  const row = await pool.query(`SELECT id FROM activities WHERE id = $1`, [activityId]);
  return row.rowCount > 0;
}

// ---------- Scoring Engine ----------
// 根据 PRD+积分规则说明页，实现统一的单打/双打个人积分结算：
// - 单打基础分：胜 +10，负 +4
// - 双打基础分（按人）：胜 +8，负 +5
// - 比分差奖励：1–3 分 负方 +1；4–7 分 胜方 +1；>=8 分 胜方 +2
// - 动态比分差上限：<50 → 上限 +2；50–99 → 上限 +1；>=100 → 上限 +0
// - 分差保护：赛前积分差 >=100 时，高分一方胜利基础分 -2，低分一方失败基础分 +2
// - 爆冷奖励（优先级高于比分差奖励）：
//   - 完全爆冷：赛前积分差 >=100 且低分方获胜 → 低分方 +3
//   - 接近爆冷：赛前积分差 >=100 且高分方获胜且比分差 <=3 → 低分方 +2

function average(nums) {
  if (!nums.length) return 0;
  return nums.reduce((a, b) => a + b, 0) / nums.length;
}

/**
 * 计算单场对局中每位选手的加减分及拆解明细
 * @returns {{
 *   points: Map<string, number>,
 *   details: Map<string, {
 *     role: "winner" | "loser",
 *     base: number,
 *     diffBonus: number,
 *     upsetBonus: number,
 *     protectionAdjust: number,
 *     preScore: number,
 *     sidePreAvg: { winner: number, loser: number },
 *   }>
 * }}
 */
function computeMatchPoints({ type, preScores, winnerIds, loserIds, winnerScore, loserScore }) {
  const winnerSideScore = average(winnerIds.map((id) => preScores.get(id) ?? 0));
  const loserSideScore = average(loserIds.map((id) => preScores.get(id) ?? 0));

  const highSide = winnerSideScore >= loserSideScore ? "winner" : "loser";
  const lowSide = highSide === "winner" ? "loser" : "winner";
  const scoreGapPre = Math.abs(winnerSideScore - loserSideScore);

  const baseWin = type === "single" ? 10 : 8;
  const baseLose = type === "single" ? 4 : 5;

  let finalBaseWin = baseWin;
  let finalBaseLose = baseLose;
  let protectionAdjustWin = 0;
  let protectionAdjustLose = 0;

  // 分差保护：赛前积分差 >= 100
  if (scoreGapPre >= 100) {
    if (highSide === "winner") {
      // 高分方胜利：高分方 -2，低分方失败 +2
      finalBaseWin = baseWin - 2;
      finalBaseLose = baseLose + 2;
      protectionAdjustWin = -2;
      protectionAdjustLose = +2;
    } else {
      // 低分方胜利：高分方失败 -2，低分方胜利 +2
      finalBaseWin = baseWin + 2;
      finalBaseLose = baseLose - 2;
      protectionAdjustWin = +2;
      protectionAdjustLose = -2;
    }
  }

  // 比分差奖励
  const diff = Math.abs(winnerScore - loserScore);
  let diffBonusWinner = 0;
  let diffBonusLoser = 0;
  if (diff >= 1) {
    if (diff <= 3) {
      diffBonusLoser = 1;
    } else if (diff <= 7) {
      diffBonusWinner = 1;
    } else {
      diffBonusWinner = 2;
    }
  }

  // 动态比分差上限
  if (scoreGapPre >= 100) {
    diffBonusWinner = 0;
    diffBonusLoser = 0;
  } else if (scoreGapPre >= 50) {
    diffBonusWinner = Math.min(diffBonusWinner, 1);
    diffBonusLoser = Math.min(diffBonusLoser, 1);
  }

  // 爆冷奖励（覆盖比分差奖励）
  let upsetBonusWinner = 0;
  let upsetBonusLoser = 0;
  if (scoreGapPre >= 100) {
    const lowSideIsWinner = lowSide === "winner";
    if (lowSideIsWinner) {
      // 完全爆冷：低分方获胜
      upsetBonusWinner = 3;
      diffBonusWinner = 0;
      diffBonusLoser = 0;
    } else if (diff <= 3) {
      // 接近爆冷：高分方胜利但小分差
      upsetBonusLoser = 2;
      diffBonusWinner = 0;
      diffBonusLoser = 0;
    }
  }

  const totalWinnerSide = finalBaseWin + diffBonusWinner + upsetBonusWinner;
  const totalLoserSide = finalBaseLose + diffBonusLoser + upsetBonusLoser;

  const points = new Map();
  const details = new Map();

  winnerIds.forEach((id) => {
    points.set(id, totalWinnerSide);
    details.set(id, {
      role: "winner",
      base: finalBaseWin,
      diffBonus: diffBonusWinner,
      upsetBonus: upsetBonusWinner,
      protectionAdjust: protectionAdjustWin,
      preScore: preScores.get(id) ?? 0,
      sidePreAvg: { winner: winnerSideScore, loser: loserSideScore },
    });
  });
  loserIds.forEach((id) => {
    points.set(id, totalLoserSide);
    details.set(id, {
      role: "loser",
      base: finalBaseLose,
      diffBonus: diffBonusLoser,
      upsetBonus: upsetBonusLoser,
      protectionAdjust: protectionAdjustLose,
      preScore: preScores.get(id) ?? 0,
      sidePreAvg: { winner: winnerSideScore, loser: loserSideScore },
    });
  });

  return { points, details };
}

// ---------- Routes ----------
app.get("/health", async (_req, res) => {
  try {
    await pool.query("SELECT 1");
    res.json({ status: "ok" });
  } catch (err) {
    res.status(500).json({ status: "error", message: err.message });
  }
});

app.post("/auth/register", async (req, res) => {
  try {
    const data = registerSchema.parse(req.body);
    const userId = data.email.trim().toLowerCase();
    const passwordHash = hashPassword(data.password);
    const isAdmin = ADMIN_EMAILS.includes(userId);

    await pool.query(
      `
        INSERT INTO users (id, name, department, avatar, total_score, win_count, match_count, is_admin, password_hash)
        VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9)
        ON CONFLICT (id) DO UPDATE SET
          name = EXCLUDED.name,
          department = EXCLUDED.department,
          avatar = COALESCE(EXCLUDED.avatar, users.avatar),
          password_hash = EXCLUDED.password_hash,
          is_admin = EXCLUDED.is_admin
      `,
      [userId, data.name, data.department ?? null, data.avatar ?? null, 0, 0, 0, isAdmin, passwordHash]
    );

    const user = await pool.query(`SELECT * FROM users WHERE id = $1`, [userId]);
    res.status(201).json(formatUser(user.rows[0]));
  } catch (err) {
    res.status(400).json({ error: err.message });
  }
});

app.post("/auth/login", async (req, res) => {
  try {
    const data = loginSchema.parse(req.body);
    const userId = data.email.trim().toLowerCase();
    const result = await pool.query(`SELECT * FROM users WHERE id = $1`, [userId]);
    if (result.rowCount === 0) return res.status(401).json({ error: "未注册账号" });

    const user = result.rows[0];
    if (!user.password_hash) {
      return res.status(401).json({ error: "账号未设置密码，请先注册" });
    }
    if (!verifyPassword(data.password, user.password_hash)) {
      return res.status(401).json({ error: "邮箱或密码错误" });
    }

    res.json(formatUser(user));
  } catch (err) {
    res.status(400).json({ error: err.message });
  }
});

app.post("/users", async (req, res) => {
  try {
    const data = userSchema.parse(req.body);
    await ensureUser(data.id, data);
    const user = await pool.query(`SELECT * FROM users WHERE id = $1`, [data.id]);
    res.json(formatUser(user.rows[0]));
  } catch (err) {
    res.status(400).json({ error: err.message });
  }
});

app.get("/users/:id", async (req, res) => {
  const user = await pool.query(`SELECT * FROM users WHERE id = $1`, [req.params.id]);
  if (user.rowCount === 0) return res.status(404).json({ error: "user not found" });
  res.json(formatUser(user.rows[0]));
});

app.get("/leaderboard", async (req, res) => {
  const limit = Number(req.query.limit ?? 20);
  const rows = await pool.query(
    `
      SELECT id, name, department, avatar, total_score, win_count, match_count
      FROM users
      ORDER BY total_score DESC, win_count DESC
      LIMIT $1
    `,
    [limit]
  );
  const entries = rows.rows.map((row, idx) => ({
    id: row.id,
    name: row.name ?? "",
    department: row.department ?? "",
    avatar: row.avatar ?? "",
    totalScore: row.total_score ?? 0,
    winCount: row.win_count ?? 0,
    matchCount: row.match_count ?? 0,
    rank: idx + 1,
  }));
  res.json(entries);
});

app.post("/activities", async (req, res) => {
  try {
    const requester = req.headers["x-user-id"];
    if (!requester || typeof requester !== "string") {
      return res.status(401).json({ error: "missing x-user-id" });
    }
    const admin = await pool.query(`SELECT is_admin FROM users WHERE id = $1`, [requester]);
    if (admin.rowCount === 0 || admin.rows[0].is_admin !== true) {
      return res.status(403).json({ error: "forbidden: admin only" });
    }

    console.log("POST /activities headers:", req.headers);
    console.log("POST /activities rawBody:", req.rawBody);
    console.log("POST /activities parsed body:", req.body);

    const body =
      typeof req.body === "string"
        ? JSON.parse(req.body || "{}")
        : req.body && Object.keys(req.body).length === 0 && req.rawBody
        ? JSON.parse(req.rawBody || "{}")
        : req.body;
    const payload = activitySchema.parse(body);
    const id = uuid();
    await pool.query(
      `
        INSERT INTO activities (id, title, start_time, end_time, location, court_count, allow_single, allow_double, description, max_participants)
        VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10)
      `,
      [
        id,
        payload.title,
        payload.startTime ?? null,
        payload.endTime ?? null,
        payload.location ?? null,
        payload.courtCount ?? 0,
        payload.allowSingle ?? true,
        payload.allowDouble ?? true,
        payload.description ?? null,
        payload.maxParticipants ?? null,
      ]
    );
    const created = await pool.query(
      `
        SELECT a.*, COUNT(s.id) AS signup_count
        FROM activities a
        LEFT JOIN signups s ON s.activity_id = a.id
        WHERE a.id = $1
        GROUP BY a.id
      `,
      [id]
    );
    res.status(201).json(mapActivity(created.rows[0]));
  } catch (err) {
    res.status(400).json({ error: err.message });
  }
});

app.get("/activities", async (_req, res) => {
  const result = await pool.query(
    `
      SELECT a.*, COUNT(s.id) AS signup_count
      FROM activities a
      LEFT JOIN signups s ON s.activity_id = a.id
      GROUP BY a.id
      ORDER BY a.start_time DESC
    `
  );
  res.json(result.rows.map(mapActivity));
});

// 获取某个用户可发起积分申请的活动：
// 1）该用户已报名该活动
// 2）活动已结束
// 3）该用户从未在该活动的任何积分申请中出现（无论是发起人、队友还是对手）
app.get("/activities/eligible-for-score", async (req, res) => {
  try {
    const userId = req.query.userId;
    if (!userId || typeof userId !== "string") {
      return res.status(400).json({ error: "userId is required" });
    }

    const result = await pool.query(
      `
        SELECT a.*, COUNT(s_all.id) AS signup_count
        FROM activities a
        -- 该用户必须报名过该活动
        JOIN signups s_user
          ON s_user.activity_id = a.id
         AND s_user.user_id = $1
        -- 统计总报名人数
        LEFT JOIN signups s_all
          ON s_all.activity_id = a.id
        -- 该用户在该活动中从未参与过任何积分申请（发起/队友/对手）
        WHERE NOT EXISTS (
          SELECT 1
          FROM score_requests sr
          WHERE sr.activity_id = a.id
            AND (
              sr.initiator_id = $1
              OR sr.teammate_id = $1
              OR sr.opponent_ids LIKE '%' || $1 || '%'
            )
        )
        GROUP BY a.id
        ORDER BY a.start_time DESC
      `,
      [userId]
    );

    // 只保留状态为 ended 的活动
    const activities = result.rows.map(mapActivity).filter((a) => a.status === "ended");
    res.json(activities);
  } catch (err) {
    res.status(400).json({ error: err.message });
  }
});

app.get("/activities/:id", async (req, res) => {
  const row = await pool.query(
    `
      SELECT a.*, COUNT(s.id) AS signup_count
      FROM activities a
      LEFT JOIN signups s ON s.activity_id = a.id
      WHERE a.id = $1
      GROUP BY a.id
    `,
    [req.params.id]
  );
  if (row.rowCount === 0) return res.status(404).json({ error: "not found" });
  res.json(mapActivity(row.rows[0]));
});

app.post("/activities/:id/signup", async (req, res) => {
  try {
    const activityId = req.params.id;
    const activityRow = await pool.query(
      `
        SELECT a.*, COUNT(s.id) AS signup_count
        FROM activities a
        LEFT JOIN signups s ON s.activity_id = a.id
        WHERE a.id = $1
        GROUP BY a.id
      `,
      [activityId]
    );
    if (activityRow.rowCount === 0) return res.status(404).json({ error: "activity not found" });

    const payload = signupSchema.parse(req.body);
    await ensureUser(payload.userId);

    const signupCount = Number(activityRow.rows[0].signup_count ?? 0);
    const maxP = activityRow.rows[0].max_participants;
    if (maxP && signupCount >= maxP) {
      return res.status(409).json({ error: "activity full" });
    }

    await pool.query(
      `
        INSERT INTO signups (id, activity_id, user_id)
        VALUES ($1, $2, $3)
        ON CONFLICT (activity_id, user_id) DO NOTHING
      `,
      [uuid(), activityId, payload.userId]
    );
    const updated = await pool.query(
      `
        SELECT a.*, COUNT(s.id) AS signup_count
        FROM activities a
        LEFT JOIN signups s ON s.activity_id = a.id
        WHERE a.id = $1
        GROUP BY a.id
      `,
      [activityId]
    );
    res.json({ ok: true, activity: mapActivity(updated.rows[0]) });
  } catch (err) {
    res.status(400).json({ error: err.message });
  }
});

app.delete("/activities/:id/signup", async (req, res) => {
  try {
    const activityId = req.params.id;
    const payload = signupSchema.parse(req.body);

    const activityRow = await pool.query(`SELECT id FROM activities WHERE id = $1`, [activityId]);
    if (activityRow.rowCount === 0) return res.status(404).json({ error: "activity not found" });

    await pool.query(`DELETE FROM signups WHERE activity_id = $1 AND user_id = $2`, [activityId, payload.userId]);

    const updated = await pool.query(
      `
        SELECT a.*, COUNT(s.id) AS signup_count
        FROM activities a
        LEFT JOIN signups s ON s.activity_id = a.id
        WHERE a.id = $1
        GROUP BY a.id
      `,
      [activityId]
    );

    res.json({ ok: true, activity: mapActivity(updated.rows[0]) });
  } catch (err) {
    res.status(400).json({ error: err.message });
  }
});

app.get("/activities/:id/signups", async (req, res) => {
  if (!(await validateActivityExists(req.params.id))) {
    return res.status(404).json({ error: "activity not found" });
  }
  const rows = await pool.query(
    `
      SELECT s.user_id, u.name, u.department, u.avatar, s.created_at
      FROM signups s
      LEFT JOIN users u ON u.id = s.user_id
      WHERE s.activity_id = $1
      ORDER BY s.created_at ASC
    `,
    [req.params.id]
  );
  res.json(
    rows.rows.map((row) => ({
      userId: row.user_id,
      name: row.name ?? "",
      department: row.department ?? "",
      avatar: row.avatar ?? "",
      createdAt: row.created_at,
    }))
  );
});

app.post("/group-matches", async (req, res) => {
  try {
    const data = groupSchema.parse(req.body);
    if (!(await validateActivityExists(data.activityId))) {
      return res.status(404).json({ error: "activity not found" });
    }
    if (data.matchType === "single" && data.playerIds.length !== 2) {
      return res.status(400).json({ error: "single match requires 2 players" });
    }
    if (data.matchType === "double" && data.playerIds.length !== 4) {
      return res.status(400).json({ error: "double match requires 4 players" });
    }
    await Promise.all(data.playerIds.map((id) => ensureUser(id)));
    await pool.query(
      `
        INSERT INTO group_matches (id, activity_id, court_no, match_type, player_ids)
        VALUES ($1, $2, $3, $4, $5)
      `,
      [uuid(), data.activityId, data.courtNo, data.matchType, JSON.stringify(data.playerIds)]
    );
    const rows = await pool.query(
      `SELECT * FROM group_matches WHERE activity_id = $1 ORDER BY court_no ASC, created_at ASC`,
      [data.activityId]
    );
    res.status(201).json(rows.rows.map(formatGroup));
  } catch (err) {
    res.status(400).json({ error: err.message });
  }
});

app.get("/activities/:id/groups", async (req, res) => {
  if (!(await validateActivityExists(req.params.id))) {
    return res.status(404).json({ error: "activity not found" });
  }
  const rows = await pool.query(
    `SELECT * FROM group_matches WHERE activity_id = $1 ORDER BY court_no ASC, created_at ASC`,
    [req.params.id]
  );
  res.json(rows.rows.map(formatGroup));
});

app.post("/score-requests", async (req, res) => {
  try {
    const data = scoreRequestSchema.parse(req.body);
    const activity = await pool.query(`SELECT * FROM activities WHERE id = $1`, [data.activityId]);
    if (activity.rowCount === 0) return res.status(404).json({ error: "activity not found" });

    // 校验：只有参加过该活动的人员之间才能发起积分申请
    const signupRows = await pool.query(
      `SELECT user_id FROM signups WHERE activity_id = $1`,
      [data.activityId]
    );
    const participants = new Set(signupRows.rows.map((r) => r.user_id));

    // 检查发起人是否参加过活动
    if (!participants.has(data.initiatorId)) {
      return res
        .status(403)
        .json({ error: "只有参加过该活动的人员才能发起积分申请" });
    }

    // 检查队友和对手是否都参加过活动
    const relatedUserIds = [
      ...(data.teammateId ? [data.teammateId] : []),
      ...data.opponentIds,
    ];
    const notJoined = relatedUserIds.filter((uid) => !participants.has(uid));
    if (notJoined.length > 0) {
      return res.status(403).json({
        error: "只有参加过该活动的人员之间才能相互发起积分申请",
      });
    }

    if (data.type === "single" && data.opponentIds.length !== 1) {
      return res.status(400).json({ error: "单打需要 1 名对手" });
    }
    if (data.type === "double") {
      if (!data.teammateId) return res.status(400).json({ error: "双打需要队友" });
      if (data.opponentIds.length !== 2) return res.status(400).json({ error: "双打需要 2 名对手" });
    }

    // 限制：同一用户在同一活动中，每种类型（单打/双打）仅能各发起一次
    const dup = await pool.query(
      `SELECT 1 FROM score_requests WHERE activity_id = $1 AND initiator_id = $2 AND type = $3`,
      [data.activityId, data.initiatorId, data.type]
    );
    if (dup.rowCount > 0) return res.status(409).json({ error: "已存在该类型申请" });

    const pending = [...(data.teammateId ? [data.teammateId] : []), ...data.opponentIds].filter(Boolean);

    await Promise.all(
      [data.initiatorId, data.teammateId, ...data.opponentIds.filter(Boolean)].map((uid) =>
        uid ? ensureUser(uid) : null
      )
    );

    const id = uuid();
    await pool.query(
      `
        INSERT INTO score_requests
          (id, activity_id, type, initiator_id, teammate_id, opponent_ids, winner_score, loser_score, status, pending_confirmations, confirmed_by)
        VALUES ($1, $2, $3, $4, $5, $6, $7, $8, 'pending', $9, '')
      `,
      [
        id,
        data.activityId,
        data.type,
        data.initiatorId,
        data.teammateId ?? null,
        data.opponentIds.join(","),
        data.winnerScore,
        data.loserScore,
        pending.join(","),
      ]
    );
    res.status(201).json({ id, status: "pending" });
  } catch (err) {
    res.status(400).json({ error: err.message });
  }
});

app.get("/score-requests", async (req, res) => {
  const activityId = req.query.activityId;
  if (!activityId) return res.status(400).json({ error: "activityId is required" });
  if (!(await validateActivityExists(activityId))) return res.status(404).json({ error: "activity not found" });
  const rows = await pool.query(`SELECT * FROM score_requests WHERE activity_id = $1 ORDER BY created_at DESC`, [
    activityId,
  ]);
  res.json(rows.rows.map(formatScoreRequest));
});

app.get("/score-requests/pending", async (req, res) => {
  try {
    const userId = req.query.userId;
    if (!userId) return res.status(400).json({ error: "userId is required" });
    
    // 获取所有待确认或部分确认的积分申请
    // 用户需要确认的条件：在 pending_confirmations 列表中
    const rows = await pool.query(
      `
        SELECT * FROM score_requests
        WHERE status IN ('pending', 'confirming')
          AND pending_confirmations LIKE '%' || $1 || '%'
        ORDER BY created_at DESC
      `,
      [userId]
    );
    
    // 过滤出真正包含该用户的待确认列表
    const filtered = rows.rows.filter((row) => {
      const pending = computePending(row.pending_confirmations);
      return pending.includes(userId);
    });

    if (filtered.length === 0) {
      return res.json([]);
    }

    // ------- 批量补充活动名称和用户姓名，用于前端展示 -------
    const activityIds = Array.from(new Set(filtered.map((r) => r.activity_id)));
    const allUserIdsSet = new Set();
    for (const r of filtered) {
      if (r.initiator_id) allUserIdsSet.add(r.initiator_id);
      if (r.teammate_id) allUserIdsSet.add(r.teammate_id);
      const opponents = computePending(r.opponent_ids);
      for (const oid of opponents) {
        if (oid) allUserIdsSet.add(oid);
      }
    }
    const allUserIds = Array.from(allUserIdsSet);

    const [activityRows, userRows] = await Promise.all([
      pool.query(`SELECT id, title FROM activities WHERE id = ANY($1::text[])`, [activityIds]),
      allUserIds.length > 0
        ? pool.query(`SELECT id, name, department FROM users WHERE id = ANY($1::text[])`, [allUserIds])
        : { rows: [] },
    ]);

    const activityMap = new Map(activityRows.rows.map((r) => [r.id, r]));
    const userMap = new Map(userRows.rows.map((r) => [r.id, r]));

    const enriched = filtered.map((row) => {
      const base = formatScoreRequest(row);
      const opponents = base.opponentIds || [];
      return {
        ...base,
        activityTitle: activityMap.get(base.activityId)?.title || "",
        initiatorName: userMap.get(base.initiatorId)?.name || base.initiatorId,
        teammateName: base.teammateId ? userMap.get(base.teammateId)?.name || base.teammateId : undefined,
        opponentsDetail: opponents.map((oid) => ({
          id: oid,
          name: userMap.get(oid)?.name || oid,
          department: userMap.get(oid)?.department || "",
        })),
      };
    });
    
    res.json(enriched);
  } catch (err) {
    res.status(400).json({ error: err.message });
  }
});

app.post("/score-requests/:id/confirm", async (req, res) => {
  try {
    const { userId, accept } = confirmSchema.parse(req.body);
    const srResult = await pool.query(`SELECT * FROM score_requests WHERE id = $1`, [req.params.id]);
    if (srResult.rowCount === 0) return res.status(404).json({ error: "not found" });
    const sr = srResult.rows[0];
    if (sr.status === "finished" || sr.status === "rejected") {
      return res.status(409).json({ error: "已结束" });
    }

    const result = await withTransaction(async (client) => {
      if (!accept) {
        await client.query(`UPDATE score_requests SET status='rejected', updated_at=NOW() WHERE id = $1`, [sr.id]);
        return { status: "rejected" };
      }

      const pending = computePending(sr.pending_confirmations);
      if (!pending.includes(userId)) {
        throw new Error("无待确认权限");
      }
      const newPending = pending.filter((p) => p !== userId);
      const confirmed = computePending(sr.confirmed_by);
      confirmed.push(userId);

      if (newPending.length > 0) {
        await client.query(
          `
            UPDATE score_requests
            SET pending_confirmations = $1, confirmed_by = $2, status='confirming', updated_at=NOW()
            WHERE id = $3
          `,
          [newPending.join(","), confirmed.join(","), sr.id]
        );
        return { status: "confirming" };
      }

      await client.query(
        `
          UPDATE score_requests
          SET pending_confirmations = '', confirmed_by = $1, status='finished', updated_at=NOW()
          WHERE id = $2
        `,
        [confirmed.join(","), sr.id]
      );

      const opponentIds = computePending(sr.opponent_ids);
      const participantIds = new Set([sr.initiator_id, ...opponentIds]);
      if (sr.type === "double" && sr.teammate_id) {
        participantIds.add(sr.teammate_id);
      }
      const allIds = Array.from(participantIds);

      // 如果旧数据中没有比分，则回退到原有的简单积分规则（兼容历史记录）
      if (sr.winner_score == null || sr.loser_score == null) {
        for (const uid of participantIds) {
          await addScore(client, {
            userId: uid,
            activityId: sr.activity_id,
            scoreRequestId: sr.id,
            score: 1,
            reason: "participation",
            incrementMatch: true,
          });
        }

        if (sr.type === "single") {
          await addScore(client, {
            userId: sr.initiator_id,
            activityId: sr.activity_id,
            scoreRequestId: sr.id,
            score: 5,
            reason: "single_win",
            incrementWin: true,
          });
        } else if (sr.teammate_id) {
          for (const uid of [sr.initiator_id, sr.teammate_id]) {
            await addScore(client, {
              userId: uid,
              activityId: sr.activity_id,
              scoreRequestId: sr.id,
              score: 3,
              reason: "double_win",
              incrementWin: true,
            });
          }
        }

        return { status: "finished" };
      }

      // 新规则：基于赛前积分、单双打类型与比分进行精细结算
      const usersResult = await client.query(
        `SELECT id, total_score FROM users WHERE id = ANY($1::text[])`,
        [allIds]
      );
      const preScores = new Map(usersResult.rows.map((row) => [row.id, row.total_score ?? 0]));

      const winnerIds =
        sr.type === "single"
          ? [sr.initiator_id]
          : sr.teammate_id
          ? [sr.initiator_id, sr.teammate_id]
          : [sr.initiator_id];

      const loserIds = opponentIds;

      const { points, details } = computeMatchPoints({
        type: sr.type,
        preScores,
        winnerIds,
        loserIds,
        winnerScore: sr.winner_score,
        loserScore: sr.loser_score,
      });

      for (const uid of allIds) {
        const delta = points.get(uid) ?? 0;
        const isWinner = winnerIds.includes(uid);
        const detail = details.get(uid) ?? null;
        await addScore(client, {
          userId: uid,
          activityId: sr.activity_id,
          scoreRequestId: sr.id,
          score: delta,
          reason: "match_score",
          incrementWin: isWinner,
          incrementMatch: true,
          detail,
        });
      }

      return { status: "finished" };
    });

    res.json(result);
  } catch (err) {
    res.status(400).json({ error: err.message });
  }
});

app.post("/score-requests/:id/reject", async (req, res) => {
  try {
    const { userId } = confirmSchema.parse(req.body);
    const srResult = await pool.query(`SELECT * FROM score_requests WHERE id = $1`, [req.params.id]);
    if (srResult.rowCount === 0) return res.status(404).json({ error: "not found" });
    const sr = srResult.rows[0];
    if (sr.status === "finished" || sr.status === "rejected") {
      return res.status(409).json({ error: "已结束" });
    }

    const pending = computePending(sr.pending_confirmations);
    if (!pending.includes(userId)) {
      return res.status(403).json({ error: "无待确认权限" });
    }

    await pool.query(`UPDATE score_requests SET status='rejected', updated_at=NOW() WHERE id = $1`, [sr.id]);
    res.json({ status: "rejected" });
  } catch (err) {
    res.status(400).json({ error: err.message });
  }
});

app.get("/score-logs", async (req, res) => {
  const userId = req.query.userId;
  const limit = Number(req.query.limit ?? 50);
  if (!userId) return res.status(400).json({ error: "userId is required" });
  const rows = await pool.query(
    `SELECT * FROM score_logs WHERE user_id = $1 ORDER BY created_at DESC LIMIT $2`,
    [userId, limit]
  );
  res.json(rows.rows.map(formatScoreLog));
});

// 积分记录详情（用于前端积分记录 item 跳转）
app.get("/score-logs/:id", async (req, res) => {
  try {
    const logId = req.params.id;
    const row = await pool.query(`SELECT * FROM score_logs WHERE id = $1`, [logId]);
    if (row.rowCount === 0) {
      return res.status(404).json({ error: "log not found" });
    }
    const log = row.rows[0];

    // 补充活动和用户信息，便于前端展示
    const [activityRows, userRows] = await Promise.all([
      pool.query(`SELECT id, title FROM activities WHERE id = $1`, [log.activity_id]),
      pool.query(`SELECT id, name, department FROM users WHERE id = $1`, [log.user_id]),
    ]);

    const activity = activityRows.rows[0] || null;
    const user = userRows.rows[0] || null;

    const base = {
      ...formatScoreLog(log),
      activityTitle: activity?.title ?? "",
      userName: user?.name ?? "",
      userDepartment: user?.department ?? "",
    };

    // 如果该积分来源于某条积分申请，附带该积分申请的完整信息（只读展示用）
    if (!log.score_request_id) {
      return res.json(base);
    }

    const srResult = await pool.query(`SELECT * FROM score_requests WHERE id = $1`, [
      log.score_request_id,
    ]);
    if (srResult.rowCount === 0) {
      return res.json(base);
    }
    const sr = srResult.rows[0];

    const opponents = computePending(sr.opponent_ids);
    const allUserIds = [
      sr.initiator_id,
      sr.teammate_id,
      ...opponents,
    ].filter(Boolean);

    const usersForSr =
      allUserIds.length > 0
        ? await pool.query(
            `SELECT id, name, department FROM users WHERE id = ANY($1::text[])`,
            [allUserIds]
          )
        : { rows: [] };
    const userMap = new Map(usersForSr.rows.map((r) => [r.id, r]));

    const scoreRequest = {
      ...formatScoreRequest(sr),
      activityTitle: activity?.title ?? "",
      initiatorName: userMap.get(sr.initiator_id)?.name || sr.initiator_id,
      teammateName: sr.teammate_id
        ? userMap.get(sr.teammate_id)?.name || sr.teammate_id
        : undefined,
      opponentsDetail: opponents.map((oid) => ({
        id: oid,
        name: userMap.get(oid)?.name || oid,
        department: userMap.get(oid)?.department || "",
      })),
    };

    res.json({
      ...base,
      scoreRequest,
    });
  } catch (err) {
    res.status(400).json({ error: err.message });
  }
});

app.get("/users/:id/summary", async (req, res) => {
  const userId = req.params.id;
  const user = await pool.query(`SELECT * FROM users WHERE id = $1`, [userId]);
  if (user.rowCount === 0) return res.status(404).json({ error: "user not found" });

  const rank = await getUserRank(userId);
  const recentLogs = await pool.query(
    `SELECT * FROM score_logs WHERE user_id = $1 ORDER BY created_at DESC LIMIT 10`,
    [userId]
  );

  // 本月积分与月度排名（用于“月度 MVP”成就判断）
  const monthlyAgg = await pool.query(
    `
      SELECT user_id,
             SUM(score) AS month_score,
             RANK() OVER (ORDER BY SUM(score) DESC) AS month_rank
      FROM score_logs
      WHERE created_at >= date_trunc('month', NOW())
      GROUP BY user_id
    `
  );
  const selfMonth = monthlyAgg.rows.find((r) => r.user_id === userId);
  const monthlyScore = selfMonth ? Number(selfMonth.month_score) : 0;
  const monthlyRank = selfMonth ? Number(selfMonth.month_rank) : null;
  const isMonthlyMvp = monthlyRank === 1 && monthlyScore > 0;

  // 终身单打/双打胜场数与排行榜名次（含老规则和新 match_score 规则）
  const winAgg = await pool.query(
    `
      WITH per_user AS (
        SELECT
          sl.user_id,
          COUNT(*) FILTER (
            WHERE sl.score > 0
              AND (
                sl.reason = 'single_win'
                OR (sl.reason = 'match_score' AND sr.type = 'single')
              )
          ) AS single_wins,
          COUNT(*) FILTER (
            WHERE sl.score > 0
              AND (
                sl.reason = 'double_win'
                OR (sl.reason = 'match_score' AND sr.type = 'double')
              )
          ) AS double_wins
        FROM score_logs sl
        LEFT JOIN score_requests sr ON sl.score_request_id = sr.id
        GROUP BY sl.user_id
      )
      SELECT
        user_id,
        single_wins,
        double_wins,
        RANK() OVER (ORDER BY single_wins DESC) AS single_rank,
        RANK() OVER (ORDER BY double_wins DESC) AS double_rank
      FROM per_user
    `
  );
  const selfWins = winAgg.rows.find((r) => r.user_id === userId) || {
    single_wins: 0,
    double_wins: 0,
    single_rank: null,
    double_rank: null,
  };
  const singleWinCount = Number(selfWins.single_wins ?? 0);
  const doubleWinCount = Number(selfWins.double_wins ?? 0);
  const singleWinRank = selfWins.single_rank != null ? Number(selfWins.single_rank) : null;
  const doubleWinRank = selfWins.double_rank != null ? Number(selfWins.double_rank) : null;
  // 单双精通：单打胜场榜和双打胜场榜同时进入前三（且胜场 > 0）
  const isSingleDoubleMaster =
    singleWinRank !== null &&
    doubleWinRank !== null &&
    singleWinRank <= 3 &&
    doubleWinRank <= 3 &&
    singleWinCount > 0 &&
    doubleWinCount > 0;

  const profile = formatUser(user.rows[0]);
  const matchCount = profile.matchCount || 0;
  const winCount = profile.winCount || 0;
  const winRate = matchCount > 0 ? Math.round((winCount / matchCount) * 100) : 0;

  res.json({
    profile,
    rank,
    isMonthlyMvp,
    isSingleDoubleMaster,
    stats: {
      winRate,
      monthlyScore,
      monthlyRank,
      singleWinCount,
      doubleWinCount,
      singleWinRank,
      doubleWinRank,
    },
    recentScoreLogs: recentLogs.rows.map(formatScoreLog),
  });
});

// ---------- Formatters ----------
function formatGroup(row) {
  return {
    id: row.id,
    activityId: row.activity_id,
    courtNo: row.court_no,
    matchType: row.match_type,
    playerIds: JSON.parse(row.player_ids || "[]"),
    createdAt: row.created_at,
  };
}

function formatScoreRequest(row) {
  return {
    id: row.id,
    activityId: row.activity_id,
    type: row.type,
    initiatorId: row.initiator_id,
    teammateId: row.teammate_id || undefined,
    opponentIds: computePending(row.opponent_ids),
    winnerScore: row.winner_score ?? undefined,
    loserScore: row.loser_score ?? undefined,
    status: row.status,
    createdAt: row.created_at,
    pendingConfirmations: computePending(row.pending_confirmations),
    confirmedBy: computePending(row.confirmed_by),
  };
}

function formatScoreLog(row) {
  return {
    id: row.id,
    userId: row.user_id,
    activityId: row.activity_id,
    score: row.score,
    reason: row.reason,
    createdAt: row.created_at,
    detail: row.detail || null,
  };
}

async function getUserRank(userId) {
  const result = await pool.query(
    `
      SELECT id,
             RANK() OVER (ORDER BY total_score DESC, win_count DESC) AS rank
      FROM users
    `
  );
  const found = result.rows.find((r) => r.id === userId);
  return found ? Number(found.rank) : null;
}

// 管理员手动将活动置为结束
app.post("/activities/:id/end", async (req, res) => {
  try {
    const requester = req.headers["x-user-id"];
    if (!requester || typeof requester !== "string") {
      return res.status(401).json({ error: "missing x-user-id" });
    }

    const admin = await pool.query(`SELECT is_admin FROM users WHERE id = $1`, [requester]);
    if (admin.rowCount === 0 || admin.rows[0].is_admin !== true) {
      return res.status(403).json({ error: "forbidden: admin only" });
    }

    const activityId = req.params.id;
    const result = await pool.query(
      `
        UPDATE activities
        SET force_ended = TRUE,
            end_time = COALESCE(end_time, NOW())
        WHERE id = $1
        RETURNING *
      `,
      [activityId]
    );

    if (result.rowCount === 0) {
      return res.status(404).json({ error: "activity not found" });
    }

    // 返回更新后的活动信息（包含当前报名人数）
    const updated = await pool.query(
      `
        SELECT a.*, COUNT(s.id) AS signup_count
        FROM activities a
        LEFT JOIN signups s ON s.activity_id = a.id
        WHERE a.id = $1
        GROUP BY a.id
      `,
      [activityId]
    );

    res.json(mapActivity(updated.rows[0]));
  } catch (err) {
    res.status(400).json({ error: err.message });
  }
});

// ---------- Bootstrapping ----------
migrate()
  .then(() => {
    app.listen(PORT, () => {
      console.log(`backend listening on :${PORT}`);
    });
  })
  .catch((err) => {
    console.error("migration failed", err);
    process.exit(1);
  });

