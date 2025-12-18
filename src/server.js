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

    // 活动级别限制：已经存在过积分申请（发起中 / 确认中 / 已完成）的活动，不能再次发起积分申请
    const existingByActivity = await pool.query(
      `
        SELECT 1
        FROM score_requests
        WHERE activity_id = $1
          AND status IN ('pending', 'confirming', 'finished')
        LIMIT 1
      `,
      [data.activityId]
    );
    if (existingByActivity.rowCount > 0) {
      return res.status(409).json({
        error: "该活动已存在积分申请或已完成积分确认，不能再次发起积分申请",
      });
    }

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
          (id, activity_id, type, initiator_id, teammate_id, opponent_ids, status, pending_confirmations, confirmed_by)
        VALUES ($1, $2, $3, $4, $5, $6, 'pending', $7, '')
      `,
      [id, data.activityId, data.type, data.initiatorId, data.teammateId ?? null, data.opponentIds.join(","), pending.join(",")]
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

  const profile = formatUser(user.rows[0]);
  const matchCount = profile.matchCount || 0;
  const winCount = profile.winCount || 0;
  const winRate = matchCount > 0 ? Math.round((winCount / matchCount) * 100) : 0;

  res.json({
    profile,
    rank,
    stats: {
      winRate,
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

