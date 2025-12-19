const { Pool } = require("pg");
const crypto = require("crypto");

const pool = new Pool({
  connectionString: process.env.DATABASE_URL,
  max: 10,
  idleTimeoutMillis: 30_000,
});

async function migrate() {
  const client = await pool.connect();
  try {
    await client.query("BEGIN");
    await client.query(`
      CREATE TABLE IF NOT EXISTS users (
        id TEXT PRIMARY KEY,
        name TEXT,
        department TEXT,
        avatar TEXT,
        total_score INTEGER DEFAULT 0,
        win_count INTEGER DEFAULT 0,
        match_count INTEGER DEFAULT 0,
        is_admin BOOLEAN DEFAULT FALSE,
        created_at TIMESTAMPTZ DEFAULT NOW()
      );

      -- auth fields
      ALTER TABLE users ADD COLUMN IF NOT EXISTS password_hash TEXT;

      CREATE TABLE IF NOT EXISTS activities (
        id TEXT PRIMARY KEY,
        title TEXT NOT NULL,
        start_time TIMESTAMPTZ,
        end_time TIMESTAMPTZ,
        location TEXT,
        court_count INTEGER DEFAULT 0,
        allow_single BOOLEAN DEFAULT TRUE,
        allow_double BOOLEAN DEFAULT TRUE,
        description TEXT,
        max_participants INTEGER,
        created_at TIMESTAMPTZ DEFAULT NOW()
      );

      -- 补充旧库中可能缺失的列
      ALTER TABLE activities
        ADD COLUMN IF NOT EXISTS force_ended BOOLEAN DEFAULT FALSE;

      CREATE TABLE IF NOT EXISTS signups (
        id TEXT PRIMARY KEY,
        activity_id TEXT NOT NULL REFERENCES activities(id) ON DELETE CASCADE,
        user_id TEXT NOT NULL REFERENCES users(id) ON DELETE CASCADE,
        created_at TIMESTAMPTZ DEFAULT NOW(),
        UNIQUE(activity_id, user_id)
      );

      CREATE TABLE IF NOT EXISTS group_matches (
        id TEXT PRIMARY KEY,
        activity_id TEXT NOT NULL REFERENCES activities(id) ON DELETE CASCADE,
        court_no INTEGER NOT NULL,
        match_type TEXT CHECK (match_type IN ('single','double')) NOT NULL,
        player_ids TEXT NOT NULL,
        created_at TIMESTAMPTZ DEFAULT NOW()
      );

      CREATE TABLE IF NOT EXISTS score_requests (
        id TEXT PRIMARY KEY,
        activity_id TEXT NOT NULL REFERENCES activities(id) ON DELETE CASCADE,
        type TEXT CHECK (type IN ('single','double')) NOT NULL,
        initiator_id TEXT NOT NULL REFERENCES users(id) ON DELETE CASCADE,
        teammate_id TEXT REFERENCES users(id) ON DELETE CASCADE,
        opponent_ids TEXT NOT NULL,
        status TEXT CHECK (status IN ('pending','confirming','finished','rejected')) DEFAULT 'pending',
        pending_confirmations TEXT NOT NULL,
        confirmed_by TEXT NOT NULL DEFAULT '',
        created_at TIMESTAMPTZ DEFAULT NOW(),
        updated_at TIMESTAMPTZ DEFAULT NOW()
      );

      -- 兼容旧库的 score_requests 表：补充比分相关列
      ALTER TABLE score_requests
        ADD COLUMN IF NOT EXISTS winner_score INTEGER;
      ALTER TABLE score_requests
        ADD COLUMN IF NOT EXISTS loser_score INTEGER;

      CREATE TABLE IF NOT EXISTS score_logs (
        id TEXT PRIMARY KEY,
        user_id TEXT NOT NULL REFERENCES users(id) ON DELETE CASCADE,
        activity_id TEXT NOT NULL REFERENCES activities(id) ON DELETE CASCADE,
        score_request_id TEXT REFERENCES score_requests(id) ON DELETE CASCADE,
        score INTEGER NOT NULL,
        -- reason 保留旧值以兼容历史数据，同时新增 match_score 作为“整场对局结算结果”
        reason TEXT NOT NULL,
        -- 额外说明信息（JSON），用于前端展示积分拆解（基础分/比分差/爆冷/保护等）
        detail JSONB,
        created_at TIMESTAMPTZ DEFAULT NOW(),
        UNIQUE(user_id, activity_id, reason)
      );

      CREATE INDEX IF NOT EXISTS idx_activities_start_time ON activities(start_time);
      CREATE INDEX IF NOT EXISTS idx_score_requests_activity ON score_requests(activity_id);
      CREATE INDEX IF NOT EXISTS idx_score_logs_user ON score_logs(user_id);

      -- 兼容老数据：如果缺少 score_request_id 列则补上
      ALTER TABLE score_logs
        ADD COLUMN IF NOT EXISTS score_request_id TEXT REFERENCES score_requests(id) ON DELETE CASCADE;

      -- 兼容老库：如果缺少 detail 列则补上（用于存储积分拆解说明）
      ALTER TABLE score_logs
        ADD COLUMN IF NOT EXISTS detail JSONB;

      -- 兼容老库中 score_logs.reason 的 CHECK 约束，扩展允许的取值
      DO $$
      BEGIN
        IF EXISTS (
          SELECT 1
          FROM information_schema.table_constraints
          WHERE table_name = 'score_logs'
            AND constraint_type = 'CHECK'
            AND constraint_name = 'score_logs_reason_check'
        ) THEN
          ALTER TABLE score_logs DROP CONSTRAINT score_logs_reason_check;
        END IF;
      END$$;

      ALTER TABLE score_logs
        ADD CONSTRAINT score_logs_reason_check
        CHECK (reason IN ('single_win','double_win','participation','match_score'));
    `);
    await client.query("COMMIT");
  } catch (err) {
    await client.query("ROLLBACK");
    throw err;
  } finally {
    client.release();
  }
}

async function withTransaction(fn) {
  const client = await pool.connect();
  try {
    await client.query("BEGIN");
    const result = await fn(client);
    await client.query("COMMIT");
    return result;
  } catch (err) {
    await client.query("ROLLBACK");
    throw err;
  } finally {
    client.release();
  }
}

async function addScore(
  client,
  {
    userId,
    activityId,
    scoreRequestId = null,
    score,
    reason,
    incrementWin = false,
    incrementMatch = false,
    detail = null,
  }
) {
  await client.query(
    `
      INSERT INTO score_logs (id, user_id, activity_id, score_request_id, score, reason, detail)
      VALUES ($1, $2, $3, $4, $5, $6, $7)
      ON CONFLICT (user_id, activity_id, reason) DO NOTHING
    `,
    [crypto.randomUUID(), userId, activityId, scoreRequestId, score, reason, detail]
  );

  await client.query(
    `
      UPDATE users
      SET total_score = total_score + $1,
          win_count = win_count + $2,
          match_count = match_count + $3
      WHERE id = $4
    `,
    [score, incrementWin ? 1 : 0, incrementMatch ? 1 : 0, userId]
  );
}

function mapActivity(row) {
  if (!row) return null;
  const now = Date.now();
  const startMs = row.start_time ? Date.parse(row.start_time) : NaN;
  const endMs = row.end_time ? Date.parse(row.end_time) : NaN;
  let status = "upcoming";
  if (row.force_ended === true) {
    // 管理员手动结束，优先级最高
    status = "ended";
  } else if (!Number.isNaN(startMs) && now >= startMs) {
    status = !Number.isNaN(endMs) && now > endMs ? "ended" : "ongoing";
  }

  return {
    id: row.id,
    title: row.title,
    startTime: row.start_time || null,
    endTime: row.end_time || null,
    location: row.location,
    courtCount: row.court_count ?? 0,
    allowSingle: !!row.allow_single,
    allowDouble: !!row.allow_double,
    description: row.description,
    status,
    signupCount: Number(row.signup_count ?? 0),
    maxParticipants: row.max_participants ?? null,
  };
}

module.exports = {
  pool,
  migrate,
  withTransaction,
  addScore,
  mapActivity,
};

