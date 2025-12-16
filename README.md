# badminton_score_backend

轻量级 Express + PostgreSQL 后端，支撑羽毛球积分系统的活动、报名、积分和排行榜功能。

## 快速开始
```bash
cd badminton_score_backend
npm install
# 开发热重载
npm run dev
# 生产/直接启动
npm start
```

### 必需环境变量
- `DATABASE_URL`：PostgreSQL 连接串（含库名，例如 `postgres://user:pass@localhost:5432/badminton`）。

### 可选环境变量
- `PORT`：服务端口，默认 `4000`
- `CORS_ORIGINS`：逗号分隔的白名单，默认 `*`
- `ADMIN_EMAILS`：逗号分隔的管理员邮箱，默认 `guoke@foryou56.com`

## 数据库
- 连接信息来自 `DATABASE_URL`，启动时自动迁移（建表/补列）。
- 主要表：`users`, `activities`, `signups`, `group_matches`, `score_requests`, `score_logs`。

## 核心接口（简略）
- `POST /auth/register`、`POST /auth/login`
- `POST /users`（创建/更新用户，内部 ensure）
- `GET /users/:id/summary`（含最近积分记录、胜率）
- 活动：
  - `POST /activities`（需要 `x-user-id` 且为管理员）
  - `GET /activities`、`GET /activities/:id`
  - 报名：`POST /activities/:id/signup`，取消：`DELETE /activities/:id/signup`
  - 查看报名：`GET /activities/:id/signups`
  - 分组：`POST /group-matches`，`GET /activities/:id/groups`
- 积分申请：
  - `POST /score-requests`，`GET /score-requests?activityId=xxx`
  - 确认：`POST /score-requests/:id/confirm`
- 积分日志：`GET /score-logs?userId=xxx`
- 排行榜：`GET /leaderboard?limit=50`

## 开发提示
- 每次请求需携带 JSON `Content-Type: application/json`。
- 创建活动需要请求头 `x-user-id` 对应管理员账号。
- 启动后自动执行迁移，无需手动跑脚本。

