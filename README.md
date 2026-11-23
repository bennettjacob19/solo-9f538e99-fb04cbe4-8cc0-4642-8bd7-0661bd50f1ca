# 加密备份服务（支持主密钥在线轮换）

基于 Flask + SQLite + `cryptography` 的小型备份页：上传小文件加密备份、下载还原原件，
并支持主密钥（KEK）的发起轮换、进度查看和旧密钥移除。

## 1. 密码学模型：信封加密

```
明文文件 ──AES-256-GCM(DEK)──► 密文正文 blob（备份卷，只存密文）
每份备份独立 DEK（32 字节随机）
DEK ──AES-256-GCM(KEK)──► wrapped_dek（SQLite，密钥卷）
主密钥 KEK（32 字节随机，0600 权限文件，密钥卷）
```

- **每份备份一个独立数据密钥 DEK**，互不相同；相同明文产出的密文也不同。
- **主密钥与备份分卷保存**：
  - `keystore` 卷：主密钥文件 `*.kek` + SQLite 元数据库（含被包装的 DEK）
  - `backup-volumes` 卷：只有密文正文 `*.blob`，拿走此卷无法解密
- GCM nonce 为 12 字节随机数并前置；包装 DEK 时以 `backup_id + kek_id` 作为 AAD 绑定，
  防止包装记录被挪动复用；正文 blob 以 `backup_id` 作为 AAD。
- 下载还原后会校验 SHA-256，密文被篡改时 GCM 认证直接失败。

## 2. 轮换语义（重点）

| 需求 | 实现方式 |
| --- | --- |
| 轮换不重写正文密文 | 轮换只把 DEK 用新 KEK **重新包装**（新增一行 `wrapped_keys`），blob 文件字节不变 |
| 上传/恢复无需等轮换结束 | 上传走当前 active KEK；下载会尝试该备份所有可用 KEK 的包装，任一可用即可还原 |
| 轮换启动后的新备份只用新 KEK 恢复 | 轮换启动即把新 KEK 置为 active、旧 KEK 置 retired，新上传只写新 KEK 包装，且不计入轮换总数 |
| 进程中断后能继续 | 轮换进度全部持久化在 `rotation_jobs` / `wrapped_keys`；新进程启动后后台 worker 自动续跑同一任务，重包装按 `(backup_id, kek_id)` 唯一索引幂等 |
| 全部备份可用新 KEK 恢复后才允许移除旧 KEK | `remove_key` 强校验：active 不可删、有 running 轮换不可删、存在"仅依赖该 KEK"的备份不可删；通过后先删元数据再粉碎密钥文件 |

### 轮换的状态机

1. `POST /rotations`：生成新 KEK 文件并置 active，旧 KEK 置 retired，创建 `running` 任务，
   任务总量 = 启动那一刻挂在旧 KEK 下的备份数。
2. 后台 `RotationWorker` 每 `ROTATION_INTERVAL` 秒取一批（`ROTATION_BATCH` 个）尚未获得
   新 KEK 包装的备份：用旧 KEK 解开 DEK → 用新 KEK 重新包装 → 写新包装 → 更新进度。
3. 当所有旧 KEK 下的备份都有了新 KEK 包装，任务置 `completed`（旧包装保留，直到显式移除旧 KEK）。
4. 控制台对已退役且可安全移除的 KEK 显示"移除并粉碎"按钮；移除时覆写+删除密钥文件。

## 3. 快速开始（Docker Compose）

```bash
docker compose up --build
# 打开 http://localhost:8000
```

两个命名卷分别承载密钥/元数据与密文正文，见 `docker-compose.yml`：

```yaml
volumes:
  keystore:          # /data/keystore：*.kek 主密钥 + backup.db
  backup-volumes:    # /data/volumes：*.blob 密文正文
```

健康检查：`GET /healthz`。

### 环境变量

| 变量 | 默认值 | 说明 |
| --- | --- | --- |
| `KEYSTORE_DIR` | `/data/keystore` | 主密钥文件与 SQLite 目录 |
| `VOLUME_DIR` | `/data/volumes` | 密文 blob 目录 |
| `DB_PATH` | `$KEYSTORE_DIR/backup.db` | SQLite 路径 |
| `ROTATION_INTERVAL` | `1` | 后台轮换轮询秒数 |
| `ROTATION_BATCH` | `10` | 每个 tick 重包装的备份数 |
| `MAX_UPLOAD_MB` | `16` | 单文件上传上限（MB） |

## 4. 本地开发

```bash
python3 -m venv --without-pip .venv        # 若系统没有 ensurepip
.venv/bin/python get-pip.py                # 自行引导 pip 后
.venv/bin/pip install -r requirements.txt
KEYSTORE_DIR=./data/keystore VOLUME_DIR=./data/volumes \
  .venv/bin/python -m backup_app.wsgi
```

## 5. 测试

```bash
.venv/bin/python -I tests/test_service.py   # 17 个服务层测试
.venv/bin/python -I tests/test_web.py       # 6 个 HTTP 集成测试（含真实后台 worker）
```

覆盖：加解密往返、DEK 独立性、密文篡改拒绝、轮换不改 blob、中途上传只挂新 KEK、
模拟进程崩溃后续跑、幂等 tick、移除保护、密钥粉碎、两代轮换后旧密钥全删仍可恢复、
密钥卷与备份卷材料互斥。

## 6. 目录结构

```
backup_app/
  config.py      # 环境变量配置
  crypto.py      # AES-256-GCM、DEK 包装/解包、AAD 绑定
  db.py          # SQLite 连接与表结构
  keystore.py    # 主密钥文件生成/加载/粉碎（0600、原子写）
  service.py     # 上传/下载/轮换/移除的全部业务规则
  worker.py      # 后台轮换线程（无自身状态，全部从 SQLite 恢复）
  web.py         # Flask 路由与控制台
  wsgi.py        # 入口
  templates/     # 单页控制台
tests/           # 单元 + HTTP 集成测试
Dockerfile
docker-compose.yml
```

## 7. 运维注意事项

- **备份密钥卷**：丢失 `keystore` 卷即永久无法解密；备份卷泄露不构成明文泄露。
- 移除旧 KEK 前请确认数据库已另行备份；移除操作会覆写并删除密钥文件，不可撤销。
- 升级镜像/重启容器不影响轮换：任务在数据库里，重启自动续跑。
- 本服务未内置鉴权，生产环境应放在网关/内网鉴权之后，或自行增加登录中间件。
