# 加密备份服务（支持主密钥在线轮换与密钥卷灾难恢复）

基于 Flask + SQLite + `cryptography` 的小型备份页：上传小文件加密备份、下载还原原件，
支持主密钥（KEK）的发起轮换、进度查看和旧密钥移除，并在密钥卷丢失后通过**恢复凭据**
把备份卷上仍完好的密文重新登记到全新的密钥卷上。

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

## 3. 灾难恢复：密钥卷丢失后的凭据导入（重点）

适用场景：`keystore` 卷（主密钥 + SQLite 元数据）丢失，但 `backup-volumes` 卷上的
密文正文 `*.blob` 仍然完好。

### 3.1 凭据里有什么

在备份页对**单份**备份点"下载恢复凭据"并设置口令，得到一个口令加密的独立文件：

```
MAGIC | version | PBKDF2 salt(16B) | iterations(4B) | nonce(12B)
      | AES-256-GCM( JSON{ 备份ID, 文件名, 大小, SHA-256, 创建时间, DEK(base64) } )
```

- 口令经 **PBKDF2-HMAC-SHA256（600000 次迭代）** 派生 256 位密钥；凭据头（magic/
  版本/salt/迭代次数）作为 GCM AAD 绑定，篡改任何一个字节都会认证失败。
- 凭据**只含该备份自己的 DEK 与登记元数据，不含任何主密钥（KEK）**：泄露一份凭据
  不影响其他备份，新密钥卷也不需要任何旧 KEK。
- 每份备份独立导出、独立导入。

### 3.2 导入时的三重认证与登记规则

换上新密钥卷后，在备份页上传凭据并输入口令，后台恢复任务依次保证：

1. **凭据认证**：PBKDF2 派生 + GCM 认证；口令错误或文件损坏直接失败，不产生任何登记。
2. **原卷密文认证**：用凭据解出的 DEK，对 `备份ID.blob` 做流式 AES-GCM 解密，
   `backup_id` 作为 AAD；密文被篡改则 GCM tag 校验失败。
3. **原文摘要核对**：流式解密同时累计 SHA-256，必须与凭据内记录的摘要、大小一致。

三者全部通过后，才按**原编号、原文件名**写入 `backups`，并用**登记生效那一刻的活动
主密钥**重新包装 DEK（写一行新的 `wrapped_keys`），原下载链接随之恢复。原卷密文
**逐字节保留、不重写**；任何一步失败，库中现有登记保持原样。

| 需求 | 实现方式 |
| --- | --- |
| 一次导入最多读一遍密文 | 顺序流式读取：先读 12B nonce、尾部读 16B tag，中间密文区仅顺序读一次，分块解密 |
| 低内存并发 | 只保留 256 KiB 分块、增量哈希和字节计数，绝不整体缓冲明文/密文；4×15 MiB 并发实测峰值约 72 MiB RSS |
| 校验期间上传/下载/轮换照常 | 每个导入在独立守护线程，且不持有 `_write_lock` 读取；暂停只阻塞该任务自己的 `Event`，不影响其他请求与轮换 worker |
| 只用登记时的主密钥包装 | 登记事务内读取当前 active KEK 包装 DEK；旧 KEK 不参与，轮换后旧钥仍可按原规则移除 |
| 重传同一凭据返回原编号 | 登记前按原编号查重：摘要一致则幂等返回原编号、不重复建行；并发下靠主键 `IntegrityError` 兜底 |
| 原编号被他人占用 | 摘要不一致时任务置 `conflict`，页面提示"编号已被另一份备份登记占用"，现有登记不动 |

### 3.3 恢复任务状态

任务状态保存在进程内存（重启后可再次上传同一凭据，导入本身幂等），通过页面轮询或
JSON API 查看：

- `GET /recovery/imports`：任务列表；`GET /recovery/imports/<job_id>`：单个任务进度
  （`running / completed / failed / conflict`、已读字节/总字节、是否幂等）。
- `POST /recovery/imports/<job_id>/pause|resume`：暂停/恢复某一份导入的流式读取；
  暂停期间其余导入、小文件上传下载和主密钥轮换都不等待它。

## 4. 快速开始（Docker Compose）

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
| `RECOVERY_CHUNK_KB` | `256` | 恢复导入流式解密的分块大小（KB） |

容器通过 compose 的 `mem_limit: 160m` 限定 160 MiB；恢复导入全程流式处理，
4 份各 15 MiB 的旧备份并发导入实测峰值约 72 MiB RSS。

## 5. 本地开发

```bash
python3 -m venv --without-pip .venv        # 若系统没有 ensurepip
.venv/bin/python get-pip.py                # 自行引导 pip 后
.venv/bin/pip install -r requirements.txt
KEYSTORE_DIR=./data/keystore VOLUME_DIR=./data/volumes \
  .venv/bin/python -m backup_app.wsgi
```

## 6. 测试

```bash
.venv/bin/python -I tests/test_service.py        # 17 个服务层测试
.venv/bin/python -I tests/test_web.py            # 6 个 HTTP 集成测试（含真实后台 worker）
.venv/bin/python -I tests/test_recovery.py       # 14 个恢复凭据/灾难恢复服务层测试
.venv/bin/python -I tests/test_recovery_web.py   # 8 个恢复流程 HTTP 集成测试
```

覆盖：加解密往返、DEK 独立性、密文篡改拒绝、轮换不改 blob、中途上传只挂新 KEK、
模拟进程崩溃后续跑、幂等 tick、移除保护、密钥粉碎、两代轮换后旧密钥全删仍可恢复、
密钥卷与备份卷材料互斥；以及恢复凭据的口令错误/篡改拒绝、三重认证（凭据 GCM、
密文 GCM、原文 SHA-256）、按原编号/文件名登记、密文只读一遍与流式内存上限、
重传幂等、编号冲突、4 份并发且其中一份读一半暂停时其余三份与上传/下载/轮换照常完成。

## 7. 目录结构

```
backup_app/
  config.py      # 环境变量配置
  crypto.py      # AES-256-GCM、DEK 包装/解包、AAD 绑定
  recovery.py    # 口令加密恢复凭据（PBKDF2+GCM）与流式密文认证/摘要校验
  db.py          # SQLite 连接与表结构
  keystore.py    # 主密钥文件生成/加载/粉碎（0600、原子写）
  service.py     # 上传/下载/轮换/移除/凭据导出导入的全部业务规则
  worker.py      # 后台轮换线程（无自身状态，全部从 SQLite 恢复）
  web.py         # Flask 路由与控制台
  wsgi.py        # 入口
  templates/     # 单页控制台（含恢复任务进度轮询）
tests/           # 单元 + HTTP 集成测试
Dockerfile
docker-compose.yml
```

## 8. 运维注意事项

- **平时就为每份备份下载恢复凭据并离线保管**：这是 `keystore` 卷丢失后唯一的恢复
  途径；凭据由口令加密，请使用强口令并与备份卷分开存放。
- 丢失 `keystore` 卷后，只要 `backup-volumes` 卷上的 `*.blob` 还在，挂载全新空密钥卷
  启动服务，再逐份上传凭据即可恢复原编号与下载链接；导入不重写、不删除原密文。
- 恢复导入只在内存里维护任务状态，重启容器不会自动续跑；对同一份凭据重新上传即可，
  已完成的登记按原编号幂等处理，不会产生重复行。
- 移除旧 KEK 前请确认数据库已另行备份；移除操作会覆写并删除密钥文件，不可撤销。
- 升级镜像/重启容器不影响轮换：任务在数据库里，重启自动续跑。
- 本服务未内置鉴权，生产环境应放在网关/内网鉴权之后，或自行增加登录中间件。
