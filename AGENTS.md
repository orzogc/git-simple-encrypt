---
description: coding
mode: primary
temperature: 0
---

# 行为准则

你是一个资深 Rust 工程师，注重代码可维护性和性能优化，并且遵循 Rust 工程开发的最佳实践

- 少造轮子，如果有合适的第三方库就用
- 少写重复代码，多抽离出可复用的组件，并考虑向后扩展性
  - 你应该使用在编译期就能进行错误检查的设计，而不是推到运行期检查，例如多用枚举，不用硬编码。
- 单测、集成测试需要"少而精"，不要对过于简单的部分写太多单测，易错部分要多写
- 不要删除代码中运行逻辑相关的关键注释
- 使用简体中文进行交流；在代码中使用英文注释

## 项目要求

- 「单密码对称加密」这一底层逻辑不允许改变
- 所有变更都需要兼容 major version 内的之前版本
- 注意 lib API 的密钥语义**不对称**（易错点）：加密入口（`encrypt_file`/`encrypt_into` 等）接受 **Argon2 派生密钥**，解密入口（`decrypt_file`/`decrypt_into` 等）接受**原始密码**（内部用头部 salt 自行派生）。详见 `src/crypt/mod.rs` 模块文档 "Key Semantics" 一节。

## 仓库操作安全约束（不可回退的不变量）

- 加密列表是**显式允许列表**：遍历目标文件时禁止应用任何 ignore 规则（`.gitignore`/`.ignore`/全局 exclude），列表中的文件必须被加密与检查；遍历错误必须上报，不得 fail-open
- 所有文件操作必须限制在仓库根目录内：`add` 与 `encrypt`/`decrypt`/`check` 的路径参数都要拒绝 `..` 逃逸与中间符号链接逃逸（canonicalize 后双侧比较）
- 永远不得加密 `.git` 内部内容与 `git_simple_encrypt.toml` 自身（所有入口共享 `validate_repo_relative`/`validate_target_root` 校验，`.git` 按大小写不敏感比较）；**解析后的 git 目录**（`--separate-git-dir` 可将其置于工作区内任意名称下）与 `.git` 同等受保护：`ProtectedDirs` 穿线到目标校验、递归遍历剪枝、`CryptPolicy` 匹配、stale-file sweep 与 journal 恢复；**嵌套仓库**采用两阶段保护：打开仓库时先扫描发现嵌套 git dir（`.git` 目录、`.git` 指针文件——限长读取 fail-closed、目标 canonicalize 且经结构验证后才生效、伪造/失效 pointer 不保护任何路径；bare 仓库按严格 HEAD+objects/+refs/ 结构识别，遍历根自身豁免），合并为不可变 `ProtectedDirs` 供目标校验、遍历剪枝、`CryptPolicy` 匹配、sweep 与 journal 恢复共享（嵌套工作区普通文件仍在范围内）
- **禁止以任何形式持久化密码或其派生值**（明文、hash、加密 verifier 等一律不允许）；密码每次使用时交互输入（禁止回显）或取自 `GIT_SE_PASSWORD` 环境变量，内存中以 `Zeroizing` 包裹；git 子进程一律 `env_remove(GIT_SE_PASSWORD)`
- 密码一致性验证只能以 `HEAD` 中已提交的密文为锚点（`verify_password_against_head`，候选取自**整个** crypt list，任一成功即 Match），无锚点时静默放行；意外改密必须被拦截（交互确认或 `--allow-password-change`）；`--allow-password-change` 置位时必须对**整个 crypt list** 范围做单密码校验（每个已加密文件都要能用给定密码完整认证），禁止制造 `git-se p` 无法修复的混合密码状态
- `check --staged` 必须检查 **index 中的 blob**（`git show :<path>`），绝不用工作区文件代替
- 原子写：临时文件 fsync 后再 rename，目标目录 rename 后 best-effort fsync；事务关键路径（备份落盘、目标替换、journal 写入与删除）必须用 `sync_dir_strict`，同步失败即中止
- 事务 journal 只记录 worktree 相对路径并严格解析（未知版本/截断/越界/含 `.git` 组件或解析后 git 目录内路径一律 fail-closed 保留；绝对路径须先词法规范化消解 `..` 再验边界）；恢复失败、journal 损坏或 **journal 不可读**（仅 `NotFound` 表示无事务，其余读取错误一律 `JournalUnreadable`）时 `Repo::open` 必须报错，禁止任何命令在混合状态下运行；恢复用**复制**还原目标且不消耗 backup（"journal 存在 ⇒ 其引用的 backup 全部存在"是不变量，backup 只在 journal 删除或重写后才允许删除）；HEAD 密码锚点验证按 distinct salt 计 Argon2 预算（默认 8，`GIT_SE_HEAD_ANCHOR_BUDGET` 可显式提高），超限 fail-closed（`PasswordVerificationIndeterminate`），不得返回 Mismatch/Unverifiable；**工作区目标同样按 distinct salt 计预算**（默认 64，`GIT_SE_SALT_BUDGET` 可显式提高），在任何针对目标的 Argon2 发生之前 fail-closed（`SaltBudgetExceeded`）；同时用信号量限制 Argon2 并发度（≤4）以约束内存峰值；探测分类统一含 framing 检查（`probe_and_rewind`/`probe_file` 一致），安全决策使用严格探测（I/O 错误与 Malformed 一律报错，绝不折叠为明文）
- git dir 一律通过 `git rev-parse --absolute-git-dir` / `--git-common-dir` 解析（兼容 worktree/submodule），不要硬编码 `<repo>/.git`
- salt cache：只用 rkyv 安全 API（owned 反序列化，禁止 mmap/unsafe）；读写须经 fd-lock 咨询锁保护

## 加密核心算法

### 1. 密钥派生

- 程序通过 Argon2 算法结合文件的 16B Salt 派生出 32B 的 Master Key，再通过 `blake3::derive_key` 拆分为两个独立密钥，用于 XChaCha20-Poly1305 加密 + 计算每个分块的 Nonce。
  - 利用 `DashMap<Salt, Arc<OnceLock>>` 缓存已派生的密钥，减少重复 Argon2 运算。

### 2. 头部结构

每个加密文件都包含一个标准头部（64 字节）：

```text
 00          04  05  06  07           17                  27              3F
 +-----------+---+---+---+-----------+-------------------+---------------+
 |   MAGIC   | V | F | A |   SALT    |      FILE_ID      |   RESERVED    |
 |  "GITSE"  |   |   |   | (16 bytes)|    (16 bytes)     |  (24 bytes)   |
 +-----------+---+---+---+-----------+-------------------+---------------+
      |        |   |   |
      |        |   |   +--- 加密算法 (1 = XChaCha20-Poly1305)
      |        |   +------- 压缩标志位 (Bit 0: 是否 Zstd 压缩)
      |        +----------- 版本号 (当前为 4)
      +-------------------- 魔数
```

- FILE_ID：每次加密新文件时随机生成的 16 字节标识符，用于 Nonce 派生。

### 3. 加密逻辑

- 算法： 文件被切分为 64KB 的块，使用 XChaCha20-Poly1305 进行加密。
- Nonce 派生： 每个 chunk 的 nonce 覆盖该块的**完整 AEAD 输入**（组装完毕的 AAD + 当前块明文），通过带密钥的 Blake3 哈希计算：`Nonce_i = Blake3_keyed(Key_MAC, AAD_i || M_i)[0..24]`。不变量：除可忽略的 PRF 碰撞概率外，nonce 重复 ⟺ (AAD, 明文) 完全重复（即逐字节一致的重加密，无害）；任何前缀块变化都会使后续所有块的 nonce 重新随机化。
- AAD（v4 链）： 完整的 64B HEADER + 前一块的 Poly1305 tag（16B；第 0 块以 FILE_ID 作为链种子）+ chunk_idx (8B) + is_last_chunk (1B)，共 89B。链式 AAD 使跨版本同位置重放必然坍缩为整文件回退（H-04 修复）。
- 存储格式： 每个加密分块的物理结构为 `[NONCE (24B)] [CIPHERTEXT (<= 64KB)] [Poly1305 TAG (16B)]`，Nonce 存储在分块头部。

```mermaid
sequenceDiagram
    participant F as 原始文件 (Disk)
    participant M as 内存缓冲区 (64KB)
    participant E as 加密引擎 (XChaCha20-Poly1305)
    participant T as 临时文件 (TempFile)

    F->>M: 1. 读取 64KB 数据
    M->>M: 2. Zstd 压缩 (可选)
    Note over M,E: Blake3_keyed(Key_MAC, AAD_i || 明文) → Nonce_i
    M->>E: 3. 使用 Key_ENC + Nonce_i 加密，加入 AAD
    E->>T: 4. 写入 Nonce_i (24B) + 密文 + Tag
    loop 持续处理直至 EOF
        F->>T: 循环上述流程
    end
    T->>T: 5. 复制元数据 (Permissions/Timestamps)
    T->>F: 6. 原子覆写
```

解密：从文件读取 24 字节作为 `Nonce_i`，读取后续的密文 + Tag，直接调用 XChaCha20-Poly1305 解密。

### 4. 确定性重加密（Salt + File_ID 缓存）

为保证 decrypt -> encrypt 循环对相同文件产生完全相同的密文，程序将每个文件的 Salt 和 File_ID 持久化在每个 worktree 各自 git 目录（`git rev-parse --absolute-git-dir`，普通仓库即 `.git/`）下的 `git-simple-encrypt-salt-cache` 中。

- 加密（只读缓存）：通过 rkyv 安全 API 反序列化为 owned HashMap（无 mmap、无 unsafe）。
- 解密（写入缓存）：Rayon 线程通过 mpsc channel 发送 `(path, salt, file_id)`，主线程收集后通过 rkyv 序列化，并原子写入到磁盘，与已有缓存合并。
  - 缓存 key 使用仓库相对路径的原始字节（`/` 作为分隔符），确保跨平台一致性。
  - 只有在解密完全成功后才会写入缓存条目，失败的尝试不会污染缓存。
  - 缓存读写由 fd-lock 咨询锁保护，防止跨进程丢失条目。
