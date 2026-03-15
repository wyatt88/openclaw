# OpenClaw Federation 部署指南

> **版本**: OpenClaw 2026.3.13+  
> **最后更新**: 2026-03-15  
> **基于真实部署经验**: Ark (Claude Opus 4.6) + Luna (Claude Sonnet 4) 双实例 Federation

---

## 概述

### Federation 是什么

Federation 让多个独立的 OpenClaw 实例建立互信关系，实现跨实例通信。每个实例是一个独立的 AI Agent，有自己的身份、密钥和能力。通过 Federation，这些 Agent 可以：

- 互相发送消息和协作
- 共享特定能力（日历、天气、任务等）
- 形成去中心化的 Web of Trust 信任网络

Federation 支持两种信任模式：

- **Token 互信**（简化模式）：适合内网或可信环境，用 Gateway token 直接认证
- **Ed25519 互信**（高级模式）：非对称加密，每条消息签名，支持信任传递

### 架构图

```
                        ┌─────────────────────────────┐
                        │        互联网 / VPC          │
                        └─────────────────────────────┘
                                    │
              ┌─────────────────────┼─────────────────────┐
              │                     │                     │
    ┌─────────▼─────────┐ ┌────────▼────────┐ ┌──────────▼────────┐
    │  ALB (HTTPS 443)  │ │  ALB (HTTPS 443) │ │  Nginx/Caddy      │
    │  + Cognito Auth   │ │  + Cognito Auth  │ │  + Let's Encrypt  │
    │  + WS 路径绕过     │ │  + WS 路径绕过   │ │  + WebSocket       │
    └─────────┬─────────┘ └────────┬────────┘ └──────────┬────────┘
              │                     │                     │
    ┌─────────▼─────────┐ ┌────────▼────────┐ ┌──────────▼────────┐
    │   Ark 实例         │ │   Luna 实例      │ │   自建实例         │
    │   EC2 t3.large    │ │   EC2 t3.xlarge  │ │   任意服务器        │
    │   Port 18789      │ │   Port 18789     │ │   Port 18789      │
    │   Opus 4.6        │ │   Sonnet 4       │ │   任意模型          │
    │   Instance Role   │ │   Instance Role  │ │   AKSK / API Key  │
    └─────────┬─────────┘ └────────┬────────┘ └──────────┬────────┘
              │                     │                     │
              │        Federation WSS / HTTPS             │
              └──────────────◄────►─┘◄───────────────────►┘
                    Ed25519 签名消息 / Token 认证
```

### 先决条件

| 项目     | 要求                                                   |
| -------- | ------------------------------------------------------ |
| 操作系统 | Amazon Linux 2023 / Ubuntu 22.04+ / macOS 13+          |
| Node.js  | 22.x LTS（推荐 v22.22.0+）                             |
| 内存     | **最低 4GB**（t3.medium），推荐 8GB（t3.large）以上    |
| 网络     | 出站 HTTPS 443，实例间 WSS 可达                        |
| 域名     | HTTPS 域名 + 有效 TLS 证书（Federation 必须用 wss://） |
| AWS      | Bedrock 模型访问权限已开通（如使用 Bedrock）           |

---

## 部署方式

### 方式一：EC2 + Instance Role（推荐用于 AWS 环境）

这是 Ark/Luna 当前使用的方式。EC2 实例通过 IAM Instance Role 自动获取 Bedrock 凭证，免密钥管理。

**适合场景**：AWS 环境、生产部署、多实例

**优点**：

- 无需管理 Access Key，凭证自动轮换
- 与 ALB、Cognito、ACM 等 AWS 服务天然集成
- 安全性最高

### 方式二：任意服务器 + AKSK（通用部署）

适用于非 EC2 环境：本地开发机、其他云厂商 VPS、IDC 服务器。通过 AWS Access Key / Secret Key 访问 Bedrock。

**适合场景**：本地服务器、非 AWS 云、VPS、开发环境

**优点**：

- 不限制运行环境
- 配置简单，快速上手

### 方式三：Docker 部署

使用 Docker Compose 一键启动，适合快速体验或容器化环境。

**适合场景**：快速启动、CI/CD、K8s 集群

**优点**：

- 环境隔离，版本可控
- 一条命令启动

---

## 详细步骤

### 1. 系统准备

#### Amazon Linux 2023 / RHEL 系

```bash
# 更新系统
sudo dnf update -y

# 安装必要工具
sudo dnf install -y git jq htop

# 安装 Node.js 22 (via nvm)
curl -o- https://raw.githubusercontent.com/nvm-sh/nvm/v0.40.1/install.sh | bash
source ~/.bashrc
nvm install 22
nvm alias default 22
node --version  # 应该输出 v22.x.x
```

#### Ubuntu 22.04+ / Debian 系

```bash
# 更新系统
sudo apt update && sudo apt upgrade -y

# 安装必要工具
sudo apt install -y curl git jq

# 安装 Node.js 22 (via nvm)
curl -o- https://raw.githubusercontent.com/nvm-sh/nvm/v0.40.1/install.sh | bash
source ~/.bashrc
nvm install 22
nvm alias default 22
node --version
```

#### macOS

```bash
# 使用 Homebrew
brew install node@22
# 或使用 nvm
curl -o- https://raw.githubusercontent.com/nvm-sh/nvm/v0.40.1/install.sh | bash
nvm install 22
```

#### 网络要求

| 端口  | 方向         | 用途                                   |
| ----- | ------------ | -------------------------------------- |
| 18789 | 入站（内部） | Gateway HTTP + WebSocket（Federation） |
| 18790 | 入站（内部） | Bridge 端口（ALB 可用此端口做 target） |
| 443   | 入站（公网） | HTTPS / WSS（通过反向代理）            |
| 443   | 出站         | AWS Bedrock API / 模型提供商 API       |

---

### 2. 安装 OpenClaw

```bash
# 全局安装
npm install -g openclaw@latest

# 验证安装
openclaw --version
# 输出示例: OpenClaw 2026.3.13 (61d171a)

# 查看安装位置
which openclaw
# /home/ec2-user/.nvm/versions/node/v22.22.0/bin/openclaw
```

---

### 3. 配置文件

配置文件位于 `~/.openclaw/openclaw.json`，使用 JSON5 格式（支持注释和尾逗号）。

#### 3.1 基础配置（EC2 Instance Role 方式）

适用于 AWS EC2 环境，IAM Role 已附加到实例。

**第一步：创建 IAM Role 并附加到 EC2**

```bash
# 创建 IAM 角色（如果还没有）
aws iam create-role --role-name openclaw-ec2-role \
  --assume-role-policy-document '{
    "Version": "2012-10-17",
    "Statement": [{
      "Effect": "Allow",
      "Principal": {"Service": "ec2.amazonaws.com"},
      "Action": "sts:AssumeRole"
    }]
  }'

# 附加 Bedrock 权限（最小权限见附录 D）
aws iam attach-role-policy --role-name openclaw-ec2-role \
  --policy-arn arn:aws:iam::aws:policy/AmazonBedrockFullAccess

# 创建实例配置文件
aws iam create-instance-profile --instance-profile-name openclaw-ec2-role
aws iam add-role-to-instance-profile \
  --instance-profile-name openclaw-ec2-role \
  --role-name openclaw-ec2-role

# 附加到 EC2 实例
aws ec2 associate-iam-instance-profile \
  --instance-id i-0xxxxxxxxxxxxxxxxx \
  --iam-instance-profile Name=openclaw-ec2-role
```

**第二步：设置环境变量（关键！）**

```bash
# ⚠️ 必须设置 AWS_PROFILE=default，否则 OpenClaw 检测不到 Instance Role 凭证
# OpenClaw 使用环境变量探测 AWS 凭证存在性，Instance Role 通过 IMDS 获取实际凭证
echo 'export AWS_PROFILE=default' >> ~/.bashrc
echo 'export AWS_REGION=us-east-1' >> ~/.bashrc
source ~/.bashrc
```

**第三步：配置文件**

```bash
mkdir -p ~/.openclaw
cat > ~/.openclaw/openclaw.json << 'OCEOF'
{
  // OpenClaw 配置 - EC2 Instance Role 模式
  // 使用 JSON5 格式，支持注释

  // 模型配置
  "models": {
    "providers": {
      "amazon-bedrock": {
        "baseUrl": "https://bedrock-runtime.us-east-1.amazonaws.com",
        "api": "bedrock-converse-stream",
        "auth": "aws-sdk",
        "models": [
          {
            "id": "us.anthropic.claude-opus-4-6-v1:0",
            "name": "Claude Opus 4.6 (Bedrock)",
            "reasoning": true,
            "input": ["text", "image"],
            "cost": { "input": 0, "output": 0, "cacheRead": 0, "cacheWrite": 0 },
            "contextWindow": 200000,
            "maxTokens": 8192
          }
        ]
      }
    },
    "bedrockDiscovery": {
      "enabled": true,
      "region": "us-east-1"
    }
  },

  // Agent 配置
  "agents": {
    "defaults": {
      "model": {
        "primary": "amazon-bedrock/us.anthropic.claude-opus-4-6-v1:0"
      },
      "workspace": "~/.openclaw/workspace",
      "contextTokens": 200000,
      "timeoutSeconds": 600
    }
  },

  // Gateway 配置
  "gateway": {
    "port": 18789,
    "mode": "local",
    "bind": "lan",
    "auth": {
      "mode": "token",
      "token": "YOUR_STRONG_RANDOM_TOKEN_HERE"
    },
    "http": {
      "endpoints": {
        "chatCompletions": { "enabled": true }
      }
    },
    "controlUi": {
      "enabled": true,
      "allowedOrigins": ["https://your-domain.com"],
      "allowInsecureAuth": true
    }
  },

  // Federation 配置（见 3.4 节）
  "federation": {
    "enabled": true,
    "instanceName": "Ark"
  }
}
OCEOF
```

**生成强随机 Token：**

```bash
# 生成 48 字节随机 token
openssl rand -base64 48
# 或
node -e "console.log(require('crypto').randomBytes(48).toString('base64url'))"
```

#### 3.2 AKSK 配置（通用方式）

适用于非 EC2 环境。有三种方式配置 AWS 凭证：

##### 方式 A：环境变量（推荐）

最简单、最通用的方式。

```bash
# 添加到 ~/.bashrc 或 ~/.profile
export AWS_ACCESS_KEY_ID="AKIAIOSFODNN7EXAMPLE"
export AWS_SECRET_ACCESS_KEY="wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY"
export AWS_REGION="us-east-1"

# 如果使用临时凭证（STS AssumeRole），还需要：
# export AWS_SESSION_TOKEN="FwoGZXIvYXdz..."

source ~/.bashrc
```

配置文件和 Instance Role 方式完全相同（`"auth": "aws-sdk"`），SDK 会自动从环境变量获取凭证。

##### 方式 B：AWS CLI Profile（推荐用于多账户）

```bash
# 配置 AWS CLI profile
aws configure --profile openclaw-bedrock
# 按提示输入 Access Key ID, Secret Access Key, Region

# 设置环境变量指向 profile
echo 'export AWS_PROFILE=openclaw-bedrock' >> ~/.bashrc
source ~/.bashrc
```

Profile 存储在 `~/.aws/credentials`：

```ini
[openclaw-bedrock]
aws_access_key_id = AKIAIOSFODNN7EXAMPLE
aws_secret_access_key = wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY
region = us-east-1
```

##### 方式 C：配置文件内联（⚠️ 仅限开发环境）

> **警告**：不推荐在生产环境使用。密钥写在配置文件中容易泄露。

如果实在需要，可以直接在环境中设置后让 AWS SDK 自动读取。**OpenClaw 配置文件本身不直接存储 AKSK**，它通过 `"auth": "aws-sdk"` 让 SDK 走标准的凭证链：

1. 环境变量 `AWS_ACCESS_KEY_ID` / `AWS_SECRET_ACCESS_KEY`
2. `~/.aws/credentials` 文件
3. EC2 Instance Metadata (IMDS)
4. ECS Container Credentials
5. SSO / Web Identity Token

##### IAM 用户最小权限

创建专用 IAM 用户并附加以下策略（见附录 D 完整 JSON）：

```bash
# 创建 IAM 用户
aws iam create-user --user-name openclaw-bedrock-user

# 创建并附加最小权限策略
aws iam put-user-policy --user-name openclaw-bedrock-user \
  --policy-name BedrockMinimalAccess \
  --policy-document '{
    "Version": "2012-10-17",
    "Statement": [
      {
        "Effect": "Allow",
        "Action": [
          "bedrock:InvokeModel",
          "bedrock:InvokeModelWithResponseStream"
        ],
        "Resource": "arn:aws:bedrock:us-east-1::foundation-model/*"
      },
      {
        "Effect": "Allow",
        "Action": "bedrock:ListFoundationModels",
        "Resource": "*"
      }
    ]
  }'

# 创建 Access Key
aws iam create-access-key --user-name openclaw-bedrock-user
# 保存输出的 AccessKeyId 和 SecretAccessKey
```

##### 完整 AKSK 模式配置文件

```bash
cat > ~/.openclaw/openclaw.json << 'OCEOF'
{
  // OpenClaw 配置 - AKSK 模式
  // 确保环境变量已设置: AWS_ACCESS_KEY_ID, AWS_SECRET_ACCESS_KEY, AWS_REGION

  "models": {
    "providers": {
      "amazon-bedrock": {
        "baseUrl": "https://bedrock-runtime.us-east-1.amazonaws.com",
        "api": "bedrock-converse-stream",
        "auth": "aws-sdk",
        "models": [
          {
            "id": "us.anthropic.claude-sonnet-4-20250514",
            "name": "Claude Sonnet 4 (Bedrock)",
            "reasoning": true,
            "input": ["text", "image"],
            "cost": { "input": 0, "output": 0, "cacheRead": 0, "cacheWrite": 0 },
            "contextWindow": 200000,
            "maxTokens": 8192
          }
        ]
      }
    },
    "bedrockDiscovery": {
      "enabled": true,
      "region": "us-east-1"
    }
  },

  "agents": {
    "defaults": {
      "model": {
        "primary": "amazon-bedrock/us.anthropic.claude-sonnet-4-20250514"
      },
      "workspace": "~/.openclaw/workspace",
      "contextTokens": 200000,
      "timeoutSeconds": 600
    }
  },

  "gateway": {
    "port": 18789,
    "mode": "local",
    "bind": "lan",
    "auth": {
      "mode": "token",
      "token": "YOUR_STRONG_RANDOM_TOKEN_HERE"
    },
    "http": {
      "endpoints": {
        "chatCompletions": { "enabled": true }
      }
    },
    "controlUi": {
      "enabled": true,
      "allowedOrigins": ["https://your-domain.com"],
      "allowInsecureAuth": true
    }
  },

  "federation": {
    "enabled": true,
    "instanceName": "MyAgent"
  }
}
OCEOF
```

#### 3.3 Gateway 配置详解

Gateway 是 OpenClaw 的核心服务进程，负责：

- HTTP API（OpenAI 兼容）
- WebSocket 连接（Bridge + Federation）
- Control UI（Web 管理界面）
- 会话管理

关键配置字段：

```json5
{
  gateway: {
    // 监听端口，默认 18789
    port: 18789,

    // 运行模式：必须显式设为 "local"
    // ⚠️ 不设置会导致问题
    mode: "local",

    // 绑定地址：用 "lan" 而不是 "0.0.0.0"
    // "lan" = 绑定所有接口（等同 0.0.0.0），但语义更清晰
    // "loopback" = 仅 127.0.0.1
    bind: "lan",

    // 认证配置
    auth: {
      mode: "token",
      // 生成方法: openssl rand -base64 48
      token: "a-very-long-random-string-please-generate-a-real-one",
    },

    // HTTP API 端点
    http: {
      endpoints: {
        // 启用 OpenAI 兼容的 /v1/chat/completions
        chatCompletions: { enabled: true },
      },
    },

    // Control UI（Web 管理界面）
    controlUi: {
      enabled: true,
      // 允许的 CORS 源
      allowedOrigins: ["https://openclaw.doublewen.cloud"],
      // ⚠️ 如果 ALB 是 HTTPS 但后端是 HTTP，必须开启
      allowInsecureAuth: true,
    },
  },
}
```

#### 3.4 Federation 配置

##### 简化模式（Token 互信）

适合内网部署、快速设置。无需管理密钥。

**实例 A（Ark）的配置：**

```json5
{
  federation: {
    enabled: true,
    instanceName: "Ark",
    // 本实例的公网端点，让对方能连过来
    endpoint: "wss://openclaw.doublewen.cloud/federation",
    peers: [
      {
        name: "Luna",
        endpoint: "wss://luna.doublewen.cloud/federation",
        // Luna 的 Gateway token
        token: "luna-gateway-token-xxx",
        capabilities: ["chat", "weather", "tasks.read"],
      },
    ],
  },
}
```

**实例 B（Luna）的配置：**

```json5
{
  federation: {
    enabled: true,
    instanceName: "Luna",
    endpoint: "wss://luna.doublewen.cloud/federation",
    peers: [
      {
        name: "Ark",
        endpoint: "wss://openclaw.doublewen.cloud/federation",
        // Ark 的 Gateway token
        token: "ark-gateway-token-xxx",
        capabilities: ["chat", "calendar.read"],
      },
    ],
  },
}
```

##### 高级模式（Ed25519 互信）

更安全，适合公网部署。每个实例有独立密钥对，消息都经过签名。

**第一步：启用 Federation 并生成密钥**

```bash
# 在实例 A 上
openclaw federation status
# 首次运行会自动生成 Ed25519 密钥对
# 记录输出的 Public Key
```

**第二步：交换公钥并配置**

```json5
{
  federation: {
    enabled: true,
    instanceName: "Ark",
    // 信任传递设置
    allowIntroductions: true,
    maxTrustDepth: 2,
    // 默认速率限制
    defaultRateLimit: {
      maxMessagesPerMinute: 10,
      maxMessagesPerHour: 100,
      maxMessagesPerDay: 500,
    },
    trustedPeers: [
      {
        name: "Luna",
        // Luna 实例的 Ed25519 公钥（Base64 或 PEM）
        publicKey: "MCowBQYDK2VwAyEA...",
        endpoint: {
          wsUrl: "wss://luna.doublewen.cloud/federation",
          httpUrl: "https://luna.doublewen.cloud",
        },
        capabilities: ["chat", "weather", "tasks.read"],
        rateLimit: {
          maxMessagesPerMinute: 20,
        },
      },
    ],
  },
}
```

##### Federation 配置参考

| 字段                 | 类型    | 默认值       | 说明                           |
| -------------------- | ------- | ------------ | ------------------------------ |
| `enabled`            | boolean | `false`      | 总开关                         |
| `instanceName`       | string  | `"openclaw"` | 握手时显示的名称               |
| `endpoint`           | string  | —            | 本实例的公网 Federation 端点   |
| `peers`              | array   | `[]`         | Token 互信的 peer 列表         |
| `trustedPeers`       | array   | `[]`         | Ed25519 互信的 peer 列表       |
| `defaultRateLimit`   | object  | 10/100/500   | 默认速率限制（分钟/小时/天）   |
| `allowIntroductions` | boolean | `true`       | 允许信任传递                   |
| `maxTrustDepth`      | number  | `2`          | 信任链最大深度（1=仅直接信任） |
| `port`               | number  | Gateway 端口 | Federation 独立端口（可选）    |
| `bind`               | string  | `"loopback"` | 绑定模式                       |

##### 可用能力（Capabilities）

| 能力             | 说明                                |
| ---------------- | ----------------------------------- |
| `chat`           | 发送和接收聊天消息                  |
| `calendar.read`  | 查询日历事件                        |
| `calendar.write` | 创建日历事件                        |
| `weather`        | 查询天气信息                        |
| `location.city`  | 获取城市级位置                      |
| `tasks.read`     | 查询共享任务                        |
| `tasks.write`    | 创建共享任务                        |
| `introduce`      | 向其他 peer 介绍新 peer（信任传递） |

---

### 4. 启动 Gateway

#### 前台运行（调试用）

```bash
openclaw gateway --port 18789
# Gateway 启动需要 10-15 秒（Node.js 初始化），这是正常的
```

#### 后台运行（生产用，不推荐）

```bash
# 创建日志目录
sudo mkdir -p /var/log/openclaw
sudo chown $(whoami):$(whoami) /var/log/openclaw

# 后台启动
nohup node --max-old-space-size=4096 \
  $(dirname $(readlink -f $(which openclaw)))/../lib/node_modules/openclaw/dist/index.js \
  gateway --port 18789 \
  > /var/log/openclaw/gateway.log 2>&1 &

# 记录 PID
echo $! > /var/run/openclaw-gateway.pid
```

#### systemd 服务（推荐）

```bash
# 获取 openclaw 安装路径
OPENCLAW_BIN=$(which openclaw)
OPENCLAW_DIR=$(dirname $(readlink -f $OPENCLAW_BIN))/../lib/node_modules/openclaw
NODE_BIN=$(which node)
CURRENT_USER=$(whoami)

# 创建 systemd unit 文件
sudo tee /etc/systemd/system/openclaw-gateway.service << EOF
[Unit]
Description=OpenClaw Gateway
After=network-online.target
Wants=network-online.target

[Service]
Type=simple
User=${CURRENT_USER}
Group=${CURRENT_USER}
WorkingDirectory=/home/${CURRENT_USER}

# 环境变量
Environment=HOME=/home/${CURRENT_USER}
Environment=NODE_ENV=production
Environment=AWS_PROFILE=default
Environment=AWS_REGION=us-east-1

# 启动命令
ExecStart=${NODE_BIN} --max-old-space-size=4096 ${OPENCLAW_DIR}/dist/index.js gateway --port 18789

# 日志
StandardOutput=append:/var/log/openclaw/gateway.log
StandardError=append:/var/log/openclaw/gateway-error.log

# 进程管理
Restart=on-failure
RestartSec=10
TimeoutStartSec=30
TimeoutStopSec=15

# 资源限制
LimitNOFILE=65535
LimitNPROC=4096

# 安全加固
NoNewPrivileges=true
ProtectSystem=strict
ReadWritePaths=/home/${CURRENT_USER} /var/log/openclaw /tmp

[Install]
WantedBy=multi-user.target
EOF

# 创建日志目录
sudo mkdir -p /var/log/openclaw
sudo chown ${CURRENT_USER}:${CURRENT_USER} /var/log/openclaw

# 启用并启动
sudo systemctl daemon-reload
sudo systemctl enable openclaw-gateway
sudo systemctl start openclaw-gateway

# 检查状态
sudo systemctl status openclaw-gateway
journalctl -u openclaw-gateway -f
```

> **提示**：OpenClaw 也内置了 `openclaw service install` 命令，可以自动生成并注册 systemd 服务。优先使用内置命令，上面的手动方式作为备用。

---

### 5. 反向代理 / 负载均衡

Federation 要求 HTTPS/WSS，所以必须在前面放反向代理。

#### 5.1 AWS ALB 方式（Ark/Luna 使用的方式）

##### 创建安全组

```bash
VPC_ID="vpc-0554f93416396f20c"

# ALB 安全组 - 允许公网 HTTPS
aws ec2 create-security-group \
  --group-name openclaw-alb-sg \
  --description "OpenClaw ALB Security Group" \
  --vpc-id $VPC_ID

ALB_SG_ID=$(aws ec2 describe-security-groups \
  --filters "Name=group-name,Values=openclaw-alb-sg" \
  --query "SecurityGroups[0].GroupId" --output text)

aws ec2 authorize-security-group-ingress \
  --group-id $ALB_SG_ID \
  --protocol tcp --port 443 --cidr 0.0.0.0/0

# EC2 安全组 - 仅允许来自 ALB 的流量
aws ec2 create-security-group \
  --group-name openclaw-ec2-sg \
  --description "OpenClaw EC2 Security Group" \
  --vpc-id $VPC_ID

EC2_SG_ID=$(aws ec2 describe-security-groups \
  --filters "Name=group-name,Values=openclaw-ec2-sg" \
  --query "SecurityGroups[0].GroupId" --output text)

# 允许 ALB 访问 Gateway 端口
aws ec2 authorize-security-group-ingress \
  --group-id $EC2_SG_ID \
  --protocol tcp --port 18789 --source-group $ALB_SG_ID

# 允许 ALB 访问 Bridge 端口（如果使用）
aws ec2 authorize-security-group-ingress \
  --group-id $EC2_SG_ID \
  --protocol tcp --port 18790 --source-group $ALB_SG_ID
```

##### 创建 Target Group

```bash
# 创建 Target Group（指向 Gateway 端口）
aws elbv2 create-target-group \
  --name openclaw-tg \
  --protocol HTTP \
  --port 18789 \
  --vpc-id $VPC_ID \
  --target-type instance \
  --health-check-path /healthz \
  --health-check-protocol HTTP \
  --health-check-interval-seconds 30 \
  --healthy-threshold-count 2 \
  --unhealthy-threshold-count 3

TG_ARN=$(aws elbv2 describe-target-groups \
  --names openclaw-tg \
  --query "TargetGroups[0].TargetGroupArn" --output text)

# 注册 EC2 实例
aws elbv2 register-targets \
  --target-group-arn $TG_ARN \
  --targets Id=i-0xxxxxxxxxxxxxxxxx
```

##### 创建 ALB

```bash
# 获取子网（至少需要 2 个 AZ 的子网）
SUBNET_A="subnet-056e83555976a27a3"
SUBNET_B="subnet-0yyyyyyyyyyyyyyyy"  # 另一个 AZ 的子网

# 创建 ALB
aws elbv2 create-load-balancer \
  --name openclaw-alb \
  --subnets $SUBNET_A $SUBNET_B \
  --security-groups $ALB_SG_ID \
  --scheme internet-facing \
  --type application \
  --ip-address-type ipv4

ALB_ARN=$(aws elbv2 describe-load-balancers \
  --names openclaw-alb \
  --query "LoadBalancers[0].LoadBalancerArn" --output text)

# ⚠️ 关键：调整 ALB idle timeout（默认 60s 太短，WebSocket 会断）
aws elbv2 modify-load-balancer-attributes \
  --load-balancer-arn $ALB_ARN \
  --attributes Key=idle_timeout.timeout_seconds,Value=3600
```

##### 配置 HTTPS Listener + ACM 证书

```bash
# 获取 ACM 证书 ARN（假设已有通配符证书 *.doublewen.cloud）
CERT_ARN=$(aws acm list-certificates \
  --query "CertificateSummaryList[?DomainName=='*.doublewen.cloud'].CertificateArn" \
  --output text)

# 创建 HTTPS listener
aws elbv2 create-listener \
  --load-balancer-arn $ALB_ARN \
  --protocol HTTPS \
  --port 443 \
  --ssl-policy ELBSecurityPolicy-TLS13-1-2-2021-06 \
  --certificates CertificateArn=$CERT_ARN \
  --default-actions Type=forward,TargetGroupArn=$TG_ARN

LISTENER_ARN=$(aws elbv2 describe-listeners \
  --load-balancer-arn $ALB_ARN \
  --query "Listeners[0].ListenerArn" --output text)
```

##### 配置 Cognito 认证（可选但推荐）

```bash
# 获取 Cognito User Pool 信息
POOL_ID="us-east-1_xxxxxxxxx"
POOL_DOMAIN="openclaw-auth"

# 创建 App Client（给 ALB 用，需要 client_secret）
CLIENT_ID=$(aws cognito-idp create-user-pool-client \
  --user-pool-id $POOL_ID \
  --client-name "openclaw-alb-client" \
  --generate-secret \
  --allowed-o-auth-flows code \
  --allowed-o-auth-scopes openid \
  --supported-identity-providers COGNITO \
  --callback-urls "https://openclaw.doublewen.cloud/oauth2/idpresponse" \
  --query "UserPoolClient.ClientId" --output text)

# 修改默认 listener 规则，添加 Cognito 认证
# 注意：这需要更新 listener 的默认 action
# 默认规则：先 Cognito 认证 → 再 forward 到 TG
aws elbv2 modify-listener \
  --listener-arn $LISTENER_ARN \
  --default-actions \
    Type=authenticate-cognito,AuthenticateCognitoConfig="{
      UserPoolArn=arn:aws:cognito-idp:us-east-1:ACCOUNT_ID:userpool/${POOL_ID},
      UserPoolClientId=${CLIENT_ID},
      UserPoolDomain=${POOL_DOMAIN}
    },Order=1" \
    "Type=forward,TargetGroupArn=$TG_ARN,Order=2"
```

##### ⚠️ 关键：WebSocket 路径必须绕过 Cognito

**这是最容易踩的坑。** ALB 的 Cognito 认证会拦截 WebSocket 握手（因为 WS 不带 Cookie），必须为 WS 路径添加直接 forward 规则：

```bash
# 绕过 Cognito 的路径列表：
# /sessions, /sessions/*, /__openclaw__/*, /webhook/*

# 规则 1: /sessions（精确匹配）
aws elbv2 create-rule \
  --listener-arn $LISTENER_ARN \
  --priority 10 \
  --conditions Field=path-pattern,Values="/sessions" \
  --actions Type=forward,TargetGroupArn=$TG_ARN

# 规则 2: /sessions/*
aws elbv2 create-rule \
  --listener-arn $LISTENER_ARN \
  --priority 11 \
  --conditions Field=path-pattern,Values="/sessions/*" \
  --actions Type=forward,TargetGroupArn=$TG_ARN

# 规则 3: /__openclaw__/*
aws elbv2 create-rule \
  --listener-arn $LISTENER_ARN \
  --priority 12 \
  --conditions Field=path-pattern,Values="/__openclaw__/*" \
  --actions Type=forward,TargetGroupArn=$TG_ARN

# 规则 4: /webhook/*
aws elbv2 create-rule \
  --listener-arn $LISTENER_ARN \
  --priority 13 \
  --conditions Field=path-pattern,Values="/webhook/*" \
  --actions Type=forward,TargetGroupArn=$TG_ARN

# 规则 5: /federation/*（Federation WebSocket）
aws elbv2 create-rule \
  --listener-arn $LISTENER_ARN \
  --priority 14 \
  --conditions Field=path-pattern,Values="/federation/*" \
  --actions Type=forward,TargetGroupArn=$TG_ARN

# 规则 6: /healthz（健康检查）
aws elbv2 create-rule \
  --listener-arn $LISTENER_ARN \
  --priority 15 \
  --conditions Field=path-pattern,Values="/healthz" \
  --actions Type=forward,TargetGroupArn=$TG_ARN
```

##### 配置 DNS

```bash
# 获取 ALB DNS 名称
ALB_DNS=$(aws elbv2 describe-load-balancers \
  --names openclaw-alb \
  --query "LoadBalancers[0].DNSName" --output text)

ALB_ZONE=$(aws elbv2 describe-load-balancers \
  --names openclaw-alb \
  --query "LoadBalancers[0].CanonicalHostedZoneId" --output text)

# 在 Route53 创建 CNAME / Alias 记录
# openclaw.doublewen.cloud → ALB DNS
aws route53 change-resource-record-sets \
  --hosted-zone-id YOUR_HOSTED_ZONE_ID \
  --change-batch '{
    "Changes": [{
      "Action": "UPSERT",
      "ResourceRecordSet": {
        "Name": "openclaw.doublewen.cloud",
        "Type": "A",
        "AliasTarget": {
          "HostedZoneId": "'$ALB_ZONE'",
          "DNSName": "'$ALB_DNS'",
          "EvaluateTargetHealth": true
        }
      }
    }]
  }'
```

#### 5.2 Nginx 方式

适合自建服务器。需要安装 Nginx + Certbot。

```bash
# 安装 Nginx + Certbot
sudo apt install -y nginx certbot python3-certbot-nginx
# 或 Amazon Linux:
sudo dnf install -y nginx
sudo pip3 install certbot certbot-nginx

# 申请证书
sudo certbot --nginx -d my-agent.example.com
```

**完整 Nginx 配置（见附录 E）：**

```bash
sudo tee /etc/nginx/sites-available/openclaw << 'EOF'
# OpenClaw Gateway - Nginx 配置
# 适用于单实例部署

# 限速设置（防止滥用）
limit_req_zone $binary_remote_addr zone=openclaw_api:10m rate=30r/m;

# HTTP → HTTPS 重定向
server {
    listen 80;
    server_name my-agent.example.com;
    return 301 https://$host$request_uri;
}

server {
    listen 443 ssl http2;
    server_name my-agent.example.com;

    # TLS 证书（Let's Encrypt）
    ssl_certificate /etc/letsencrypt/live/my-agent.example.com/fullchain.pem;
    ssl_certificate_key /etc/letsencrypt/live/my-agent.example.com/privkey.pem;
    ssl_protocols TLSv1.2 TLSv1.3;
    ssl_ciphers HIGH:!aNULL:!MD5;
    ssl_prefer_server_ciphers on;

    # HSTS
    add_header Strict-Transport-Security "max-age=31536000; includeSubDomains" always;

    # 通用代理头
    proxy_set_header Host $host;
    proxy_set_header X-Real-IP $remote_addr;
    proxy_set_header X-Forwarded-For $proxy_add_x_forwarded_for;
    proxy_set_header X-Forwarded-Proto $scheme;

    # 默认路由 → Gateway
    location / {
        proxy_pass http://127.0.0.1:18789;

        # API 限速
        limit_req zone=openclaw_api burst=10 nodelay;
    }

    # WebSocket 路由（需要特殊头 + 长超时）
    location /sessions {
        proxy_pass http://127.0.0.1:18789;
        proxy_http_version 1.1;
        proxy_set_header Upgrade $http_upgrade;
        proxy_set_header Connection "upgrade";
        proxy_read_timeout 3600s;
        proxy_send_timeout 3600s;
    }

    location /__openclaw__/ {
        proxy_pass http://127.0.0.1:18789;
        proxy_http_version 1.1;
        proxy_set_header Upgrade $http_upgrade;
        proxy_set_header Connection "upgrade";
        proxy_read_timeout 3600s;
        proxy_send_timeout 3600s;
    }

    location /federation/ {
        proxy_pass http://127.0.0.1:18789;
        proxy_http_version 1.1;
        proxy_set_header Upgrade $http_upgrade;
        proxy_set_header Connection "upgrade";
        proxy_read_timeout 3600s;
        proxy_send_timeout 3600s;
    }

    # 健康检查（无需认证）
    location /healthz {
        proxy_pass http://127.0.0.1:18789;
        access_log off;
    }
}
EOF

# 启用站点
sudo ln -sf /etc/nginx/sites-available/openclaw /etc/nginx/sites-enabled/
sudo nginx -t && sudo systemctl reload nginx
```

#### 5.3 Caddy 方式（最简单）

Caddy 自动管理 TLS 证书，零配置 HTTPS + WebSocket。

```bash
# 安装 Caddy
sudo apt install -y debian-keyring debian-archive-keyring apt-transport-https
curl -1sLf 'https://dl.cloudsmith.io/public/caddy/stable/gpg.key' | sudo gpg --dearmor -o /usr/share/keyrings/caddy-stable-archive-keyring.gpg
curl -1sLf 'https://dl.cloudsmith.io/public/caddy/stable/debian.deb.txt' | sudo tee /etc/apt/sources.list.d/caddy-stable.list
sudo apt update && sudo apt install caddy
```

**Caddyfile 配置：**

```bash
sudo tee /etc/caddy/Caddyfile << 'EOF'
my-agent.example.com {
    reverse_proxy localhost:18789
}
EOF

sudo systemctl reload caddy
```

就这么简单。Caddy 自动处理：

- Let's Encrypt 证书申请和续期
- HTTPS 重定向
- WebSocket 代理
- HTTP/2

---

### 6. Federation 配对

三种方式建立 Federation 信任：

#### 6.1 配置文件方式（最直接）

在两个实例的配置文件中互相写入对方信息。

**实例 A 的 `~/.openclaw/openclaw.json`（相关部分）：**

```json5
{
  federation: {
    enabled: true,
    instanceName: "Ark",
    endpoint: "wss://openclaw.doublewen.cloud/federation",
    peers: [
      {
        name: "Luna",
        endpoint: "wss://luna.doublewen.cloud/federation",
        token: "luna-gateway-token",
      },
    ],
  },
}
```

**实例 B 的 `~/.openclaw/openclaw.json`（相关部分）：**

```json5
{
  federation: {
    enabled: true,
    instanceName: "Luna",
    endpoint: "wss://luna.doublewen.cloud/federation",
    peers: [
      {
        name: "Ark",
        endpoint: "wss://openclaw.doublewen.cloud/federation",
        token: "ark-gateway-token",
      },
    ],
  },
}
```

修改配置后重启 Gateway：

```bash
sudo systemctl restart openclaw-gateway
# 或
openclaw gateway call config.apply --params '...'
```

#### 6.2 CLI 配对方式（Ed25519 密钥交换）

更安全的方式，通过 CLI 进行交互式配对。

**在实例 A 上生成配对码：**

```bash
openclaw federation pair --generate --name Ark --capabilities chat,weather
# 输出：
# 🌐 Federation Pairing
# ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
#   Setup Code:  OC-xxxx-xxxx-xxxx-xxxx
#   Instance:    Ark
#   Peer ID:     oc1_a7f3...
#   Endpoint:    http://10.0.132.102:18789
#
#   On the other instance, run:
#   $ openclaw federation pair --code OC-xxxx-xxxx-xxxx-xxxx --url http://10.0.132.102:18789
#
#   Waiting for pairing request... (60s timeout)
```

**在实例 B 上使用配对码：**

```bash
openclaw federation pair \
  --code OC-xxxx-xxxx-xxxx-xxxx \
  --url http://10.0.132.102:18789 \
  --name Luna \
  --capabilities chat,tasks.read

# 输出：
# 🔗 Connecting to http://10.0.132.102:18789...
# 📝 Using setup code: OC-xxxx-xxxx-xxxx-xxxx
#
# ✅ Pairing successful!
#   Peer: Ark (oc1_a7f3...)
#   Capabilities: chat, weather
```

> **注意**：CLI 配对需要两个实例之间网络直连（不经过 ALB/Cognito）。如果两个 EC2 在同一 VPC，可以用内网 IP 直连。

#### 6.3 Web UI 方式

1. 打开 Control UI：`https://openclaw.doublewen.cloud`
2. 进入 **Federation** 面板
3. 点击 **Generate Pairing Code**
4. 将生成的配对码分享给对方
5. 对方在其 Control UI 中输入配对码

---

### 7. 验证

#### 检查 Gateway 健康

```bash
# 本地健康检查
curl -s http://localhost:18789/healthz | jq .
# 期望输出: {"status":"ok",...}

# 通过域名检查
curl -s https://openclaw.doublewen.cloud/healthz | jq .
```

#### 检查 API 可用性

```bash
# 测试 chat completions API
curl -s http://localhost:18789/v1/chat/completions \
  -H "Authorization: Bearer YOUR_GATEWAY_TOKEN" \
  -H "Content-Type: application/json" \
  -d '{
    "model": "amazon-bedrock/us.anthropic.claude-opus-4-6-v1:0",
    "messages": [{"role": "user", "content": "Hello! Reply with one word."}],
    "max_tokens": 50
  }' | jq .choices[0].message.content
```

#### 检查 Federation 状态

```bash
# 查看本地 Federation 身份和 peer 状态
openclaw federation status

# 列出所有已信任的 peer
openclaw federation peers

# 详细信息
openclaw federation peers --verbose
```

#### 跨实例通信测试

```bash
# 从 Ark 向 Luna 发送消息
openclaw federation chat Luna "Hello from Ark! Can you hear me?"

# 检查连接状态（JSON 格式）
openclaw federation status --json | jq '.peers[] | {name, connected, trust}'
```

#### 端到端验证脚本

```bash
#!/bin/bash
# verify-federation.sh - Federation 部署验证脚本

set -e
echo "🔍 OpenClaw Federation 验证"
echo "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━"

# 1. 版本检查
echo -n "1. OpenClaw 版本: "
openclaw --version

# 2. Gateway 健康
echo -n "2. Gateway 健康: "
HTTP_CODE=$(curl -s -o /dev/null -w "%{http_code}" http://localhost:18789/healthz)
if [ "$HTTP_CODE" = "200" ]; then
    echo "✅ OK (HTTP $HTTP_CODE)"
else
    echo "❌ FAIL (HTTP $HTTP_CODE)"
    exit 1
fi

# 3. HTTPS 端点
echo -n "3. HTTPS 端点: "
DOMAIN=${1:-"openclaw.doublewen.cloud"}
HTTP_CODE=$(curl -s -o /dev/null -w "%{http_code}" "https://$DOMAIN/healthz")
if [ "$HTTP_CODE" = "200" ]; then
    echo "✅ OK (https://$DOMAIN)"
else
    echo "❌ FAIL (HTTP $HTTP_CODE from https://$DOMAIN)"
fi

# 4. Federation 状态
echo -n "4. Federation: "
FED_STATUS=$(openclaw federation status --json 2>/dev/null)
TOTAL_PEERS=$(echo "$FED_STATUS" | jq -r '.totalPeers // 0')
CONNECTED=$(echo "$FED_STATUS" | jq -r '.totalConnected // 0')
echo "📊 Peers: $TOTAL_PEERS total, $CONNECTED connected"

# 5. 模型可用性
echo -n "5. Bedrock 模型: "
MODEL_COUNT=$(openclaw models list --json 2>/dev/null | jq 'length // 0')
echo "📊 $MODEL_COUNT 个模型可用"

echo ""
echo "✅ 验证完成"
```

---

### 8. 安全加固

#### Token 管理

```bash
# 生成强随机 token
openssl rand -base64 48

# 定期轮换 token（建议每 90 天）
NEW_TOKEN=$(openssl rand -base64 48)
openclaw config set gateway.auth.token "$NEW_TOKEN"
# 同步更新所有 Federation peer 配置中的 token
```

#### 防火墙规则

```bash
# EC2 安全组最小规则（见附录 F）
# 入站：仅允许 ALB 安全组访问 18789/18790
# 出站：允许 HTTPS 443（Bedrock API）

# 如果使用 iptables（非 AWS 环境）
sudo iptables -A INPUT -p tcp --dport 18789 -s 127.0.0.1 -j ACCEPT
sudo iptables -A INPUT -p tcp --dport 18789 -s REVERSE_PROXY_IP -j ACCEPT
sudo iptables -A INPUT -p tcp --dport 18789 -j DROP
```

#### TLS 要求

- **永远使用 `wss://`**，不要用 `ws://`
- Federation endpoint 必须是 HTTPS
- ALB TLS Policy 至少 `ELBSecurityPolicy-TLS13-1-2-2021-06`

#### Cognito / OAuth2 保护

- Control UI 必须在认证后才能访问
- API 端点通过 Gateway token 保护
- WebSocket 路径需要绕过 Cognito（见 5.1 节），但自身有 token 认证

#### 审计日志

```bash
# 查看 Gateway 日志
tail -f /var/log/openclaw/gateway.log

# Federation 相关日志
grep -i federation /var/log/openclaw/gateway.log

# 如果用 systemd
journalctl -u openclaw-gateway --since "1 hour ago" | grep -i federation
```

---

### 9. 监控与运维

#### 健康检查端点

| 端点         | 方法 | 用途                   |
| ------------ | ---- | ---------------------- |
| `/healthz`   | GET  | 基础健康检查（200=OK） |
| `/v1/models` | GET  | 模型列表（需要 token） |

```bash
# 用于监控系统的健康检查脚本
curl -sf http://localhost:18789/healthz > /dev/null && echo "UP" || echo "DOWN"
```

#### Gateway 日志位置

| 部署方式 | 日志位置                         |
| -------- | -------------------------------- |
| systemd  | `journalctl -u openclaw-gateway` |
| nohup    | `/var/log/openclaw/gateway.log`  |
| Docker   | `docker logs openclaw-gateway`   |
| 前台     | 直接输出到终端                   |

#### 常见问题排查

| 症状                         | 原因                  | 解决方案                                     |
| ---------------------------- | --------------------- | -------------------------------------------- |
| Gateway 启动但无响应         | 初始化中（10-15 秒）  | 等待，这是正常的                             |
| `EACCES: permission denied`  | 端口被占用或权限不足  | `lsof -i :18789` 检查                        |
| 模型列表为空                 | AWS 凭证未检测到      | 检查 `AWS_PROFILE=default`                   |
| WebSocket 连接断开           | ALB idle timeout 太短 | 调到 3600s                                   |
| Cognito 认证循环             | WS 路径未绕过 Cognito | 添加直接 forward 规则                        |
| Federation peer 显示 offline | 网络不通或 token 错误 | 检查双方配置和网络连通性                     |
| OOM Kill                     | 内存不足              | 至少 4GB，推荐用 `--max-old-space-size=4096` |
| `config validation failed`   | 配置文件有误          | `openclaw doctor` 诊断                       |

```bash
# 通用排查命令
openclaw health           # 总体健康状态
openclaw doctor           # 诊断配置问题
openclaw logs --tail 50   # 最近 50 条日志
openclaw status           # Gateway 运行状态
openclaw models list      # 可用模型列表
openclaw federation status # Federation 状态
```

---

## 踩坑记录

> 以下全部来自 Ark + Luna 双实例部署的真实经验。

### 1. 🔴 t3.small (2GB) 内存不够

**现象**：Gateway 启动后几分钟被 OOM Kill，或响应极慢。

**原因**：OpenClaw Gateway（Node.js）+ 模型推理管理 + WebSocket 连接池，静态内存占用约 1.5-2GB。

**解决**：至少用 t3.medium (4GB)。生产环境推荐 t3.large (8GB) 或 t3.xlarge (16GB)。

```bash
# 检查内存使用
free -h
# 如果 available < 1GB，需要升级实例
```

### 2. 🔴 `gateway.mode` 必须显式设为 `"local"`

**现象**：Gateway 行为异常，某些功能不可用。

**原因**：不设置 mode 时默认值可能不是 `local`，导致 Gateway 进入其他运行模式。

**解决**：配置文件中必须显式写 `"mode": "local"`。

### 3. 🟡 `gateway.bind` 要用 `"lan"` 而不是 `"0.0.0.0"`

**现象**：写 `"0.0.0.0"` 配置校验报错。

**原因**：OpenClaw 使用语义化的 bind 值：`"lan"` | `"loopback"` | `"auto"` | `"tailnet"`。不接受原始 IP。

**解决**：用 `"lan"` 代替 `"0.0.0.0"`，效果相同。

### 4. 🔴 ALB 的 WebSocket 路径必须绕过 Cognito

**现象**：Control UI 能打开，但 Agent 会话无法建立。WebSocket 连接 401。

**原因**：Cognito 认证依赖 HTTP Cookie，WebSocket 握手时不会自动带 Cookie。Cognito action 会返回 302 重定向，WS 客户端无法处理。

**解决**：为以下路径添加直接 forward 规则（不经过 Cognito）：

- `/sessions`、`/sessions/*`
- `/__openclaw__/*`
- `/webhook/*`
- `/federation/*`

### 5. 🟡 `openclaw doctor --fix` 会进入交互模式

**现象**：在 SSM Session Manager 中运行 `openclaw doctor --fix` 卡住。

**原因**：`--fix` 模式会弹出交互确认提示，SSM 的伪终端有时处理不好。

**解决**：使用 `openclaw doctor --yes` 代替（自动确认所有修复），或在正常 SSH 终端中操作。

### 6. 🟡 Gateway 启动需要 10-15 秒

**现象**：启动后立即 curl 健康检查返回 connection refused。

**原因**：Node.js 需要加载大量模块、初始化 Zod schema 验证、建立模型连接。这是正常行为。

**解决**：

- 健康检查设置 `start_period: 20s`（Docker/ALB）
- systemd 设置 `TimeoutStartSec=30`
- 脚本中启动后 `sleep 15` 再检查

### 7. 🔴 ALB idle timeout 默认 60s

**现象**：长时间 Agent 对话突然断开，重连后上下文丢失。

**原因**：ALB 默认 60 秒空闲超时，Agent 思考超过 60 秒时 WebSocket 被 ALB 断开。

**解决**：

```bash
aws elbv2 modify-load-balancer-attributes \
  --load-balancer-arn $ALB_ARN \
  --attributes Key=idle_timeout.timeout_seconds,Value=3600
```

### 8. 🟡 Control UI 需要 `allowInsecureAuth: true`

**现象**：Control UI 登录时 token 认证失败或 CORS 错误。

**原因**：ALB 终结 TLS 后，到 EC2 后端是 HTTP（非 HTTPS）。OpenClaw 默认要求安全连接传输 token。

**解决**：配置文件中设置 `"allowInsecureAuth": true`。

### 9. 🟡 Bedrock 模型需要提前开通访问权限

**现象**：API 调用返回 `AccessDeniedException`。

**原因**：AWS Bedrock 默认不开放所有模型，需要在 AWS Console 中手动请求访问。

**解决**：

1. 打开 [AWS Bedrock Console](https://console.aws.amazon.com/bedrock/)
2. 左侧菜单 → Model access
3. 选择需要的模型（如 Anthropic Claude）→ Request access
4. 等待几分钟生效

### 10. 🟡 Federation WSS 路径也需要绕过 Cognito

**现象**：两个实例的 Federation 连接建立失败。

**原因**：和 WebSocket 同样的问题，Federation 使用 WSS 通信。

**解决**：在 ALB 规则中添加 `/federation/*` 的直接 forward 规则（见 5.1 节）。

---

## 附录

### A. 完整配置文件示例（AKSK 模式）

```json5
// ~/.openclaw/openclaw.json
// AKSK 模式完整配置
// 环境变量需要: AWS_ACCESS_KEY_ID, AWS_SECRET_ACCESS_KEY, AWS_REGION
{
  // ── 模型配置 ──
  models: {
    providers: {
      "amazon-bedrock": {
        baseUrl: "https://bedrock-runtime.us-east-1.amazonaws.com",
        api: "bedrock-converse-stream",
        auth: "aws-sdk",
        models: [
          {
            id: "us.anthropic.claude-sonnet-4-20250514",
            name: "Claude Sonnet 4 (Bedrock)",
            reasoning: true,
            input: ["text", "image"],
            cost: { input: 0, output: 0, cacheRead: 0, cacheWrite: 0 },
            contextWindow: 200000,
            maxTokens: 8192,
          },
          {
            id: "us.anthropic.claude-opus-4-6-v1:0",
            name: "Claude Opus 4.6 (Bedrock)",
            reasoning: true,
            input: ["text", "image"],
            cost: { input: 0, output: 0, cacheRead: 0, cacheWrite: 0 },
            contextWindow: 200000,
            maxTokens: 8192,
          },
        ],
      },
    },
    bedrockDiscovery: {
      enabled: true,
      region: "us-east-1",
      providerFilter: ["anthropic"],
      refreshInterval: 3600,
    },
  },

  // ── Agent 配置 ──
  agents: {
    defaults: {
      model: {
        primary: "amazon-bedrock/us.anthropic.claude-sonnet-4-20250514",
        fallbacks: ["amazon-bedrock/us.anthropic.claude-opus-4-6-v1:0"],
      },
      models: {
        "amazon-bedrock/us.anthropic.claude-sonnet-4-20250514": { alias: "sonnet" },
        "amazon-bedrock/us.anthropic.claude-opus-4-6-v1:0": { alias: "opus" },
      },
      workspace: "~/.openclaw/workspace",
      contextTokens: 200000,
      timeoutSeconds: 600,
      maxConcurrent: 3,
    },
  },

  // ── Gateway 配置 ──
  gateway: {
    port: 18789,
    mode: "local",
    bind: "lan",
    auth: {
      mode: "token",
      token: "REPLACE-WITH-REAL-TOKEN-openssl-rand-base64-48",
    },
    http: {
      endpoints: {
        chatCompletions: { enabled: true },
      },
    },
    controlUi: {
      enabled: true,
      allowedOrigins: ["https://my-agent.example.com"],
      allowInsecureAuth: true,
    },
  },

  // ── Federation 配置 ──
  federation: {
    enabled: true,
    instanceName: "MyAgent",
    endpoint: "wss://my-agent.example.com/federation",
    allowIntroductions: true,
    maxTrustDepth: 2,
    defaultRateLimit: {
      maxMessagesPerMinute: 10,
      maxMessagesPerHour: 100,
      maxMessagesPerDay: 500,
    },
    peers: [
      {
        name: "FriendAgent",
        endpoint: "wss://friend.example.com/federation",
        token: "friend-gateway-token-here",
        capabilities: ["chat", "weather"],
      },
    ],
  },

  // ── 渠道配置（可选） ──
  channels: {
    telegram: {
      enabled: false,
      botToken: "",
      dmPolicy: "pairing",
    },
  },
}
```

### B. systemd unit 文件

```ini
# /etc/systemd/system/openclaw-gateway.service
[Unit]
Description=OpenClaw AI Agent Gateway
Documentation=https://docs.openclaw.com
After=network-online.target
Wants=network-online.target

[Service]
Type=simple
User=ec2-user
Group=ec2-user
WorkingDirectory=/home/ec2-user

# 环境变量
Environment=HOME=/home/ec2-user
Environment=NODE_ENV=production
Environment=AWS_PROFILE=default
Environment=AWS_REGION=us-east-1
# AKSK 方式取消注释以下两行：
# Environment=AWS_ACCESS_KEY_ID=AKIAIOSFODNN7EXAMPLE
# Environment=AWS_SECRET_ACCESS_KEY=wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY

# 启动命令 - 根据实际路径调整
ExecStart=/home/ec2-user/.nvm/versions/node/v22.22.0/bin/node \
  --max-old-space-size=4096 \
  /home/ec2-user/.nvm/versions/node/v22.22.0/lib/node_modules/openclaw/dist/index.js \
  gateway --port 18789

# 日志
StandardOutput=append:/var/log/openclaw/gateway.log
StandardError=append:/var/log/openclaw/gateway-error.log

# 进程管理
Restart=on-failure
RestartSec=10
TimeoutStartSec=30
TimeoutStopSec=15

# 资源限制
LimitNOFILE=65535
LimitNPROC=4096

# 安全加固
NoNewPrivileges=true
ProtectSystem=strict
ReadWritePaths=/home/ec2-user /var/log/openclaw /tmp

[Install]
WantedBy=multi-user.target
```

```bash
# 安装和使用
sudo cp openclaw-gateway.service /etc/systemd/system/
sudo mkdir -p /var/log/openclaw && sudo chown ec2-user:ec2-user /var/log/openclaw
sudo systemctl daemon-reload
sudo systemctl enable openclaw-gateway
sudo systemctl start openclaw-gateway
sudo systemctl status openclaw-gateway
```

### C. Docker Compose 文件

#### Dockerfile（基于官方镜像构建）

如果需要自定义构建：

```dockerfile
# 使用 OpenClaw 官方 Dockerfile
# docker build -t openclaw:local .
# 源码目录中已包含 Dockerfile
```

#### docker-compose.yml

```yaml
# docker-compose.yml - OpenClaw Federation 部署
version: "3.9"

services:
  openclaw-gateway:
    image: ${OPENCLAW_IMAGE:-openclaw:local}
    container_name: openclaw-gateway
    environment:
      HOME: /home/node
      TERM: xterm-256color
      NODE_ENV: production
      TZ: ${OPENCLAW_TZ:-UTC}
      # Gateway Token
      OPENCLAW_GATEWAY_TOKEN: ${OPENCLAW_GATEWAY_TOKEN}
      # AWS 凭证（AKSK 模式）
      AWS_ACCESS_KEY_ID: ${AWS_ACCESS_KEY_ID:-}
      AWS_SECRET_ACCESS_KEY: ${AWS_SECRET_ACCESS_KEY:-}
      AWS_REGION: ${AWS_REGION:-us-east-1}
      # 如果用 Instance Role，设置这个即可
      AWS_PROFILE: ${AWS_PROFILE:-}
    volumes:
      # 配置目录（包含 openclaw.json）
      - ${OPENCLAW_CONFIG_DIR:-./config}:/home/node/.openclaw
      # 工作区
      - ${OPENCLAW_WORKSPACE_DIR:-./workspace}:/home/node/.openclaw/workspace
    ports:
      # Gateway HTTP + WS
      - "${OPENCLAW_GATEWAY_PORT:-18789}:18789"
      # Bridge
      - "${OPENCLAW_BRIDGE_PORT:-18790}:18790"
    init: true
    restart: unless-stopped
    command:
      [
        "node",
        "--max-old-space-size=4096",
        "dist/index.js",
        "gateway",
        "--bind",
        "lan",
        "--port",
        "18789",
      ]
    healthcheck:
      test:
        [
          "CMD",
          "node",
          "-e",
          "fetch('http://127.0.0.1:18789/healthz').then((r)=>process.exit(r.ok?0:1)).catch(()=>process.exit(1))",
        ]
      interval: 30s
      timeout: 5s
      retries: 5
      start_period: 20s
    deploy:
      resources:
        limits:
          memory: 4G
        reservations:
          memory: 2G
```

#### .env 文件

```bash
# .env - Docker Compose 环境变量

# OpenClaw 镜像
OPENCLAW_IMAGE=openclaw:local

# Gateway Token（必须设置）
OPENCLAW_GATEWAY_TOKEN=your-strong-random-token-here

# AWS 凭证（AKSK 模式，二选一）
# 方式 1: AKSK
AWS_ACCESS_KEY_ID=AKIAIOSFODNN7EXAMPLE
AWS_SECRET_ACCESS_KEY=wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY
AWS_REGION=us-east-1

# 方式 2: Instance Role（仅在 EC2 上有效）
# AWS_PROFILE=default

# 路径配置
OPENCLAW_CONFIG_DIR=./config
OPENCLAW_WORKSPACE_DIR=./workspace
OPENCLAW_GATEWAY_PORT=18789
OPENCLAW_BRIDGE_PORT=18790
OPENCLAW_TZ=Asia/Shanghai
```

#### 快速启动

```bash
# 1. 创建目录
mkdir -p openclaw-deploy/{config,workspace}
cd openclaw-deploy

# 2. 复制 docker-compose.yml 和 .env

# 3. 创建配置文件
cp /path/to/openclaw.json config/openclaw.json

# 4. 构建镜像（如果用源码）
cd /tmp/openclaw-src && docker build -t openclaw:local .
cd -

# 5. 启动
docker compose up -d

# 6. 检查状态
docker compose ps
docker compose logs -f openclaw-gateway

# 7. 验证
curl http://localhost:18789/healthz
```

### D. IAM Policy JSON（最小权限）

```json
{
  "Version": "2012-10-17",
  "Statement": [
    {
      "Sid": "BedrockInvokeModels",
      "Effect": "Allow",
      "Action": ["bedrock:InvokeModel", "bedrock:InvokeModelWithResponseStream"],
      "Resource": [
        "arn:aws:bedrock:us-east-1::foundation-model/anthropic.*",
        "arn:aws:bedrock:us-east-1::foundation-model/us.anthropic.*"
      ]
    },
    {
      "Sid": "BedrockListModels",
      "Effect": "Allow",
      "Action": "bedrock:ListFoundationModels",
      "Resource": "*"
    }
  ]
}
```

**附加说明**：

- 如果需要所有 Bedrock 模型，Resource 改为 `arn:aws:bedrock:*::foundation-model/*`
- 如果只用 Claude，上面的策略已经足够
- 生产环境建议加上 Condition 限制 IP 或 VPC

```bash
# 创建策略
aws iam create-policy \
  --policy-name OpenClawBedrockMinimal \
  --policy-document file://bedrock-minimal-policy.json

# 附加到角色或用户
aws iam attach-role-policy \
  --role-name openclaw-ec2-role \
  --policy-arn arn:aws:iam::ACCOUNT_ID:policy/OpenClawBedrockMinimal
```

### E. Nginx 完整配置文件

```nginx
# /etc/nginx/sites-available/openclaw
# OpenClaw Gateway 完整 Nginx 配置

# 限速区域
limit_req_zone $binary_remote_addr zone=openclaw_api:10m rate=30r/m;
limit_req_zone $binary_remote_addr zone=openclaw_ws:10m rate=10r/m;

# 上游定义
upstream openclaw_gateway {
    server 127.0.0.1:18789;
    keepalive 32;
}

# HTTP → HTTPS 重定向
server {
    listen 80;
    listen [::]:80;
    server_name my-agent.example.com;

    # ACME challenge（Let's Encrypt）
    location /.well-known/acme-challenge/ {
        root /var/www/certbot;
    }

    location / {
        return 301 https://$host$request_uri;
    }
}

# HTTPS 主配置
server {
    listen 443 ssl http2;
    listen [::]:443 ssl http2;
    server_name my-agent.example.com;

    # ── TLS 配置 ──
    ssl_certificate /etc/letsencrypt/live/my-agent.example.com/fullchain.pem;
    ssl_certificate_key /etc/letsencrypt/live/my-agent.example.com/privkey.pem;
    ssl_protocols TLSv1.2 TLSv1.3;
    ssl_ciphers ECDHE-ECDSA-AES128-GCM-SHA256:ECDHE-RSA-AES128-GCM-SHA256:ECDHE-ECDSA-AES256-GCM-SHA384:ECDHE-RSA-AES256-GCM-SHA384;
    ssl_prefer_server_ciphers off;
    ssl_session_cache shared:SSL:10m;
    ssl_session_timeout 1d;
    ssl_session_tickets off;

    # OCSP Stapling
    ssl_stapling on;
    ssl_stapling_verify on;
    resolver 8.8.8.8 8.8.4.4 valid=300s;

    # ── 安全头 ──
    add_header Strict-Transport-Security "max-age=63072000; includeSubDomains; preload" always;
    add_header X-Content-Type-Options nosniff always;
    add_header X-Frame-Options DENY always;
    add_header Referrer-Policy strict-origin-when-cross-origin always;

    # ── 通用代理设置 ──
    proxy_set_header Host $host;
    proxy_set_header X-Real-IP $remote_addr;
    proxy_set_header X-Forwarded-For $proxy_add_x_forwarded_for;
    proxy_set_header X-Forwarded-Proto $scheme;
    proxy_http_version 1.1;

    # ── 默认路由（HTTP API + Control UI）──
    location / {
        proxy_pass http://openclaw_gateway;
        limit_req zone=openclaw_api burst=20 nodelay;
        proxy_read_timeout 600s;
    }

    # ── WebSocket 路由 ──
    # Sessions（Bridge WebSocket）
    location /sessions {
        proxy_pass http://openclaw_gateway;
        proxy_set_header Upgrade $http_upgrade;
        proxy_set_header Connection "upgrade";
        proxy_read_timeout 3600s;
        proxy_send_timeout 3600s;
        limit_req zone=openclaw_ws burst=5 nodelay;
    }

    # OpenClaw 内部 WebSocket
    location /__openclaw__/ {
        proxy_pass http://openclaw_gateway;
        proxy_set_header Upgrade $http_upgrade;
        proxy_set_header Connection "upgrade";
        proxy_read_timeout 3600s;
        proxy_send_timeout 3600s;
    }

    # Federation WebSocket
    location /federation/ {
        proxy_pass http://openclaw_gateway;
        proxy_set_header Upgrade $http_upgrade;
        proxy_set_header Connection "upgrade";
        proxy_read_timeout 3600s;
        proxy_send_timeout 3600s;
    }

    # Webhook 回调
    location /webhook/ {
        proxy_pass http://openclaw_gateway;
        proxy_read_timeout 30s;
    }

    # ── 健康检查 ──
    location /healthz {
        proxy_pass http://openclaw_gateway;
        access_log off;
    }

    # ── 静态资源缓存（Control UI）──
    location ~* \.(js|css|png|jpg|jpeg|gif|ico|svg|woff|woff2|ttf|eot)$ {
        proxy_pass http://openclaw_gateway;
        expires 7d;
        add_header Cache-Control "public, immutable";
    }
}
```

### F. 安全组规则表

#### ALB 安全组 (`openclaw-alb-sg`)

| 类型 | 协议 | 端口  | 来源       | 说明              |
| ---- | ---- | ----- | ---------- | ----------------- |
| 入站 | TCP  | 443   | 0.0.0.0/0  | 公网 HTTPS        |
| 入站 | TCP  | 443   | ::/0       | 公网 HTTPS (IPv6) |
| 出站 | TCP  | 18789 | EC2 安全组 | 到 Gateway        |
| 出站 | TCP  | 18790 | EC2 安全组 | 到 Bridge         |

#### EC2 安全组 (`openclaw-ec2-sg`)

| 类型 | 协议 | 端口  | 来源        | 说明                     |
| ---- | ---- | ----- | ----------- | ------------------------ |
| 入站 | TCP  | 18789 | ALB 安全组  | Gateway（从 ALB）        |
| 入站 | TCP  | 18790 | ALB 安全组  | Bridge（从 ALB）         |
| 入站 | TCP  | 22    | 管理员 CIDR | SSH（仅管理用）          |
| 出站 | TCP  | 443   | 0.0.0.0/0   | Bedrock API + 外部 HTTPS |
| 出站 | TCP  | 53    | 0.0.0.0/0   | DNS                      |
| 出站 | UDP  | 53    | 0.0.0.0/0   | DNS                      |

> **注意**：EC2 实例之间的 Federation 通信走 ALB（通过公网域名），不需要额外的安全组规则。如果想走内网直连，需要在 EC2 安全组中互相允许 18789 端口。

---

## 快速参考卡

```
# 安装
npm install -g openclaw@latest

# 配置
vim ~/.openclaw/openclaw.json

# 启动
openclaw gateway --port 18789              # 前台
sudo systemctl start openclaw-gateway       # systemd

# Federation
openclaw federation status                  # 查看状态
openclaw federation peers                   # 列出 peer
openclaw federation pair --generate         # 生成配对码
openclaw federation pair --code OC-xxxx     # 使用配对码
openclaw federation chat <peer> "hello"     # 测试消息

# 运维
openclaw health                             # 健康状态
openclaw doctor                             # 诊断问题
openclaw logs --tail 50                     # 查看日志
openclaw models list                        # 模型列表
curl http://localhost:18789/healthz         # API 健康检查

# Token 生成
openssl rand -base64 48
```
