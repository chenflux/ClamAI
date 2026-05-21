# ClamAI

<p align="center">
  <strong>AI 安全护栏</strong>
</p>

<p align="center">
  智能体防护 · 内容安全检测 · 多模型统一代理 | 可部署为网关或终端 EDR
</p>

<p align="center">
  <img src="https://img.shields.io/badge/Go-1.22+-00ADD8?style=flat-square" alt="Go" />
  <img src="https://img.shields.io/badge/React-18-61DAFB?style=flat-square" alt="React" />
  <img src="https://img.shields.io/badge/License-GPLv3-blue?style=flat-square" alt="License" />
  <img src="https://img.shields.io/badge/Platform-Windows%20%7C%20Linux-green?style=flat-square" alt="Platform" />
</p>

---

<p align="center">
  <img src="https://raw.githubusercontent.com/chenflux/blogs_picture/master/2026-05-11_193600_417.png" alt="ClamAI 安全总览" width="800" />
</p>

---

## 功能特性

- **Provider-native 透明代理** — 按服务商原生协议透传，不做格式转换，零延迟开销
- **14+ AI 提供商** — OpenAI / Anthropic / SiliconFlow / DeepSeek / 智谱 / 通义千问 / 豆包 / Moonshot / Yi / OpenRouter / Cursor / MiniMax 等
- **内容安全防护** — 关键词检测（AC 自动机）+ 正则威胁规则 + LLM 语义分类，支持拦截/告警双模式
- **系统行为分析** — 两层威胁检测架构（规则评分 + AI 深度分析），自动识别高风险 API Key
- **AI 智能体安全** — 环境安全检测 + 运行时威胁监控 + 日志审计，覆盖 Claude Code / Cursor / OpenClaw 等 12 种智能体
- **流量管控** — 速率限制、API Key 精细权限、按 Key / Provider / Model 多维统计
- **双模式部署** — PC 桌面应用（Tauri）或独立 Web 服务

## 快速开始

### Web 服务模式

```bash
# 克隆仓库
git clone https://github.com/chenflux/ClamAI.git
cd ClamAI

# 构建前端
npm install && npm run build

# 编译 Go 服务
cd server
cp -r ../dist frontend/dist/
go build -tags server -o ClamAI-Server .

# 启动（默认监听 0.0.0.0:38080 + 0.0.0.0:38081）
./ClamAI-Server --port 38080 --admin-port 38081 --host 0.0.0.0
```

打开浏览器访问 `http://localhost:38081/admin/`，首次使用会进入设置向导。

### PC 桌面模式

下载 Release 中的 `ClamAI.exe` + `ClamAI-Server.exe`，双击启动即可。

### 在外部工具中使用

ClamAI 采用 Provider-native 透明代理，外部工具按服务商选择对应路径前缀：

| 服务商 | API 地址 |
|--------|----------|
| SiliconFlow | `http://localhost:38080/siliconflow/v1` |
| DeepSeek | `http://localhost:38080/deepseek/v1` |
| OpenAI | `http://localhost:38080/openai/v1` |
| Anthropic | `http://localhost:38080/anthropic/v1` |
| 智谱 GLM | `http://localhost:38080/glm/v1` |
| 通义千问 | `http://localhost:38080/qwen/v1` |

API Key 使用 ClamAI 生成的 `clam-sk-xxxx` 格式密钥。

## 项目结构

```
ClamAI/
├── server/          # Go 后端服务（代理引擎 + 管理 API + 安全检测）
├── src/             # React 前端（管理界面）
├── src-tauri/       # Tauri 桌面壳（Rust）
├── docs/            # 文档
├── build.bat        # 构建入口（Release）
└── build-dev.bat    # 构建入口（Debug）
```

## 技术栈

| 层级 | 技术 |
|------|------|
| 桌面壳 | Tauri 1.x (Rust) |
| 前端 | React 18 + TypeScript + Vite + Tailwind CSS |
| 后端 | Go 1.22+ (gorilla/mux + GORM) |
| 数据库 | SQLite（默认）/ PostgreSQL |
| 安全引擎 | AC 自动机 + 正则引擎 + LLM 语义分类 |

## 文档

- [快速使用指南](docs/快速使用.md)
- [项目架构](docs/项目架构.md)
- [数据流关系](docs/数据流关系.md)
- [代码结构](docs/代码结构.md)
- [API 清单](docs/API清单.md)
- [故障排查](docs/故障排查.md)

## 构建

```bash
# 完整构建（前端 + Rust 桌面 + Go 服务，当前平台）
build.bat

# 仅构建 Go 服务（多平台交叉编译）
build.bat service

# Debug 构建
build-dev.bat
```

构建产物输出到 `outputs/` 目录。

## 致谢

感谢以下开源项目为 ClamAI 智能体安全检测模块提供的规则与识别能力参考：[Caramel-Pudding](https://github.com/EdinLyle/Caramel-Pudding)、[cc-audit](https://github.com/ryo-ebata/cc-audit)、[golf-scanner](https://github.com/golf-mcp/golf-scanner)、[clawkeeper](https://github.com/rad-security/clawkeeper)。

## 许可证

[GPLv3](LICENSE)
