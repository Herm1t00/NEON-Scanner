# AI 自动漏洞挖掘流水线 —— 完整项目手册

> ⚠️ **法律与安全声明**
> 本项目仅供学习研究使用，**仅限在自己拥有的代码、本地靶场（DVWA/Vulhub/WebGoat）、已获得书面授权的目标上运行**。
> 未经授权扫描、探测他人系统属于违法行为。代码内置白名单强校验，越界目标直接拒绝执行。
> AI 输出存在幻觉，所有漏洞结论必须人工复核。

---

## 目录

- [一、项目介绍](#一项目介绍)
- [二、架构总览](#二架构总览)
- [三、快速上手（5 分钟跑起来）](#三快速上手5-分钟跑起来)
- [四、详细安装与配置](#四详细安装与配置)
- [五、使用教程](#五使用教程)
- [六、技术文档（模块详解）](#六技术文档模块详解)
- [七、常见问题 FAQ](#七常见问题-faq)
- [八、扩展开发](#八扩展开发)
- [九、附录](#九附录)

---

## 一、项目介绍

### 1.1 这是什么？

一套 AI 驱动的自动化漏洞挖掘流水线，把传统安全扫描工具和大模型结合起来：

- **AI 负责**：分析扫描结果、判断是不是漏洞、生成 POC、输出报告
- **传统工具负责**：实际的探测、扫描、验证
- **安全护栏**：白名单、限速、命令黑名单，防止误扫

### 1.2 能做什么？

✅ 自动信息收集（HTTP 探测、目录枚举）
✅ 自动爬取网站表单和链接（Playwright）
✅ 静态代码扫描（Semgrep，可选）
✅ 动态漏洞验证（SQL 注入、XSS、信息泄露）
✅ AI 智能分析（判断风险等级、生成推理）
✅ RAG 知识库增强（检索漏洞原理，降低幻觉）
✅ 自动生成 HTML / JSON 报告

### 1.3 不能做什么？

❌ 不能自动挖 0day（只能识别已知类型漏洞）
❌ AI 输出会有幻觉，**所有漏洞必须人工复核**
❌ 不能用来攻击未授权的目标（违法！）
❌ 复杂逻辑漏洞、条件竞争、内核漏洞无能为力

---

## 二、架构总览

### 2.1 整体分层架构

```
┌─────────────────────────────────────────────────────────────────┐
│                        交付层（输出）                            │
│   HTML 可视化报告 │ JSON 结构化数据 │ 全链路日志                  │
└─────────────────────────────────────────────────────────────────┘
                              ↑
┌─────────────────────────────────────────────────────────────────┐
│                        智能分析层（AI 核心）                     │
│   LLM 漏洞推理 │ RAG 知识库检索 │ POC 生成 │ 误报分拣           │
└─────────────────────────────────────────────────────────────────┘
                              ↑
┌─────────────────────────────────────────────────────────────────┐
│                        探测执行层（扫描器）                      │
│   信息收集 │ Playwright 爬虫 │ 动态验证 │ SAST 静态扫描          │
└─────────────────────────────────────────────────────────────────┘
                              ↑
┌─────────────────────────────────────────────────────────────────┐
│                        安全护栏层（强制前置）                    │
│   目标白名单 │ 请求限速 │ 命令黑名单 │ Docker 沙箱隔离          │
└─────────────────────────────────────────────────────────────────┘
                              ↑
┌─────────────────────────────────────────────────────────────────┐
│                        基础层（基础设施）                        │
│   Python 3.11+ │ LiteLLM 统一接口 │ Chroma 向量库 │ Flask 靶场  │
└─────────────────────────────────────────────────────────────────┘
```

### 2.2 数据流全景

```
用户输入目标 URL
      ↓
【安全护栏】白名单校验 → 通过？
      ↓ 是
【信息收集】httpx 探测 + 目录枚举
      ↓
【爬虫】Playwright 爬取页面 + 表单提取
      ↓
【动态验证】SQLi 检测 + XSS 检测 + 敏感路径扫描
      ↓
【RAG 检索】从向量库召回相关漏洞原理
      ↓
【LLM 分析】把所有数据 + RAG 知识喂给大模型
      ↓
【分拣】多源结果合并去重 + 误报过滤
      ↓
【报告】生成 HTML + JSON
      ↓
人工复核
```

### 2.3 技术栈

| 技术 | 版本 | 选型理由 |
|------|------|----------|
| Python | 3.11+ | 安全领域生态最丰富 |
| LiteLLM | ≥1.40 | 统一 100+ LLM 接口，换模型不用改代码 |
| LangGraph | ≥0.2 | 多 Agent 编排框架 |
| ChromaDB | ≥0.5 | 轻量级向量数据库，本地运行 |
| Sentence-Transformers | ≥2.2 | 本地 embedding 模型 |
| httpx | ≥0.27 | 异步 HTTP 客户端 |
| Playwright | ≥1.40 | 现代浏览器自动化 |
| Flask | 任意 | 轻量 Web 框架（靶场用） |

---

## 三、快速上手（5 分钟跑起来）

### 第一步：启动自带靶场

```bash
cd ai-vuln-pipeline
python vuln_app.py
```

看到这个输出说明启动成功：

```
==================================================
🐛 漏洞靶场启动成功!
📍 访问地址: http://127.0.0.1:5000
==================================================
```

### 第二步：把靶场加入白名单

编辑 `.env` 文件：

```env
TARGET_WHITELIST=http://127.0.0.1,http://127.0.0.1:5000
```

### 第三步：运行流水线

```bash
python demo_all.py
```

### 第四步：查看报告

运行完成后，报告在 `output/` 目录：
- `report_xxx.html` — 浏览器打开，可视化报告
- `report_xxx.json` — 机器可读

---

## 四、详细安装与配置

### 4.1 环境准备

| 软件 | 版本 | 用途 | 下载地址 |
|------|------|------|----------|
| Python | 3.11 ~ 3.13 | 运行主程序 | https://www.python.org/ |

### 4.2 安装步骤

```bash
# 1. 创建虚拟环境（推荐）
python -m venv venv

# 2. 激活（Windows）
venv\Scripts\activate
# 激活（Linux/Mac）
source venv/bin/activate

# 3. 安装 Python 依赖
pip install -r requirements.txt
```

### 4.3 安装 Playwright 浏览器（可选，爬虫功能用）

国内用户用镜像加速：

```powershell
# Windows PowerShell
$env:PLAYWRIGHT_DOWNLOAD_HOST = "https://npmmirror.com/mirrors/playwright"
python -m playwright install chromium
```

### 4.4 构建 RAG 知识库（可选，AI 分析增强）

国内用户用镜像加速：

```powershell
$env:HF_ENDPOINT = "https://hf-mirror.com"
python build_rag.py
```

### 4.5 配置 .env

复制模板：

```bash
cp .env.example .env
```

#### LLM 配置（必须）

**方案 A：智谱 AI（推荐，免费，国内直连）**

```env
LLM_PROVIDER=openai
LLM_MODEL=glm-4-flash
LLM_API_KEY=你的智谱API key
LLM_API_BASE=https://open.bigmodel.cn/api/paas/v4/
```

> 获取 key：https://open.bigmodel.cn/ → 注册 → API Keys → 创建

**方案 B：OpenAI / DeepSeek 等**

```env
LLM_PROVIDER=openai
LLM_MODEL=gpt-4o-mini
LLM_API_KEY=sk-xxxx
LLM_API_BASE=https://api.openai.com/v1
```

**方案 C：本地 Ollama（完全免费，离线）**

```env
LLM_PROVIDER=ollama
LLM_MODEL=deepseek-coder:6.7b
```

> 需要先装 Ollama：https://ollama.com/
> 然后拉模型：`ollama pull deepseek-coder:6.7b`

#### 安全白名单（最重要！）

```env
# 只有这些目标允许扫描，逗号分隔
# 不在列表里的目标直接拒绝执行
TARGET_WHITELIST=http://127.0.0.1,http://localhost,http://192.168.1.100
```

⚠️ **这是法律护栏**，未经授权扫描他人系统属于违法行为。

#### 限速配置（可选）

```env
SCAN_INTERVAL=2.0      # 每次请求间隔（秒）
MAX_CONCURRENT=1       # 最大并发数
RATE_LIMIT_PER_SEC=2   # 每秒最多请求数
```

---

## 五、使用教程

### 5.1 运行命令参考

| 命令 | 说明 |
|------|------|
| `python demo_all.py` | 完整版流水线（所有模块） |
| `python demo_local.py` | 基础版（信息收集 + 目录枚举） |
| `python demo_simple.py` | 简化版（不用 RAG） |
| `python test_llm3.py` | 测试 LLM 连接 |
| `python build_rag.py` | 重建 RAG 知识库 |
| `python vuln_app.py` | 启动自带漏洞靶场 |

### 5.2 主程序命令行参数

```bash
python main.py --target http://127.0.0.1:5000

# 跳过某些模块
python main.py --target http://127.0.0.1:5000 --no-nuclei --no-crawler

# 带源码 SAST 扫描
python main.py --target http://127.0.0.1:5000 --source-dir ./myapp

# 启用 sqlmap（较慢）
python main.py --target http://127.0.0.1:5000 --sqlmap
```

### 5.3 报告解读

HTML 报告包含：
- 顶部风险统计卡片（高危几个、中危几个）
- 表格展示所有漏洞（等级、类型、置信度、来源、URL、证据）
- 颜色区分风险等级

JSON 报告包含：
- 完整结构化数据，方便二次处理

### 5.4 往靶场加更多漏洞

编辑 `vuln_app.py`，加新的路由：

```python
@app.route("/new_vuln")
def new_vuln():
    # 你的漏洞代码
    pass
```

然后重新跑流水线，看看 AI 能不能发现新漏洞。

---

## 六、技术文档（模块详解）

### 6.1 安全护栏层

#### 目标白名单（`utils/whitelist.py`）

**功能：** 所有扫描目标必须先过白名单校验，不在列表内直接拒绝。

**实现原理：**
1. 从 URL 提取 host
2. 和白名单逐条比对
3. 额外检查：公网 IP 不在白名单直接拒绝（防误扫）

**为什么重要：** 这是法律护栏，防止 AI 失控扫到公网目标。

#### 限速器（`utils/rate_limiter.py`）

**功能：** 控制请求频率，防止打挂靶场或触发 WAF。

**实现：** 令牌桶算法，每秒最多 N 个请求，最小请求间隔。

#### 命令黑名单（`utils/command_guard.py`）

**功能：** 拦截 AI 下发的危险命令（rm -rf、fork bomb 等）。

#### Docker 沙箱（`utils/sandbox.py`）

**功能：** POC 验证在一次性容器里跑，用完销毁。

### 6.2 探测执行层

#### 信息收集 Agent（`agents/recon_agent.py`）

**功能：** HTTP 基础探测 + 目录枚举。

**输出：**
```python
{
    "status_code": 200,
    "title": "页面标题",
    "server": "Nginx/1.21.0",
    "tech_stack": ["PHP", "MySQL"],
    "directories": ["/admin", "/.env", ...]
}
```

#### Playwright 爬虫 Agent（`agents/crawler_agent.py`）

**功能：** 自动爬取网站，发现所有链接和表单。

**输出：**
```python
{
    "pages_crawled": 13,
    "forms": [{"action": "/login", "method": "POST", "fields": ["username", "password"]}]
}
```

**为什么用 Playwright？** 能爬 JS 渲染的页面，requests 只能拿原始 HTML。

#### 动态验证模块（`agents/dynamic_verify.py`）

**检测项：**

| 检测类型 | 原理 | 判定逻辑 |
|----------|------|----------|
| SQL 注入 | 加单引号看报错 | 页面出现 SQL 错误关键词 |
| 反射 XSS | 发 payload 看回显 | payload 完整出现在 HTML 里 |
| 信息泄露 | 扫描敏感路径 | 状态码 200 且大小 > 50 字节 |

#### SAST 静态扫描 Agent（`agents/sast_agent.py`）

**功能：** 对源码做静态分析（Semgrep），发现危险函数。

### 6.3 智能分析层（AI 核心）

#### LLM 漏洞推理 Agent（`agents/llm_reason_agent.py`）

**这是整个流水线的大脑。**

**Prompt 设计：**
```
你是 Web 安全漏洞分析专家...
【扫描数据】{...}
【漏洞知识库参考】{RAG 检索结果}
【任务】判断哪些是真漏洞，输出风险等级、证据、推理过程
【输出格式】严格 JSON
```

**关键技术点：**
1. 结构化输出：强制 LLM 输出 JSON
2. 低温度：temperature=0.1，减少幻觉
3. RAG 增强：先检索相关漏洞原理，再喂给 LLM

#### RAG 知识库（`utils/rag_loader.py`）

**技术流程：**
```
离线：漏洞文档 → 切分 → Embedding 向量化 → Chroma 存储
在线：扫描结果 → 向量化 → 相似度搜索（Top 3）→ 拼入 Prompt
```

**当前知识库：** SQL 注入、XSS、信息泄露原理文档

#### 分拣 Agent（`agents/triage_agent.py`）

**处理逻辑：**
1. 去重：同一个漏洞只保留一条
2. 误报过滤：过滤已知误报特征
3. 低置信度过滤：< 0.3 的扔掉
4. 排序：按风险等级排序

### 6.4 交付层

#### 报告生成器（`utils/report_generator.py`）

生成两种格式：
- **JSON：** 机器可读，方便二次处理
- **HTML：** 人可读，带风险统计卡片和表格

---

## 七、常见问题 FAQ

### Q1: LLM 连接报错 401 令牌不正确？

**原因：** API key 不对或者不完整。

**解决：**
- 智谱 AI 的 key 格式是 `xxx.xxx`（中间有个点）
- 重新去后台复制完整的 key
- 检查 `.env` 里的 `LLM_API_BASE` 有没有写错

### Q2: Playwright 下载浏览器失败？

**原因：** 国内访问微软下载服务器慢。

**解决：** 用国内镜像：
```powershell
$env:PLAYWRIGHT_DOWNLOAD_HOST = "https://npmmirror.com/mirrors/playwright"
python -m playwright install chromium
```

### Q3: RAG 模型下载慢？

**原因：** 国内访问 HuggingFace 慢。

**解决：** 用国内镜像：
```powershell
$env:HF_ENDPOINT = "https://hf-mirror.com"
python build_rag.py
```

### Q4: 白名单报错 "目标不在白名单内"？

**原因：** 你要扫的目标没加进 `.env` 的白名单。

**解决：** 编辑 `.env`，把目标加进去：
```env
TARGET_WHITELIST=http://127.0.0.1,http://你的目标地址
```

### Q5: AI 分析出了很多误报？

**原因：** 大模型幻觉是正常的。

**解决：**
- 所有漏洞必须人工复核
- 往 RAG 知识库多放点漏洞原理文档
- 换更强的模型（比如 glm-4 而不是 glm-4-flash）

### Q6: 能扫真实的网站吗？

**绝对不行！**
- 未经授权扫描他人系统属于违法行为
- 只能扫自己的、或者拿到书面授权的目标
- 本地靶场随便扫

---

## 八、扩展开发

### 8.1 加更多漏洞检测规则

编辑 `agents/dynamic_verify.py`，加新的检测函数：

```python
def verify_command_injection(url: str) -> dict:
    """命令注入检测"""
    # 你的代码
    pass
```

### 8.2 加更多 RAG 文档

往 `rag_knowledge/vuln_doc/` 目录放新的 `.txt` 漏洞文档：
- csrf.txt
- ssrf.txt
- xxe.txt
- 文件上传漏洞.txt

然后重建知识库：
```bash
python build_rag.py
```

### 8.3 接更多扫描工具

在 `agents/verify_agent.py` 里加新的工具调用：
- Nuclei 模板扫描
- sqlmap 自动 SQLi 验证
- subfinder 子域名枚举

### 8.4 后续扩展路线

**短期（1-2 周）：**
- [ ] 接 Nuclei 模板扫描
- [ ] 加更多 RAG 文档
- [ ] 支持登录态自动识别

**中期（1-2 月）：**
- [ ] 多 Agent 分工（侦察、利用、报告）
- [ ] LLM 辅助 Fuzz
- [ ] 接 CodeQL 做深度污点分析

**长期（3+ 月）：**
- [ ] 自动化漏洞验证链（发现 → 验证 → PoC → 报告）
- [ ] 二进制漏洞挖掘（LLM + AFL++）

---

## 九、附录

### 9.1 完整文件结构

```
ai-vuln-pipeline/
├── .env.example            # 配置模板
├── .env                    # 实际配置
├── requirements.txt        # Python 依赖
├── config.py                # 全局配置加载
├── main.py                  # 主程序入口
├── vuln_app.py              # 自带漏洞靶场
├── build_rag.py             # RAG 构建脚本
├── demo_all.py              # 完整版 Demo
├── demo_local.py            # 基础版 Demo
├── demo_simple.py           # 简化版 Demo
├── test_llm3.py             # LLM 测试
│
├── agents/                  # 智能体模块
│   ├── recon_agent.py       # 信息收集
│   ├── crawler_agent.py     # Playwright 爬虫
│   ├── sast_agent.py          # 静态扫描
│   ├── llm_reason_agent.py   # LLM 漏洞推理
│   ├── dynamic_verify.py      # 动态验证
│   ├── verify_agent.py        # Nuclei/sqlmap（可选）
│   ├── poc_generator.py       # POC 生成
│   └── triage_agent.py        # 分拣报告
│
├── utils/                   # 工具模块
│   ├── whitelist.py          # 白名单护栏
│   ├── rate_limiter.py       # 限速器
│   ├── command_guard.py      # 命令黑名单
│   ├── sandbox.py             # Docker 沙箱
│   ├── logger.py              # 日志
│   ├── rag_loader.py          # RAG 向量库
│   └── report_generator.py     # 报告生成
│
├── rag_knowledge/           # RAG 知识库
│   ├── vuln_doc/             # 漏洞原理文档
│   │   ├── sqli.txt
│   │   ├── xss.txt
│   │   └── info_disclosure.txt
│   └── chroma_db/            # 向量库（自动生成）
│
├── output/                  # 扫描报告输出
├── logs/                    # 运行日志
└── venv/                    # Python 虚拟环境
```

### 9.2 性能数据

| 阶段 | 耗时 | 说明 |
|------|------|------|
| 信息收集 | ~5 秒 | 40 个路径逐个请求 |
| Playwright 爬虫 | ~10 秒 | 爬 13 个页面 |
| 动态验证 | ~5 秒 | SQLi + XSS + 路径扫描 |
| LLM 分析 | ~15 秒 | GLM-4-Flash 推理 |
| **总计** | **~35 秒** | 扫一个靶场 |

### 9.3 安全设计（三层防护）

```
第 1 层：白名单硬校验 → 目标不在列表，直接拒绝
第 2 层：限速 + 命令黑名单 → 不能乱扫，不能发危险命令
第 3 层：Docker 沙箱 → POC 在隔离容器里跑
```

---

## ⚠️ 最后提醒

1. **法律红线**：只能扫自己的靶场或授权目标，扫别人的网站是违法的
2. **AI 会犯错**：所有漏洞结论必须人工复核，不要直接信 AI
3. **这是学习工具**：不是一键出 0day 的神器，真正的漏洞挖掘还是要靠人
4. **持续迭代**：往 RAG 里多放文档、加更多检测规则，准确率会越来越高
