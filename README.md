# NEON Scanner

企业级自动化漏洞扫描工具，专为补天/SRC平台优化。

## 功能特性

- **V22 验证型扫描器**：所有漏洞基于实际验证（SQL注入发SLEEP、XSS发唯一标记、目录遍历读/etc/passwd），不做猜测性检测
- **Banner Grabber**：真实抓取 MySQL/SSH/Redis 等服务 Banner 版本号
- **ICP备案查询**：自动查询域名归属并截图
- **补天格式报告**：严格按照补天提交规范生成 TXT + HTML 双格式报告
- **Cyberpunk 桌面UI**：customtkinter 框架，深色科幻风格
- **异步切页**：扫描时UI不卡顿

## 漏洞类型覆盖

| 类别 | 检测项 |
|------|--------|
| Web漏洞 | SQL注入、XSS、目录遍历、SSRF、信息泄露、配置错误 |
| 服务端口 | MySQL、SSH、Redis、PostgreSQL、MongoDB Banner抓取 |
| 安全头 | X-Frame-Options、CSP、HSTS 缺失检测 |
| 子域名 | 自动枚举发现 |

## 项目结构

```
ai-vuln-pipeline/
├── scanner_v22.py      # V22 扫描器主程序
├── desktop_app.py      # 桌面应用（Cyberpunk UI）
├── icp_auto.py         # ICP备案自动截图脚本
├── .env                # 配置文件（白名单/LLM API）
├── PROJECT_GUIDE.md    # 项目手册
└── output/             # 扫描结果输出目录
```

## 快速开始

```bash
# 安装依赖
pip install -r requirements.txt

# 配置 .env
TARGET_WHITELIST=your-target.com
LLM_API_KEY=your-zhipu-api-key

# 命令行扫描
python scanner_v22.py https://target.com

# 启动桌面应用
python desktop_app.py
```

## 报告导出

扫描完成后点击「📤 导出报告」，自动在 `output/` 下创建带时间戳的文件夹，包含：
- `漏洞报告.txt` — 纯文本格式，可直接复制到补天表单
- `漏洞报告.html` — 网页格式，带每个字段的复制按钮

每个漏洞字段严格对应补天表单：
- 漏洞类别（一级）：Web漏洞 / 操作系统及通用软件漏洞
- 漏洞类型（二级）：SQL注入 / XSS / 配置错误 / 信息泄露
- Hunter测绘语句、POC命令、复现步骤、白帽声明

## 免责声明

本工具仅用于授权安全测试和漏洞研究。使用者必须确保扫描目标已获得书面授权。未经授权扫描他人系统属于违法行为。
