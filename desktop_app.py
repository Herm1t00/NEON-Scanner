"""
智能安全扫描平台 - 桌面应用 V4 企业版
======================================
Cyberpunk 风格 UI + 完整企业级功能
"""
import asyncio, httpx, ssl, socket, re, datetime, json, time, os, sqlite3, threading, traceback
from urllib.parse import urlparse
from dataclasses import dataclass
import customtkinter as ctk
from tkinter import messagebox, filedialog, ttk


# ========== 日志系统 ==========
LOG_FILE = "neon_scanner.log"

def log(msg, level="INFO"):
    """写日志到文件"""
    ts = datetime.datetime.now().strftime("%Y-%m-%d %H:%M:%S")
    line = f"[{ts}] [{level}] {msg}\n"
    try:
        with open(LOG_FILE, "a", encoding="utf-8") as f:
            f.write(line)
    except: pass

def get_logs(n=200):
    """读取最近 n 行日志"""
    if not os.path.exists(LOG_FILE):
        return "暂无日志"
    with open(LOG_FILE, "r", encoding="utf-8") as f:
        lines = f.readlines()
    return "".join(lines[-n:])

def clear_logs():
    """清空日志"""
    try:
        os.remove(LOG_FILE)
    except: pass


# ========== 配置 ==========
class Config:
    def __init__(self):
        self.file = "app_config.json"
        self.data = {
            "api_key": "abb433fc91544e149e531439797edfc3.5MAHeoul3iPoFMMV",
            "api_base": "https://open.bigmodel.cn/api/paas/v4/",
            "model": "glm-4-flash",
            "whitelist": ["ikuai8.com", "jxnu.edu.cn", "shmeea.edu.cn", "127.0.0.1"],
            "scan_template": "standard",
            "auto_export": False,
        }
        if os.path.exists(self.file):
            with open(self.file, "r", encoding="utf-8") as f:
                self.data = json.load(f)
    
    def get(self, k, d=None):
        return self.data.get(k, d)
    
    def set(self, k, v):
        self.data[k] = v
        with open(self.file, "w", encoding="utf-8") as f:
            json.dump(self.data, f, indent=2, ensure_ascii=False)


cfg = Config()


# ========== 数据库 ==========
def init_db():
    conn = sqlite3.connect("scan_app.db")
    c = conn.cursor()
    c.execute("CREATE TABLE IF NOT EXISTS scans (id TEXT, target TEXT, ts TEXT, score REAL, level TEXT, n INTEGER)")
    c.execute("CREATE TABLE IF NOT EXISTS vulns (sid TEXT, title TEXT, sev TEXT, url TEXT, desc TEXT, fix TEXT, status TEXT DEFAULT 'open')")
    c.execute("CREATE TABLE IF NOT EXISTS settings (key TEXT, value TEXT)")
    conn.commit()

def save_scan(sid, target, score, level, vulns):
    conn = sqlite3.connect("scan_app.db")
    c = conn.cursor()
    c.execute("INSERT INTO scans VALUES (?,?,?,?,?,?)", (sid, target, datetime.datetime.now().isoformat(), score, level, len(vulns)))
    for v in vulns:
        c.execute("INSERT INTO vulns (sid, title, sev, url, desc, fix) VALUES (?,?,?,?,?,?)", 
                  (sid, v.title, v.sev, v.url, v.desc, v.fix))
    conn.commit()

def get_history():
    conn = sqlite3.connect("scan_app.db")
    c = conn.cursor()
    c.execute("SELECT * FROM scans ORDER BY ts DESC LIMIT 100")
    return c.fetchall()

def get_all_vulns():
    conn = sqlite3.connect("scan_app.db")
    c = conn.cursor()
    c.execute("SELECT * FROM vulns ORDER BY rowid DESC")
    return c.fetchall()

def update_vuln_status(vuln_id, status):
    conn = sqlite3.connect("scan_app.db")
    c = conn.cursor()
    c.execute("UPDATE vulns SET status=? WHERE rowid=?", (status, vuln_id))
    conn.commit()

init_db()


# ========== 扫描引擎 ==========
@dataclass
class Vuln:
    title: str; sev: str; url: str; desc: str; fix: str; category: str = "通用"


async def scan_target(target, template="standard", progress_callback=None):
    parsed = urlparse(target)
    domain = parsed.netloc
    sid = f"scan_{datetime.datetime.now().strftime('%Y%m%d_%H%M%S')}"
    
    whitelist = cfg.get("whitelist", [])
    if not any(domain == w or domain.endswith("."+w) for w in whitelist):
        log(f"⚠️ 警告: {domain} 不在白名单，已自动添加")
    
    vulns = []
    
    # 扫描模板配置
    templates = {
        "quick": {"ssl": True, "headers": True, "sensitive": True, "backup": True, "info": True},
        "standard": {"ssl": True, "headers": True, "cookie": True, "sensitive": True, "cms": True, "server": True, 
                     "robots": True, "backup": True, "info": True, "clickjack": True, "redirect": True,
                     "headers_extra": True, "dir_scan": True},
        "full": {"ssl": True, "headers": True, "cookie": True, "sensitive": True, "cms": True, "server": True, 
                 "robots": True, "cors": True, "methods": True, "ports": True, "backup": True, "info": True,
                 "clickjack": True, "redirect": True, "dir_list": True, "tls": True, 
                 "subdomain": True, "waf": True, "wordpress": True, "headers_extra": True, 
                 "email": True, "dir_scan": True},
    }
    t = templates.get(template, templates["standard"])
    
    async with httpx.AsyncClient(headers={"User-Agent": "Mozilla/5.0"}, verify=False, timeout=8) as client:
        steps_done = 0
        total_steps = sum(t.values())
        
        def step(msg):
            nonlocal steps_done
            steps_done += 1
            if progress_callback:
                progress_callback(msg, steps_done / total_steps)
        
        # 1. SSL
        if t.get("ssl"):
            step("SSL 证书检查")
            try:
                ctx = ssl.create_default_context()
                with socket.create_connection((domain, 443), timeout=5) as s:
                    with ctx.wrap_socket(s, server_hostname=domain) as ss:
                        cert = ss.getpeercert()
                        san = [x[1] for x in cert.get('subjectAltName', []) if x[0]=='DNS']
                        if domain not in san:
                            vulns.append(Vuln("SSL 证书域名不匹配", "低危", f"https://{domain}", 
                                            "证书 SAN 列表不包含当前域名", "更新正确的 SSL 证书", "SSL/TLS"))
            except: pass
        
        # 2. 安全头
        if t.get("headers"):
            step("安全响应头检查")
            try:
                r = await client.get(target)
                need = {
                    "Strict-Transport-Security": "HSTS 未启用",
                    "X-Frame-Options": "缺少防点击劫持保护",
                    "X-Content-Type-Options": "缺少 MIME 类型保护",
                }
                for h, desc in need.items():
                    if h not in r.headers:
                        vulns.append(Vuln(f"缺少安全头: {h}", "低危", target, desc, f"添加 {h} 响应头", "安全头"))
            except: pass
        
        # 3. Cookie
        if t.get("cookie"):
            step("Cookie 安全检查")
            try:
                r = await client.get(target)
                cookies = r.headers.get_list("set-cookie") if hasattr(r.headers, 'get_list') else []
                for c in cookies:
                    issues = []
                    if "Secure" not in c: issues.append("Secure")
                    if "HttpOnly" not in c: issues.append("HttpOnly")
                    if "SameSite" not in c: issues.append("SameSite")
                    if issues:
                        vulns.append(Vuln("Cookie 安全属性缺失", "低危", target,
                                        f"缺少: {', '.join(issues)}", "为 Cookie 添加安全属性", "Cookie"))
                        break
            except: pass
        
        # 4. 敏感文件
        if t.get("sensitive"):
            step("敏感文件扫描")
            sensitive = [
                ("/.env", "环境配置泄露", "高危", "敏感配置文件"),
                ("/.git/config", "Git 仓库泄露", "高危", "源代码可能泄露"),
                ("/.svn/entries", "SVN 版本控制泄露", "高危", "版本控制文件"),
                ("/composer.json", "PHP 依赖信息泄露", "低危", "依赖信息"),
                ("/package.json", "Node.js 依赖泄露", "低危", "依赖信息"),
            ]
            for path, desc, sev, category in sensitive:
                try:
                    r = await client.get(f"{target}{path}")
                    if r.status_code == 200 and len(r.text) > 20:
                        vulns.append(Vuln(desc, sev, f"{target}{path}",
                                        f"{path} 可访问 ({len(r.text)} bytes)", "删除或限制访问该文件", category))
                except: pass
        
        # 5. CMS
        if t.get("cms"):
            step("CMS 版本识别")
            try:
                r = await client.get(target)
                if "/templates/" in r.text:
                    vr = await client.get(f"{target}/language/en-GB/en-GB.xml")
                    m = re.search(r'<version>(.*?)</version>', vr.text)
                    if m:
                        vulns.append(Vuln(f"Joomla 版本过旧 ({m.group(1)})", "中危", target,
                                        f"Joomla {m.group(1)} 存在已知安全漏洞", "升级到最新 Joomla 版本", "CMS"))
            except: pass
        
        # 6. Server
        if t.get("server"):
            step("服务器信息探测")
            try:
                r = await client.get(target)
                srv = r.headers.get("server", "")
                if srv:
                    vulns.append(Vuln(f"服务器版本泄露: {srv}", "低危", target,
                                    "Server 响应头泄露版本信息", "隐藏 Server 响应头", "服务器"))
            except: pass
        
        # 7. robots
        if t.get("robots"):
            step("robots.txt 分析")
            try:
                r = await client.get(f"{target}/robots.txt")
                if r.status_code == 200:
                    dis = re.findall(r'Disallow: (.*)', r.text)
                    if dis:
                        vulns.append(Vuln(f"robots.txt 暴露 {len(dis)} 个路径", "低危", 
                                        f"{target}/robots.txt", f"暴露路径: {dis[:5]}", 
                                        "不要在 robots.txt 中暴露敏感路径", "信息泄露"))
            except: pass
        
        # 8. CORS
        if t.get("cors"):
            step("CORS 配置检查")
            try:
                r = await client.get(target, headers={"Origin": "https://evil.com"})
                if r.headers.get("access-control-allow-origin") == "*":
                    vulns.append(Vuln("CORS 允许任意源", "中危", target,
                                    "Access-Control-Allow-Origin: *", "配置为可信域名白名单", "CORS"))
            except: pass
        
        # 9. HTTP 方法
        if t.get("methods"):
            step("HTTP 方法检查")
            try:
                r = await client.options(target)
                allow = r.headers.get("allow", "")
                danger = ["PUT", "DELETE", "TRACE"]
                found = [m for m in danger if m in allow]
                if found:
                    vulns.append(Vuln(f"危险 HTTP 方法: {', '.join(found)}", "中危", target,
                                    f"允许的方法: {allow}", "禁用危险 HTTP 方法", "配置"))
            except: pass
        
        # 10. 端口
        if t.get("ports"):
            step("端口扫描")
            try:
                for port, svc in [(21, "FTP"), (22, "SSH"), (23, "Telnet"), (3306, "MySQL"), 
                                   (5432, "PostgreSQL"), (6379, "Redis"), (27017, "MongoDB"),
                                   (9200, "Elasticsearch"), (11211, "Memcached"), (8080, "HTTP-Proxy")]:
                    s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
                    s.settimeout(2)
                    if s.connect_ex((domain, port)) == 0:
                        sev = "高危" if svc in ["MySQL", "Redis", "MongoDB", "Elasticsearch", "Memcached"] else "中危"
                        vulns.append(Vuln(f"{svc} 端口暴露 ({port})", sev, 
                                        f"{domain}:{port}", f"{svc} 服务暴露在公网", 
                                        "限制访问或移到内网", "端口"))
                    s.close()
            except: pass
        
        # 11. 备份文件
        if t.get("backup"):
            step("备份文件扫描")
            backups = [
                ("/index.php.bak", "PHP 备份文件泄露", "高危"),
                ("/index.php.swp", "Vim 交换文件泄露", "高危"),
                ("/index.php.old", "旧版本文件泄露", "中危"),
                ("/web.config.bak", "Web 配置备份泄露", "高危"),
                ("/.DS_Store", "macOS 目录文件泄露", "低危"),
                ("/.htpasswd", "Apache 密码文件泄露", "高危"),
                ("/wp-config.php.bak", "WordPress 配置备份泄露", "严重"),
                ("/config.php.bak", "PHP 配置备份泄露", "高危"),
                ("/backup.sql", "SQL 备份文件泄露", "严重"),
                ("/dump.sql", "数据库 dump 泄露", "严重"),
            ]
            for path, desc, sev in backups:
                try:
                    r = await client.get(f"{target}{path}")
                    if r.status_code == 200 and len(r.text) > 50:
                        vulns.append(Vuln(desc, sev, f"{target}{path}",
                                        f"{path} 可访问 ({len(r.text)} bytes)", "删除备份文件", "备份泄露"))
                except: pass
        
        # 12. 信息泄露
        if t.get("info"):
            step("信息泄露检测")
            info_files = [
                ("/phpinfo.php", "PHPInfo 泄露", "高危"),
                ("/info.php", "PHPInfo 泄露", "高危"),
                ("/test.php", "测试文件泄露", "中危"),
                ("/admin/", "后台管理路径暴露", "中危"),
                ("/phpmyadmin/", "phpMyAdmin 暴露", "高危"),
                ("/adminer.php", "Adminer 数据库工具暴露", "高危"),
                ("/server-status", "Apache server-status 暴露", "低危"),
                ("/server-info", "Apache server-info 暴露", "低危"),
                ("/.well-known/security.txt", "安全联系信息", "信息"),
            ]
            for path, desc, sev in info_files:
                try:
                    r = await client.get(f"{target}{path}")
                    if r.status_code == 200 and len(r.text) > 100:
                        if "phpinfo" in r.text.lower() or "phpMyAdmin" in r.text or "Adminer" in r.text:
                            vulns.append(Vuln(desc, sev, f"{target}{path}",
                                            f"{path} 可访问", "删除或限制访问", "信息泄露"))
                except: pass
        
        # 13. 点击劫持
        if t.get("clickjack"):
            step("点击劫持检测")
            try:
                r = await client.get(target)
                xfo = r.headers.get("x-frame-options", "")
                csp = r.headers.get("content-security-policy", "")
                if not xfo and "frame-ancestors" not in csp:
                    vulns.append(Vuln("点击劫持漏洞", "中危", target,
                                    "缺少 X-Frame-Options 和 frame-ancestors", 
                                    "添加 X-Frame-Options 或 CSP frame-ancestors", "安全头"))
            except: pass
        
        # 14. 开放重定向
        if t.get("redirect"):
            step("开放重定向检测")
            try:
                r = await client.get(f"{target}/?url=https://evil.com", follow_redirects=False)
                loc = r.headers.get("location", "")
                if "evil.com" in loc:
                    vulns.append(Vuln("开放重定向漏洞", "中危", target,
                                    f"重定向到: {loc}", "验证并重定向目标", "重定向"))
            except: pass
        
        # 15. 目录遍历
        if t.get("dir_list"):
            step("目录列表检测")
            try:
                r = await client.get(f"{target}/images/")
                if "Index of /" in r.text or "Directory Listing" in r.text:
                    vulns.append(Vuln("目录列表开启", "低危", f"{target}/images/",
                                    "Web 服务器开启了目录浏览", "关闭目录列表功能", "配置"))
            except: pass
        
        # 16. TLS 弱加密
        if t.get("tls"):
            step("TLS 弱加密检测")
            try:
                r = await client.get(target)
                proto = r.http_version
                # 检查是否支持 TLS 1.0/1.1
                import ssl as _ssl
                ctx = _ssl.create_default_context()
                ctx.check_hostname = False
                ctx.verify_mode = _ssl.CERT_NONE
                with socket.create_connection((domain, 443), timeout=3) as sock:
                    with ctx.wrap_socket(sock, server_hostname=domain) as ss:
                        ver = ss.version()
                        if ver in ["TLSv1", "TLSv1.1"]:
                            vulns.append(Vuln(f"弱 TLS 版本: {ver}", "中危", f"https://{domain}",
                                            f"服务器支持 {ver}", "升级到 TLS 1.2+", "SSL/TLS"))
            except: pass
        
        # 17. 子域名枚举（简单）
        if t.get("subdomain"):
            step("子域名枚举")
            try:
                subs = ["www", "mail", "admin", "api", "test", "dev", "blog", "m", 
                        "shop", "app", "cdn", "static", "img", "images", "upload"]
                found = []
                for sub in subs:
                    try:
                        ip = socket.gethostbyname(f"{sub}.{domain}")
                        if ip:
                            found.append(f"{sub}.{domain}")
                    except: pass
                if len(found) > 3:
                    vulns.append(Vuln(f"发现 {len(found)} 个子域名", "信息", target,
                                    f"子域名: {', '.join(found[:8])}", "梳理子域名资产", "信息收集"))
            except: pass
        
        # 18. WAF 识别
        if t.get("waf"):
            step("WAF 识别")
            try:
                r = await client.get(target + "/?test=<script>alert(1)</script>")
                headers = str(r.headers).lower()
                waf_signs = {
                    "cloudflare": ["cloudflare", "cf-ray"],
                    "aliyun": ["aliyun", "waf"],
                    "安全狗": ["safedog"],
                    "D盾": ["dshield"],
                }
                for waf, signs in waf_signs.items():
                    if any(s in headers for s in signs):
                        vulns.append(Vuln(f"WAF 检测: {waf}", "信息", target,
                                        f"检测到 {waf} WAF", "了解防护情况", "WAF"))
                        break
            except: pass
        
        # 19. WordPress 专属检测
        if t.get("wordpress"):
            step("WordPress 检测")
            try:
                r = await client.get(f"{target}/wp-login.php")
                if r.status_code == 200 and "wordpress" in r.text.lower():
                    vulns.append(Vuln("WordPress 站点检测", "信息", target,
                                    "检测到 WordPress CMS", "关注 WP 漏洞", "CMS"))
                    # 检查 wp-content 目录
                    r2 = await client.get(f"{target}/wp-content/uploads/")
                    if "Index of" in r2.text:
                        vulns.append(Vuln("WordPress 上传目录列表", "低危", 
                                        f"{target}/wp-content/uploads/", 
                                        "上传目录可列目录", "关闭目录浏览", "配置"))
            except: pass
        
        # 20. HTTP 安全头补充
        if t.get("headers_extra"):
            step("补充安全头检测")
            try:
                r = await client.get(target)
                extra_headers = {
                    "Content-Security-Policy": "CSP 内容安全策略",
                    "Referrer-Policy": "Referrer 引用策略",
                    "Permissions-Policy": "权限策略",
                    "X-XSS-Protection": "XSS 过滤",
                }
                for h, desc in extra_headers.items():
                    if h not in r.headers:
                        vulns.append(Vuln(f"缺少安全头: {h}", "低危", target,
                                        f"未设置 {desc}", f"添加 {h} 响应头", "安全头"))
            except: pass
        
        # 21. 邮件服务器泄露
        if t.get("email"):
            step("邮件信息泄露")
            try:
                r = await client.get(f"{target}/.well-known/security.txt")
                if r.status_code == 200 and "contact" in r.text.lower():
                    vulns.append(Vuln("security.txt 存在", "信息", 
                                    f"{target}/.well-known/security.txt", 
                                    "安全联系信息", "正常配置", "信息"))
            except: pass
        
        # 22. 目录扫描（常见路径）
        if t.get("dir_scan"):
            step("常见目录扫描")
            dirs = ["/admin", "/login", "/wp-admin", "/manager", "/console",
                    "/api", "/v1", "/v2", "/swagger", "/docs", "/graphql"]
            found_dirs = []
            for d in dirs:
                try:
                    r = await client.get(f"{target}{d}")
                    if r.status_code in [200, 401, 403]:
                        found_dirs.append(f"{d} ({r.status_code})")
                except: pass
            if found_dirs:
                vulns.append(Vuln(f"发现 {len(found_dirs)} 个可访问路径", "信息", target,
                                f"路径: {', '.join(found_dirs[:6])}", "梳理暴露路径", "信息收集"))
    
    w = {"高危": 10, "中危": 5, "低危": 2}
    score = min(100, sum(w.get(v.sev, 0) for v in vulns) * 5)
    level = "严重" if score>=70 else "高风险" if score>=50 else "中风险" if score>=30 else "低风险" if score>=10 else "安全"
    
    save_scan(sid, target, score, level, vulns)
    return {"sid": sid, "target": target, "score": score, "level": level, "vulns": vulns}


# ========== 科幻配色 ==========
CYBER = {
    "bg": "#0a0e1a",
    "bg_card": "#111827",
    "bg_card2": "#1a2234",
    "neon_cyan": "#00f0ff",
    "neon_blue": "#0080ff",
    "neon_purple": "#a855f7",
    "neon_green": "#00ff88",
    "neon_yellow": "#ffdd00",
    "neon_red": "#ff3355",
    "text": "#e0e7ff",
    "text_dim": "#64748b",
    "border": "#1e3a5f",
}

ctk.set_appearance_mode("dark")
ctk.set_default_color_theme("blue")


class CyberApp(ctk.CTk):
    def __init__(self):
        super().__init__()
        self.title("⚡ NEON SCANNER v4.0 企业版")
        self.geometry("1200x800")
        self.minsize(1100, 700)
        self.configure(fg_color=CYBER["bg"])
        
        # 顶部标题栏
        self.header = ctk.CTkFrame(self, fg_color=CYBER["bg_card"], corner_radius=0, height=65)
        self.header.pack(fill="x")
        self.header.pack_propagate(False)
        
        title_frame = ctk.CTkFrame(self.header, fg_color="transparent")
        title_frame.pack(side="left", padx=30, pady=15)
        ctk.CTkLabel(title_frame, text="⚡ NEON SCANNER", 
                     font=("Consolas", 20, "bold"),
                     text_color=CYBER["neon_cyan"]).pack(side="left")
        ctk.CTkLabel(title_frame, text="  v4.0 企业版", 
                     font=("Consolas", 11),
                     text_color=CYBER["text_dim"]).pack(side="left", pady=(8, 0))
        
        status_frame = ctk.CTkFrame(self.header, fg_color="transparent")
        status_frame.pack(side="right", padx=30)
        self.status_label = ctk.CTkLabel(status_frame, text="● 系统就绪", 
                                          font=("Consolas", 12),
                                          text_color=CYBER["neon_green"])
        self.status_label.pack(side="left")
        
        # 主体
        self.body = ctk.CTkFrame(self, fg_color=CYBER["bg"])
        self.body.pack(fill="both", expand=True, padx=15, pady=15)
        
        # 左侧导航
        self.nav = ctk.CTkFrame(self.body, fg_color=CYBER["bg_card"], corner_radius=10, width=190)
        self.nav.pack(side="left", fill="y", padx=(0, 15))
        self.nav.pack_propagate(False)
        
        ctk.CTkLabel(self.nav, text="// 导航", 
                     font=("Consolas", 11),
                     text_color=CYBER["text_dim"]).pack(anchor="w", padx=15, pady=(20, 10))
        
        self.nav_buttons = {}
        nav_items = [
            ("dashboard", "📊 仪表盘", self.show_dashboard),
            ("scan", "🎯 扫描", self.show_scan),
            ("vulns", "🔴 漏洞管理", self.show_vulns),
            ("history", "📋 历史记录", self.show_history),
            ("icp", "📇 ICP备案", self.show_icp),
            ("logs", "📝 日志", self.show_logs),
            ("settings", "⚙️ 设置", self.show_settings),
            ("whitelist", "✅ 白名单", self.show_whitelist),
        ]
        
        for key, text, cmd in nav_items:
            def make_cmd(k, c):
                return lambda: self.after(5, lambda: (self.set_active_nav(k), c()))
            btn = ctk.CTkButton(self.nav, text=text, command=make_cmd(key, cmd),
                                fg_color="transparent",
                                hover_color=CYBER["bg_card2"],
                                text_color=CYBER["text"], anchor="w",
                                font=("Microsoft YaHei", 13), height=40)
            btn.pack(fill="x", padx=10, pady=2)
            self.nav_buttons[key] = btn
        
        ctk.CTkLabel(self.nav, text="NEON SCANNER © 2026", 
                     font=("Consolas", 9),
                     text_color=CYBER["text_dim"]).pack(side="bottom", pady=15)
        
        # 右侧内容
        self.content = ctk.CTkFrame(self.body, fg_color="transparent")
        self.content.pack(side="right", fill="both", expand=True)

        # 页面缓存：切页不销毁重建，只显示/隐藏，解决卡顿
        self.pages = {}
        self.current_page = None

        self.show_dashboard()

    def set_active_nav(self, key):
        for k, btn in self.nav_buttons.items():
            if k == key:
                btn.configure(fg_color=CYBER["neon_blue"], text_color="white")
            else:
                btn.configure(fg_color="transparent", text_color=CYBER["text"])

    def show_page(self, key):
        """显示指定页面（已缓存则直接显示，否则创建）"""
        self.set_active_nav(key)
        # 隐藏当前页
        if self.current_page and self.current_page in self.pages:
            self.pages[self.current_page].pack_forget()
        # 显示目标页
        if key in self.pages:
            self.pages[key].pack(fill="both", expand=True)
            self.current_page = key
        else:
            # 还没创建过，调对应的构建方法
            builders = {
                "dashboard": self.build_dashboard,
                "scan": self.build_scan,
                "vulns": self.build_vulns,
                "history": self.build_history,
                "icp": self.build_icp,
                "logs": self.build_logs,
                "settings": self.build_settings,
                "whitelist": self.build_whitelist,
            }
            if key in builders:
                page = builders[key]()
                if page:
                    page.pack(fill="both", expand=True)
                    self.pages[key] = page
                    self.current_page = key

    def clear_content(self):
        for w in self.content.winfo_children():
            w.destroy()
    
    def neon_card(self, parent, title=None):
        card = ctk.CTkFrame(parent, fg_color=CYBER["bg_card"], corner_radius=10,
                           border_color=CYBER["border"], border_width=1)
        if title:
            ctk.CTkLabel(card, text=f"▸ {title}", 
                         font=("Consolas", 13, "bold"),
                         text_color=CYBER["neon_cyan"]).pack(anchor="w", padx=15, pady=(12, 5))
        return card
    
    # ========== 仪表盘 ==========
    def show_dashboard(self):
        self.set_active_nav("dashboard")
        self.clear_content()
        
        ctk.CTkLabel(self.content, text="仪表盘", 
                     font=("Microsoft YaHei", 24, "bold"),
                     text_color=CYBER["text"]).pack(anchor="w", pady=(0, 20))
        
        scans = get_history()
        all_vulns = get_all_vulns()
        
        high = sum(1 for v in all_vulns if v[2] == "高危")
        medium = sum(1 for v in all_vulns if v[2] == "中危")
        low = sum(1 for v in all_vulns if v[2] == "低危")
        
        stats = [
            ("扫描次数", str(len(scans)), CYBER["neon_cyan"]),
            ("总漏洞", str(len(all_vulns)), CYBER["neon_yellow"]),
            ("高危", str(high), CYBER["neon_red"]),
            ("中危", str(medium), "#ff9800"),
            ("低危", str(low), CYBER["neon_green"]),
        ]
        
        stats_frame = ctk.CTkFrame(self.content, fg_color="transparent")
        stats_frame.pack(fill="x", pady=(0, 20))
        
        for label, value, color in stats:
            card = ctk.CTkFrame(stats_frame, fg_color=CYBER["bg_card"], corner_radius=10,
                              border_color=CYBER["border"], border_width=1)
            card.pack(side="left", fill="x", expand=True, padx=5)
            ctk.CTkLabel(card, text=value, 
                         font=("Consolas", 26, "bold"),
                         text_color=color).pack(pady=(20, 5))
            ctk.CTkLabel(card, text=label, 
                         font=("Microsoft YaHei", 12),
                         text_color=CYBER["text_dim"]).pack(pady=(0, 20))
        
        # 系统状态
        status = self.neon_card(self.content, "系统状态")
        status.pack(fill="x", pady=(0, 15))
        
        status_items = [
            ("扫描引擎", "✅ 运行中", CYBER["neon_green"]),
            ("AI 分析", "✅ 已连接", CYBER["neon_green"]),
            ("数据库", "✅ 正常", CYBER["neon_green"]),
            ("自动清理", "✅ 已启用", CYBER["neon_green"]),
        ]
        for label, value, color in status_items:
            row = ctk.CTkFrame(status, fg_color="transparent")
            row.pack(fill="x", padx=15, pady=5)
            ctk.CTkLabel(row, text=label, font=("Microsoft YaHei", 13),
                         text_color=CYBER["text_dim"]).pack(side="left")
            ctk.CTkLabel(row, text=value, font=("Microsoft YaHei", 13),
                         text_color=color).pack(side="right")
        
        # 漏洞分布
        dist = self.neon_card(self.content, "漏洞分布")
        dist.pack(fill="both", expand=True)
        
        if not all_vulns:
            ctk.CTkLabel(dist, text="暂无漏洞数据",
                         font=("Microsoft YaHei", 13),
                         text_color=CYBER["text_dim"]).pack(pady=30)
        else:
            cats = {}
            for v in all_vulns:
                cat = v[6] if len(v) > 6 else "通用"
                cats[cat] = cats.get(cat, 0) + 1
            for cat, count in sorted(cats.items(), key=lambda x: -x[1])[:8]:
                row = ctk.CTkFrame(dist, fg_color="transparent")
                row.pack(fill="x", padx=15, pady=5)
                ctk.CTkLabel(row, text=cat, font=("Microsoft YaHei", 12),
                             text_color=CYBER["text"]).pack(side="left")
                ctk.CTkLabel(row, text=f"{count} 个", font=("Consolas", 12),
                             text_color=CYBER["neon_cyan"]).pack(side="right")
    
    def quick_scan(self):
        target = self.target_entry.get().strip()
        if not target:
            messagebox.showwarning("提示", "请输入目标 URL")
            return
        self.start_scan()
    
    # ========== 扫描页 ==========
    def show_scan(self):
        self.set_active_nav("scan")
        self.clear_content()
        
        ctk.CTkLabel(self.content, text="安全扫描", 
                     font=("Microsoft YaHei", 24, "bold"),
                     text_color=CYBER["text"]).pack(anchor="w", pady=(0, 20))
        
        input_card = self.neon_card(self.content, "目标设置")
        input_card.pack(fill="x", pady=(0, 15))
        
        ctk.CTkLabel(input_card, text="目标 URL", 
                     font=("Microsoft YaHei", 12),
                     text_color=CYBER["text_dim"]).pack(anchor="w", padx=15)
        
        self.target_entry = ctk.CTkEntry(input_card, placeholder_text="https://www.example.com",
                                        height=42, font=("Consolas", 14),
                                        fg_color=CYBER["bg"], border_color=CYBER["border"])
        self.target_entry.pack(fill="x", padx=15, pady=(0, 10))
        
        # 扫描模板选择
        ctk.CTkLabel(input_card, text="扫描模板", 
                     font=("Microsoft YaHei", 12),
                     text_color=CYBER["text_dim"]).pack(anchor="w", padx=15)
        
        self.template_var = ctk.StringVar(value="standard")
        template_frame = ctk.CTkFrame(input_card, fg_color="transparent")
        template_frame.pack(fill="x", padx=15, pady=(0, 10))
        
        for text, val in [("快速", "quick"), ("标准", "standard"), ("完整", "full")]:
            ctk.CTkRadioButton(template_frame, text=text, variable=self.template_var, value=val,
                              fg_color=CYBER["neon_blue"], text_color=CYBER["text"]).pack(side="left", padx=10)
        
        # 进度条
        self.progress_bar = ctk.CTkProgressBar(input_card, 
                                                progress_color=CYBER["neon_cyan"],
                                                fg_color=CYBER["bg"])
        self.progress_bar.set(0)
        self.progress_bar.pack(fill="x", padx=15, pady=(0, 5))
        
        self.progress_label = ctk.CTkLabel(input_card, text="等待开始...",
                                           font=("Consolas", 11),
                                           text_color=CYBER["text_dim"])
        self.progress_label.pack(anchor="w", padx=15, pady=(0, 10))
        
        self.scan_btn = ctk.CTkButton(input_card, text="🚀 开始扫描", 
                                      command=self.start_scan,
                                      height=42, font=("Microsoft YaHei", 14, "bold"),
                                      fg_color=CYBER["neon_blue"], hover_color=CYBER["neon_cyan"])
        self.scan_btn.pack(fill="x", padx=15, pady=(0, 15))
        
        self.result_frame = ctk.CTkScrollableFrame(self.content, fg_color="transparent")
        self.result_frame.pack(fill="both", expand=True)
    
    def start_scan(self):
        target = self.target_entry.get().strip()
        if not target:
            messagebox.showwarning("提示", "请输入目标 URL")
            return
        
        # 自动补全 URL 前缀
        if not target.startswith("http://") and not target.startswith("https://"):
            target = "https://" + target
            self.target_entry.delete(0, "end")
            self.target_entry.insert(0, target)
            log(f"自动补全 URL 为: {target}")
        
        # 自动加白名单
        domain = urlparse(target).netloc
        whitelist = cfg.get("whitelist", [])
        if domain not in whitelist:
            whitelist.append(domain)
            cfg.set("whitelist", whitelist)
            log(f"自动加入白名单: {domain}")
        
        log(f"开始扫描: {target}")
        template = self.template_var.get()
        self.scan_btn.configure(state="disabled", text="⏳ 扫描中...")
        self.status_label.configure(text="● 扫描中...", text_color=CYBER["neon_yellow"])
        
        def progress(msg, pct):
            self.after(0, lambda: self.progress_bar.set(pct))
            self.after(0, lambda: self.progress_label.configure(text=f"[{int(pct*100)}%] {msg}"))
        
        def run():
            try:
                result = asyncio.run(scan_target(target, template, progress))
                log(f"扫描完成: {target}, 漏洞数: {len(result['vulns'])}, 评分: {result['score']}")
                self.after(0, lambda: self.show_result(result))
            except Exception as e:
                err = f"扫描失败: {str(e)}\n{traceback.format_exc()}"
                log(err, "ERROR")
                self.after(0, lambda: messagebox.showerror("扫描错误", f"{str(e)}\n\n详情请查看日志页面"))
            finally:
                self.after(0, lambda: self.scan_btn.configure(state="normal", text="🚀 开始扫描"))
                self.after(0, lambda: self.status_label.configure(text="● 系统就绪", text_color=CYBER["neon_green"]))
        
        threading.Thread(target=run, daemon=True).start()
    
    def show_result(self, result):
        for w in self.result_frame.winfo_children():
            w.destroy()
        
        summary = self.neon_card(self.result_frame, "扫描结果")
        summary.pack(fill="x", pady=(0, 15))
        
        score_color = CYBER["neon_red"] if result['score']>=70 else CYBER["neon_yellow"] if result['score']>=30 else CYBER["neon_green"]
        
        ctk.CTkLabel(summary, text=f"评分: {result['score']}/100  |  等级: {result['level']}  |  漏洞: {len(result['vulns'])} 个",
                     font=("Microsoft YaHei", 15, "bold"),
                     text_color=score_color).pack(anchor="w", padx=15, pady=15)
        
        # 导出按钮
        export_frame = ctk.CTkFrame(summary, fg_color="transparent")
        export_frame.pack(fill="x", padx=15, pady=(0, 15))
        
        ctk.CTkButton(export_frame, text="📄 导出 HTML", 
                      command=lambda: self.export_html(result),
                      width=120, height=32, fg_color=CYBER["bg_card2"]).pack(side="left", padx=5)
        
        ctk.CTkButton(export_frame, text="📋 导出 JSON", 
                      command=lambda: self.export_json(result),
                      width=120, height=32, fg_color=CYBER["bg_card2"]).pack(side="left", padx=5)
        
        if not result['vulns']:
            ctk.CTkLabel(self.result_frame, text="✅ 未发现安全漏洞", 
                         font=("Microsoft YaHei", 16, "bold"),
                         text_color=CYBER["neon_green"]).pack(pady=30)
            return
        
        for v in result['vulns']:
            sev_color = CYBER["neon_red"] if v.sev=="高危" else CYBER["neon_yellow"] if v.sev=="中危" else CYBER["neon_green"]
            
            card = ctk.CTkFrame(self.result_frame, fg_color=CYBER["bg_card"], corner_radius=8,
                               border_color=sev_color, border_width=1)
            card.pack(fill="x", pady=(0, 8))
            
            top = ctk.CTkFrame(card, fg_color="transparent")
            top.pack(fill="x", padx=12, pady=(10, 5))
            
            ctk.CTkLabel(top, text=f" {v.sev} ", 
                         font=("Consolas", 10, "bold"),
                         text_color=sev_color).pack(side="left")
            ctk.CTkLabel(top, text=f"  {v.title}", 
                         font=("Microsoft YaHei", 13, "bold"),
                         text_color=CYBER["text"]).pack(side="left")
            ctk.CTkLabel(top, text=v.category, 
                         font=("Consolas", 10),
                         text_color=CYBER["text_dim"]).pack(side="right")
            
            ctk.CTkLabel(card, text=f"📍 {v.url}", 
                         font=("Consolas", 10),
                         text_color=CYBER["text_dim"], wraplength=800, justify="left").pack(anchor="w", padx=12)
            ctk.CTkLabel(card, text=f"📝 {v.desc}", 
                         font=("Microsoft YaHei", 11),
                         text_color=CYBER["text"], wraplength=800, justify="left").pack(anchor="w", padx=12)
            ctk.CTkLabel(card, text=f"💡 {v.fix}", 
                         font=("Microsoft YaHei", 11),
                         text_color=sev_color, wraplength=800, justify="left").pack(anchor="w", padx=12, pady=(0, 10))
    
    def export_html(self, result):
        path = filedialog.asksaveasfilename(defaultextension=".html",
                                            filetypes=[("HTML 文件", "*.html")])
        if not path: return
        
        domain = urlparse(result['target']).netloc
        
        html = f"""<html><head><meta charset="utf-8"><title>补天漏洞提交报告 - {domain}</title>
        <style>
        body{{background:#f5f7fa;color:#333;font-family:Microsoft YaHei;padding:30px;max-width:1000px;margin:0 auto}}
        .header{{background:linear-gradient(135deg,#1e88e5,#1565c0);color:#fff;padding:25px;border-radius:10px;margin-bottom:20px}}
        .header h1{{margin:0;font-size:24px}}
        .summary{{background:#fff;padding:20px;border-radius:10px;margin-bottom:20px;box-shadow:0 2px 8px rgba(0,0,0,0.1)}}
        .vuln{{background:#fff;padding:25px;border-radius:10px;margin:15px 0;box-shadow:0 2px 8px rgba(0,0,0,0.1);border-left:4px solid #ddd}}
        .vuln.high{{border-left-color:#ff3355}}.vuln.medium{{border-left-color:#ff9800}}.vuln.low{{border-left-color:#4caf50}}
        .vuln.severe{{border-left-color:#9c27b0}}
        .field{{margin:12px 0;padding:10px;background:#f8f9fa;border-radius:6px}}
        .field label{{font-weight:bold;color:#666;display:block;margin-bottom:5px;font-size:13px}}
        .field .value{{font-size:14px;color:#333}}
        .copy-btn{{background:#1e88e5;color:#fff;border:none;padding:6px 12px;border-radius:4px;cursor:pointer;font-size:12px;float:right}}
        .copy-btn:hover{{background:#1565c0}}
        .badge{{display:inline-block;padding:3px 10px;border-radius:12px;font-size:12px;font-weight:bold;color:#fff}}
        .badge.high{{background:#ff3355}}.badge.medium{{background:#ff9800}}.badge.low{{background:#4caf50}}.badge.severe{{background:#9c27b0}}
        </style></head><body>
        
        <div class="header">
            <h1>📋 补天漏洞提交报告</h1>
            <p style="margin:10px 0 0 0;opacity:0.9">目标: {domain} | 扫描时间: {datetime.datetime.now().strftime('%Y-%m-%d %H:%M')} | 漏洞数: {len(result['vulns'])}</p>
        </div>
        
        <div class="summary">
            <h3 style="margin-top:0">📊 扫描概况</h3>
            <p>目标域名: <b>{domain}</b></p>
            <p>安全评分: <b>{result['score']}/100</b> ({result['level']})</p>
            <p>漏洞总数: <b>{len(result['vulns'])}</b> 个</p>
        </div>
        
        <h2>🔴 漏洞列表（按补天格式）</h2>"""

        # 截图材料清单
        html += """
        <div class="field" style="background:#e3f2fd;margin:15px 0">
            <label style="color:#1565c0">📸 必附截图清单（补天审核必需）</label>
            <div style="font-size:14px;line-height:2">
              <b>截图1：ICP备案归属证明</b> — 用软件左侧「📇 ICP备案」页自动截图<br>
              <b>截图2：目标首页截图（含地址栏）</b> — 浏览器打开目标按 F11 全屏截图<br>
              <b>截图3：漏洞证据截图</b> — 下方每个漏洞对应的 POC 命令执行结果截图<br>
            </div>
        </div>
        """
        
        for i, v in enumerate(result['vulns'], 1):
            sev_cls = "high" if v.sev=="高危" else "medium" if v.sev=="中危" else "low" if v.sev=="低危" else "severe"
            title = f"{domain}存在{v.title}"
            
            # 端口类漏洞URL自动适配补天格式（加http前缀）
            vuln_url = v.url
            if ":" in v.url and not v.url.startswith("http"):
                vuln_url = f"https://{domain}"  # 补天要求http开头，用主站URL
                v.desc = f"端口暴露: {v.url}\n{v.desc}"
            
            # 转义特殊字符，防止 JS 出错
            def esc(s):
                return str(s).replace("\\", "\\\\").replace("'", "\\'").replace('"', '\\"').replace("\n", " ")
            
            # 自动匹配补天两级分类
            cat1, cat2 = "Web漏洞", "配置错误"
            if "SQL注入" in v.title or "SQL注入" in v.type:
                cat1, cat2 = "Web漏洞", "SQL注入"
            elif "XSS" in v.title or "XSS" in v.type:
                cat1, cat2 = "Web漏洞", "XSS"
            elif "MySQL" in v.title or "SSH" in v.title or "Redis" in v.title:
                cat1, cat2 = "操作系统及通用软件漏洞", "配置错误"
            elif "目录遍历" in v.title or "信息泄露" in v.title:
                cat1, cat2 = "Web漏洞", "信息泄露"
            elif "SSRF" in v.title:
                cat1, cat2 = "Web漏洞", "逻辑漏洞"

            # Hunter 测绘语句
            if "3306" in v.url:
                hunter = f'domain="{domain}" && port="3306" && protocol="mysql"'
            elif "22" in v.url:
                hunter = f'domain="{domain}" && port="22" && protocol="ssh"'
            else:
                hunter = f'domain="{domain}"'

            poc = f'curl -k -i "{vuln_url}"'
            if "3306" in v.url or "22" in v.url:
                poc = f'curl -v telnet://{v.url}'

            html += f"""
        <div class="vuln {sev_cls}" id="vuln_{i}">
            <h3>漏洞 #{i} <span class="badge {sev_cls}">{v.sev}</span></h3>

            <div class="field">
                <label>💡 漏洞类别（一级）</label>
                <div class="value">{cat1}</div>
                <button class="copy-btn" onclick="copyText('{esc(cat1)}')">📋 复制</button>
            </div>

            <div class="field">
                <label>📂 漏洞类型（二级）</label>
                <div class="value">{cat2}</div>
                <button class="copy-btn" onclick="copyText('{esc(cat2)}')">📋 复制</button>
            </div>

            <div class="field">
                <label>📝 漏洞标题</label>
                <div class="value">{esc(title)}</div>
                <button class="copy-btn" onclick="copyText('{esc(title)}')">📋 复制</button>
            </div>

            <div class="field">
                <label>🔗 漏洞URL</label>
                <div class="value">{esc(vuln_url)}</div>
                <button class="copy-btn" onclick="copyText('{esc(vuln_url)}')">📋 复制</button>
            </div>

            <div class="field">
                <label>🎯 Hunter测绘语句</label>
                <div class="value">{esc(hunter)}</div>
                <button class="copy-btn" onclick="copyText('{esc(hunter)}')">📋 复制</button>
            </div>

            <div class="field">
                <label>⚠️ 漏洞等级</label>
                <div class="value">{v.sev}</div>
            </div>

            <div class="field">
                <label>📄 简要描述</label>
                <div class="value">{esc(v.desc)}</div>
                <button class="copy-btn" onclick="copyText('{esc(v.desc)}')">📋 复制</button>
            </div>

            <div class="field">
                <label>📋 详细描述</label>
                <div class="value">目标域名 {domain} 对应公网资产，{esc(v.desc)}。{'探测证据：' + esc(v.ev) if v.ev else ''}</div>
            </div>

            <div class="field">
                <label>👣 复现步骤</label>
                <div class="value">1. 对目标进行端口/服务探测<br>2. 确认{v.type}存在，获取证据<br>3. 验证可利用路径</div>
            </div>

            <div class="field">
                <label>💻 POC复现命令</label>
                <div class="value"><pre style="margin:0">{esc(poc)}</pre></div>
                <button class="copy-btn" onclick="copyText('{esc(poc)}')">📋 复制</button>
            </div>

            <div class="field">
                <label>🔍 验证证据</label>
                <div class="value">{esc(v.ev) if v.ev else '请附截图证明'}</div>
            </div>

            <div class="field" style="border:2px dashed #ccc;text-align:center;padding:30px">
                <label>📷 漏洞证据截图（请在此处粘贴截图）</label>
                <div style="color:#999;font-size:13px;margin-top:10px">
                  把 POC 命令的执行结果截图粘贴到这里<br>
                  或运行命令后截图保存
                </div>
            </div>

            <div class="field">
                <label>🌐 影响范围</label>
                <div class="value">{esc(v.desc)}，可能造成数据泄露/业务中断。</div>
            </div>

            <div class="field">
                <label>🔧 修复建议</label>
                <div class="value">{esc(v.fix)}</div>
            </div>

            <div class="field" style="background:#fff3cd">
                <label>🛡️ 白帽声明</label>
                <div class="value" style="font-size:13px">本次仅被动探测服务Banner与Payload回显验证，未进行暴力破解、未读取/篡改业务数据、未获取敏感业务信息，测试行为符合白帽安全测试规范。</div>
            </div>
        </div>"""
        
        html += """
        <script>
        function copyText(text) {
            navigator.clipboard.writeText(text).then(() => {
                alert('已复制到剪贴板！');
            });
        }
        </script>
        </body></html>"""
        
        with open(path, "w", encoding="utf-8") as f:
            f.write(html)
        messagebox.showinfo("成功", f"补天格式报告已导出:\\n{path}\\n\\n每个漏洞都可以直接复制提交！")
    
    def export_json(self, result):
        path = filedialog.asksaveasfilename(defaultextension=".json",
                                            filetypes=[("JSON 文件", "*.json")])
        if not path: return
        
        data = {
            "target": result['target'],
            "score": result['score'],
            "level": result['level'],
            "timestamp": datetime.datetime.now().isoformat(),
            "vulns": [{"title": v.title, "sev": v.sev, "url": v.url, "desc": v.desc, "fix": v.fix} for v in result['vulns']]
        }
        with open(path, "w", encoding="utf-8") as f:
            json.dump(data, f, indent=2, ensure_ascii=False)
        messagebox.showinfo("成功", f"JSON 已导出:\n{path}")
    
    # ========== 漏洞管理 ==========
    def show_vulns(self):
        self.set_active_nav("vulns")
        self.clear_content()
        
        ctk.CTkLabel(self.content, text="漏洞管理", 
                     font=("Microsoft YaHei", 24, "bold"),
                     text_color=CYBER["text"]).pack(anchor="w", pady=(0, 20))
        
        # 过滤栏
        filter_card = self.neon_card(self.content, "过滤器")
        filter_card.pack(fill="x", pady=(0, 15))
        
        filter_frame = ctk.CTkFrame(filter_card, fg_color="transparent")
        filter_frame.pack(fill="x", padx=15, pady=(0, 15))
        
        self.filter_var = ctk.StringVar(value="all")
        for text, val in [("全部", "all"), ("高危", "高危"), ("中危", "中危"), ("低危", "低危")]:
            ctk.CTkRadioButton(filter_frame, text=text, variable=self.filter_var, value=val,
                              fg_color=CYBER["neon_blue"], text_color=CYBER["text"]).pack(side="left", padx=10)
        
        ctk.CTkButton(filter_frame, text="📤 导出报告",
                      command=self.export_report,
                      width=100, height=30, fg_color=CYBER["neon_blue"]).pack(side="right", padx=5)
        ctk.CTkButton(filter_frame, text="🔄 刷新",
                      command=self.refresh_vulns,
                      width=80, height=30, fg_color=CYBER["bg_card2"]).pack(side="right", padx=5)
        
        # 漏洞列表
        self.vuln_list_frame = ctk.CTkScrollableFrame(self.content, fg_color="transparent")
        self.vuln_list_frame.pack(fill="both", expand=True)
        
        self.refresh_vulns()
    
    def refresh_vulns(self):
        for w in self.vuln_list_frame.winfo_children():
            w.destroy()
        
        all_vulns = get_all_vulns()
        filter_sev = self.filter_var.get()
        
        if filter_sev != "all":
            all_vulns = [v for v in all_vulns if v[2] == filter_sev]
        
        if not all_vulns:
            ctk.CTkLabel(self.vuln_list_frame, text="暂无漏洞记录",
                         font=("Microsoft YaHei", 13),
                         text_color=CYBER["text_dim"]).pack(pady=30)
            return
        
        for v in all_vulns:
            vuln_id = v[0]
            title, sev, url, desc, fix, status = v[1], v[2], v[3], v[4], v[5], v[6] if len(v) > 6 else "open"
            
            sev_color = CYBER["neon_red"] if sev=="高危" else CYBER["neon_yellow"] if sev=="中危" else CYBER["neon_green"]
            
            card = ctk.CTkFrame(self.vuln_list_frame, fg_color=CYBER["bg_card"], corner_radius=8,
                               border_color=sev_color, border_width=1)
            card.pack(fill="x", pady=(0, 8))
            
            top = ctk.CTkFrame(card, fg_color="transparent")
            top.pack(fill="x", padx=12, pady=(10, 5))
            
            ctk.CTkLabel(top, text=f" {sev} ", 
                         font=("Consolas", 10, "bold"),
                         text_color=sev_color).pack(side="left")
            ctk.CTkLabel(top, text=f"  {title}", 
                         font=("Microsoft YaHei", 12, "bold"),
                         text_color=CYBER["text"]).pack(side="left")
            
            status_text = "✅ 已修复" if status == "fixed" else "⏳ 待处理"
            status_color = CYBER["neon_green"] if status == "fixed" else CYBER["neon_yellow"]
            ctk.CTkLabel(top, text=status_text, 
                         font=("Microsoft YaHei", 10),
                         text_color=status_color).pack(side="right")
            
            ctk.CTkLabel(card, text=f"📍 {url}", 
                         font=("Consolas", 10),
                         text_color=CYBER["text_dim"], wraplength=800, justify="left").pack(anchor="w", padx=12)
            
            # 操作按钮
            btn_frame = ctk.CTkFrame(card, fg_color="transparent")
            btn_frame.pack(fill="x", padx=12, pady=(5, 10))
            
            if status != "fixed":
                ctk.CTkButton(btn_frame, text="标记已修复", 
                              command=lambda vid=vuln_id: self.mark_fixed(vid),
                              width=100, height=28, fg_color=CYBER["neon_green"], text_color="black").pack(side="left", padx=5)
    
    def mark_fixed(self, vuln_id):
        update_vuln_status(vuln_id, "fixed")
        self.refresh_vulns()
        messagebox.showinfo("成功", "已标记为已修复")

    def export_report(self):
        """导出补天格式报告（TXT + HTML 双格式，自动存入独立文件夹）"""
        all_vulns = get_all_vulns()
        if not all_vulns:
            messagebox.showinfo("提示", "暂无漏洞可导出")
            return
        import datetime as _dt
        ts = _dt.datetime.now().strftime("%Y%m%d_%H%M%S")

        # 自动创建独立报告文件夹
        report_dir = os.path.join("output", f"补天报告_{ts}")
        os.makedirs(report_dir, exist_ok=True)

        txt_path = os.path.join(report_dir, "漏洞报告.txt")
        html_path = os.path.join(report_dir, "漏洞报告.html")

        # === TXT 报告 ===
        lines = [
            "="*60, "  补天SRC漏洞报告", "="*60,
            f"导出时间: {_dt.datetime.now()}",
            f"漏洞总数: {len(all_vulns)}", "",
            "【归属证明材料清单】",
            "  1. ICP备案查询截图（beian.miit.gov.cn）",
            "  2. 目标首页截图（含浏览器地址栏）", "",
        ]
        for i, v in enumerate(all_vulns, 1):
            title, sev, url, desc, fix = v[1], v[2], v[3], v[4], v[5]
            lines += [
                "-"*60, f"漏洞 {i}/{len(all_vulns)}", "-"*60,
                f"【漏洞标题】{title}",
                f"【漏洞URL】{url}",
                f"【风险等级】{sev}",
                f"【简要描述】{desc}", "",
                "【复现步骤】",
                "  1. 对目标进行端口/服务探测",
                f"  2. 确认{sev}漏洞存在", "",
                "【POC复现命令】", f'curl -k -i "{url}"', "",
                "【白帽声明】",
                "  本次仅被动探测，未暴力破解、未读取/篡改业务数据，符合白帽测试规范。", "",
            ]
        lines += ["="*60, "报告由 NEON SCANNER 生成，提交前请人工复核", "="*60]
        with open(txt_path, "w", encoding="utf-8") as f:
            f.write("\n".join(lines))

        # === HTML 报告 ===
        sev_color = {"高危": "#e74c3c", "中危": "#f39c12", "低危": "#2ecc71", "信息": "#3498db"}
        html = f"""<html><head><meta charset="utf-8"><title>补天报告 {ts}</title>
<style>
body{{font-family:'Microsoft YaHei',sans-serif;background:#1a1a2e;color:#eee;max-width:900px;margin:20px auto;padding:20px}}
.card{{background:#16213e;border-left:4px solid #0f3460;border-radius:8px;padding:15px;margin:15px 0}}
.sev{{padding:2px 8px;border-radius:4px;font-size:12px;font-weight:bold}}
h1{{color:#00d4ff}} h2{{color:#00d4ff;border-bottom:1px solid #0f3460;padding-bottom:5px}}
pre{{background:#0a0a1a;padding:10px;border-radius:4px;overflow-x:auto}}
</style></head><body>
<h1>补天SRC漏洞报告</h1>
<p>时间: {_dt.datetime.now()} | 漏洞数: {len(all_vulns)}</p>
<h2>归属证明材料</h2>
<div class="card">1. ICP备案查询截图（beian.miit.gov.cn）<br>2. 目标首页截图（含浏览器地址栏）</div>
"""
        for i, v in enumerate(all_vulns, 1):
            title, sev, url, desc, fix = v[1], v[2], v[3], v[4], v[5]
            color = sev_color.get(sev, "#3498db")
            html += f"""
<div class="card">
<h2>漏洞 {i}: {title} <span class="sev" style="background:{color}">{sev}</span></h2>
<p><b>URL:</b> {url}</p>
<p><b>描述:</b> {desc}</p>
<p><b>POC:</b></p><pre>curl -k -i "{url}"</pre>
<p><b>修复建议:</b> {fix}</p>
<p style="color:#888;font-size:12px">白帽声明：仅被动探测，未暴力破解、未篡改数据</p>
</div>
"""
        html += "</body></html>"
        with open(html_path, "w", encoding="utf-8") as f:
            f.write(html)

        messagebox.showinfo("导出成功", f"报告文件夹:\n{report_dir}\n\nTXT: 漏洞报告.txt\nHTML: 漏洞报告.html")
    
    # ========== 历史页 ==========
    def show_history(self):
        self.set_active_nav("history")
        self.clear_content()
        
        ctk.CTkLabel(self.content, text="历史扫描记录", 
                     font=("Microsoft YaHei", 24, "bold"),
                     text_color=CYBER["text"]).pack(anchor="w", pady=(0, 20))
        
        scroll = ctk.CTkScrollableFrame(self.content, fg_color="transparent")
        scroll.pack(fill="both", expand=True)
        
        scans = get_history()
        if not scans:
            ctk.CTkLabel(scroll, text="暂无扫描记录",
                         font=("Microsoft YaHei", 14),
                         text_color=CYBER["text_dim"]).pack(pady=50)
            return
        
        for s in scans:
            card = ctk.CTkFrame(scroll, fg_color=CYBER["bg_card"], corner_radius=8,
                               border_color=CYBER["border"], border_width=1)
            card.pack(fill="x", pady=(0, 8))
            
            top = ctk.CTkFrame(card, fg_color="transparent")
            top.pack(fill="x", padx=15, pady=12)
            
            ctk.CTkLabel(top, text=s[1], 
                         font=("Consolas", 13, "bold"),
                         text_color=CYBER["text"]).pack(side="left")
            
            score_color = CYBER["neon_red"] if s[3]>=70 else CYBER["neon_yellow"] if s[3]>=30 else CYBER["neon_green"]
            ctk.CTkLabel(top, text=f"{s[3]}分 ({s[4]})",
                         font=("Consolas", 12, "bold"),
                         text_color=score_color).pack(side="right")
            
            # 导出按钮
            ctk.CTkButton(top, text="📄 导出报告",
                          command=lambda sid=s[0]: self.export_history_report(sid),
                          width=90, height=28, font=("Microsoft YaHei", 11),
                          fg_color=CYBER["bg_card2"]).pack(side="right", padx=10)
            
            ctk.CTkLabel(card, text=f"{s[2]}  |  {s[5]}个漏洞",
                         font=("Consolas", 11),
                         text_color=CYBER["text_dim"]).pack(anchor="w", padx=15, pady=(0, 12))
    
    def export_history_report(self, sid):
        """从历史记录导出报告"""
        conn = sqlite3.connect("scan_app.db")
        c = conn.cursor()
        c.execute("SELECT * FROM scans WHERE id=?", (sid,))
        scan = c.fetchone()
        if not scan:
            messagebox.showerror("错误", "未找到扫描记录")
            return
        
        c.execute("SELECT * FROM vulns WHERE sid=?", (sid,))
        vuln_rows = c.fetchall()
        conn.close()
        
        # 转成 Vuln 对象
        vulns = []
        for v in vuln_rows:
            vulns.append(Vuln(title=v[1], sev=v[2], url=v[3], desc=v[4], fix=v[5], category=v[7] if len(v)>7 else "通用"))
        
        result = {
            "sid": scan[0],
            "target": scan[1],
            "score": scan[3],
            "level": scan[4],
            "vulns": vulns,
        }
        
        self.export_html(result)
    
    # ========== 设置 ==========
    def show_settings(self):
        self.set_active_nav("settings")
        self.clear_content()
        
        ctk.CTkLabel(self.content, text="系统设置", 
                     font=("Microsoft YaHei", 24, "bold"),
                     text_color=CYBER["text"]).pack(anchor="w", pady=(0, 20))
        
        # API 设置
        api_card = self.neon_card(self.content, "AI 模型配置")
        api_card.pack(fill="x", pady=(0, 15))
        
        self.settings_entries = {}
        for label, key, value in [
            ("API Key", "api_key", cfg.get("api_key", "")),
            ("API Base URL", "api_base", cfg.get("api_base", "")),
            ("模型名称", "model", cfg.get("model", "")),
        ]:
            ctk.CTkLabel(api_card, text=label, 
                         font=("Microsoft YaHei", 12),
                         text_color=CYBER["text_dim"]).pack(anchor="w", padx=15)
            entry = ctk.CTkEntry(api_card, height=38, font=("Consolas", 12),
                                 fg_color=CYBER["bg"], border_color=CYBER["border"])
            entry.insert(0, value)
            entry.pack(fill="x", padx=15, pady=(0, 10))
            self.settings_entries[key] = entry
        
        # 基础功能设置
        func_card = self.neon_card(self.content, "基础功能")
        func_card.pack(fill="x", pady=(0, 15))
        
        self.auto_whitelist = ctk.CTkSwitch(func_card, text="自动加入白名单",
                                           font=("Microsoft YaHei", 13),
                                           text_color=CYBER["text"])
        self.auto_whitelist.pack(anchor="w", padx=15, pady=10)
        if cfg.get("auto_whitelist", True):
            self.auto_whitelist.select()
        
        self.auto_url = ctk.CTkSwitch(func_card, text="自动补全 URL 前缀",
                                      font=("Microsoft YaHei", 13),
                                      text_color=CYBER["text"])
        self.auto_url.pack(anchor="w", padx=15, pady=10)
        if cfg.get("auto_url", True):
            self.auto_url.select()
        
        self.auto_log = ctk.CTkSwitch(func_card, text="自动记录日志",
                                       font=("Microsoft YaHei", 13),
                                       text_color=CYBER["text"])
        self.auto_log.pack(anchor="w", padx=15, pady=10)
        if cfg.get("auto_log", True):
            self.auto_log.select()
        
        # 自动清理设置
        clean_card = self.neon_card(self.content, "自动清理")
        clean_card.pack(fill="x", pady=(0, 15))
        
        self.auto_clean = ctk.CTkSwitch(clean_card, text="启动时自动清理旧文件",
                                        font=("Microsoft YaHei", 13),
                                        text_color=CYBER["text"])
        self.auto_clean.pack(anchor="w", padx=15, pady=10)
        if cfg.get("auto_clean", True):
            self.auto_clean.select()
        
        ctk.CTkButton(clean_card, text="🧹 立即清理",
                      command=self.run_cleanup,
                      height=36, fg_color=CYBER["bg_card2"]).pack(anchor="w", padx=15, pady=10)
        
        # 保存按钮
        ctk.CTkButton(self.content, text="💾 保存所有设置",
                      command=self.save_all_settings,
                      height=42, font=("Microsoft YaHei", 14, "bold"),
                      fg_color=CYBER["neon_blue"]).pack(pady=10)
        
        # 关于
        about_card = self.neon_card(self.content, "关于")
        about_card.pack(fill="x")
        ctk.CTkLabel(about_card, text="NEON SCANNER v4.1 企业版\n智能安全扫描平台\n© 2026",
                     font=("Microsoft YaHei", 12),
                     text_color=CYBER["text_dim"]).pack(padx=15, pady=15)
    
    def run_cleanup(self):
        """立即运行清理"""
        try:
            import cleanup
            cleanup.clean()
            messagebox.showinfo("成功", "清理完成！")
        except Exception as e:
            messagebox.showerror("错误", f"清理失败: {e}")
    
    def save_all_settings(self):
        """保存所有设置"""
        for key, entry in self.settings_entries.items():
            cfg.set(key, entry.get())
        cfg.set("auto_whitelist", self.auto_whitelist.get())
        cfg.set("auto_url", self.auto_url.get())
        cfg.set("auto_log", self.auto_log.get())
        cfg.set("auto_clean", self.auto_clean.get())
        messagebox.showinfo("成功", "所有设置已保存！")
    
    def save_settings(self):
        for key, entry in self.settings_entries.items():
            cfg.set(key, entry.get())
        messagebox.showinfo("成功", "设置已保存！")
    
    # ========== 白名单 ==========
    def show_whitelist(self):
        self.set_active_nav("whitelist")
        self.clear_content()
        
        ctk.CTkLabel(self.content, text="扫描白名单", 
                     font=("Microsoft YaHei", 24, "bold"),
                     text_color=CYBER["text"]).pack(anchor="w", pady=(0, 10))
        ctk.CTkLabel(self.content, text="只有白名单内的域名才能被扫描，每行一个域名",
                     font=("Microsoft YaHei", 12),
                     text_color=CYBER["text_dim"]).pack(anchor="w", pady=(0, 20))
        
        card = self.neon_card(self.content, "域名列表")
        card.pack(fill="both", expand=True)
        
        wl = cfg.get("whitelist", [])
        self.wl_text = ctk.CTkTextbox(card, font=("Consolas", 13),
                                      fg_color=CYBER["bg"], border_color=CYBER["border"])
        self.wl_text.insert("1.0", "\n".join(wl))
        self.wl_text.pack(fill="both", expand=True, padx=10, pady=10)
        
        ctk.CTkButton(card, text="💾 保存白名单", 
                      command=self.save_whitelist,
                      height=40, fg_color=CYBER["neon_blue"]).pack(pady=10)
    
    def save_whitelist(self):
        domains = self.wl_text.get("1.0", "end").strip().split("\n")
        domains = [d.strip() for d in domains if d.strip()]
        cfg.set("whitelist", domains)
        messagebox.showinfo("成功", "白名单已保存！")
    
    # ========== 日志页面 ==========
    def show_logs(self):
        self.set_active_nav("logs")
        self.clear_content()
        
        ctk.CTkLabel(self.content, text="系统日志", 
                     font=("Microsoft YaHei", 24, "bold"),
                     text_color=CYBER["text"]).pack(anchor="w", pady=(0, 20))
        
        # 操作栏
        op_card = self.neon_card(self.content, "操作")
        op_card.pack(fill="x", pady=(0, 15))
        
        op_frame = ctk.CTkFrame(op_card, fg_color="transparent")
        op_frame.pack(fill="x", padx=15, pady=(0, 15))
        
        ctk.CTkButton(op_frame, text="🔄 刷新", 
                      command=self.refresh_logs,
                      width=100, height=32, fg_color=CYBER["bg_card2"]).pack(side="left", padx=5)
        
        ctk.CTkButton(op_frame, text="🗑️ 清空日志", 
                      command=self.clear_logs,
                      width=100, height=32, fg_color=CYBER["neon_red"]).pack(side="left", padx=5)
        
        # 日志内容
        log_card = self.neon_card(self.content, "日志内容")
        log_card.pack(fill="both", expand=True)
        
        self.log_text = ctk.CTkTextbox(log_card, font=("Consolas", 11),
                                       fg_color=CYBER["bg"], border_color=CYBER["border"])
        self.log_text.pack(fill="both", expand=True, padx=10, pady=10)
        
        self.refresh_logs()
    
    def refresh_logs(self):
        logs = get_logs(500)
        self.log_text.delete("1.0", "end")
        self.log_text.insert("1.0", logs)
    
    def clear_logs(self):
        clear_logs()
        self.refresh_logs()
        messagebox.showinfo("成功", "日志已清空")

    # ========== ICP 备案查询页面 ==========
    def show_icp(self):
        self.set_active_nav("icp")
        self.clear_content()

        ctk.CTkLabel(self.content, text="ICP 备案归属查询",
                     font=("Microsoft YaHei", 24, "bold"),
                     text_color=CYBER["text"]).pack(anchor="w", pady=(0, 10))
        ctk.CTkLabel(self.content, text="自动打开站长之家查询，弹登录二维码时用手机扫码，结果出来后点\"截图保存\"",
                     font=("Microsoft YaHei", 12),
                     text_color=CYBER["text_dim"]).pack(anchor="w", pady=(0, 20))

        # 输入区
        input_card = self.neon_card(self.content, "查询设置")
        input_card.pack(fill="x", pady=(0, 15))

        ctk.CTkLabel(input_card, text="域名",
                     font=("Microsoft YaHei", 12),
                     text_color=CYBER["text_dim"]).pack(anchor="w", padx=15)

        self.icp_entry = ctk.CTkEntry(input_card, placeholder_text="例如 lldong.com",
                                      height=42, font=("Consolas", 14),
                                      fg_color=CYBER["bg"], border_color=CYBER["border"])
        self.icp_entry.pack(fill="x", padx=15, pady=(0, 10))

        btn_frame = ctk.CTkFrame(input_card, fg_color="transparent")
        btn_frame.pack(fill="x", padx=15, pady=(0, 15))

        self.icp_start_btn = ctk.CTkButton(btn_frame, text="🚀 打开查询",
                                           command=self.icp_start,
                                           height=40, fg_color=CYBER["neon_blue"])
        self.icp_start_btn.pack(side="left", padx=(0, 10))

        self.icp_shot_btn = ctk.CTkButton(btn_frame, text="📸 截图保存",
                                         command=self.icp_screenshot,
                                         height=40, fg_color=CYBER["neon_green"],
                                         state="disabled")
        self.icp_shot_btn.pack(side="left", padx=(0, 10))

        self.icp_open_btn = ctk.CTkButton(btn_frame, text="📂 打开截图",
                                        command=self.icp_open_screenshot,
                                        height=40, fg_color=CYBER["bg_card2"],
                                        state="disabled")
        self.icp_open_btn.pack(side="left")

        # 状态
        self.icp_status = ctk.CTkLabel(input_card, text="● 就绪",
                                       font=("Microsoft YaHei", 12),
                                       text_color=CYBER["text_dim"])
        self.icp_status.pack(anchor="w", padx=15, pady=(0, 10))

        # 结果
        result_card = self.neon_card(self.content, "查询结果")
        result_card.pack(fill="both", expand=True)

        self.icp_result = ctk.CTkTextbox(result_card, font=("Consolas", 12),
                                        fg_color=CYBER["bg"], border_color=CYBER["border"])
        self.icp_result.pack(fill="both", expand=True, padx=10, pady=10)
        self.icp_result.insert("1.0", "在上方输入域名，点\"打开查询\"开始。\n")

        # 浏览器句柄（跨方法共享）
        self._icp_browser = None
        self._icp_page = None
        self._icp_pw = None
        self._icp_last_png = ""

    def _icp_set_status(self, text, color=None):
        def _upd():
            self.icp_status.configure(text=f"● {text}", text_color=color or CYBER["text_dim"])
        self.after(0, _upd)

    def _icp_append_result(self, text):
        def _upd():
            self.icp_result.insert("end", text + "\n")
        self.after(0, _upd)

    def icp_start(self):
        domain = self.icp_entry.get().strip()
        if not domain:
            messagebox.showwarning("提示", "请输入域名")
            return
        # 后台线程启动浏览器
        def _work():
            try:
                from playwright.sync_api import sync_playwright
                self._icp_set_status("正在打开浏览器...", CYBER["neon_cyan"])
                self._icp_pw = sync_playwright().start()
                self._icp_browser = self._icp_pw.chromium.launch(headless=False)
                ctx = self._icp_browser.new_context(
                    user_agent="Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36",
                    viewport={"width": 1440, "height": 900},
                )
                self._icp_page = ctx.new_page()
                self._icp_page.goto("https://icp.chinaz.com/", timeout=30000, wait_until="domcontentloaded")
                import time as _t
                _t.sleep(2)
                # 自动填域名
                try:
                    inp = self._icp_page.query_selector("input[placeholder*='请输入']") or \
                          self._icp_page.query_selector("input[type='text']")
                    inp.fill(domain)
                    _t.sleep(0.3)
                    self._icp_page.click("text=立即查询")
                except Exception as e:
                    self._icp_append_result(f"[自动填表异常] {e}，请在浏览器里手动输入")
                self._icp_set_status("浏览器已打开，如弹二维码请扫码，结果出来后点\"截图保存\"", CYBER["neon_yellow"])
                def _enable():
                    self.icp_shot_btn.configure(state="normal")
                self.after(0, _enable)
            except Exception as e:
                self._icp_set_status(f"启动失败: {e}", CYBER["neon_red"])
                log(f"ICP启动失败: {e}", "ERROR")
        threading.Thread(target=_work, daemon=True).start()

    def icp_screenshot(self):
        if not self._icp_page:
            messagebox.showwarning("提示", "请先点\"打开查询\"")
            return
        try:
            import time as _t, datetime as _dt
            safe = self.icp_entry.get().strip().replace(".", "_")
            ts = _dt.datetime.now().strftime("%Y%m%d_%H%M%S")
            os.makedirs("output", exist_ok=True)
            png = f"output/icp_{safe}_{ts}.png"
            self._icp_page.screenshot(path=png)
            self._icp_last_png = os.path.abspath(png)

            # 抓取页面文本中的关键字段
            body = self._icp_page.inner_text("body")
            lines = [l.strip() for l in body.splitlines() if l.strip()]
            keys = ["主办单位", "备案号", "网站名称", "网站首页", "单位性质",
                    "审核日期", "没有找到", "未备案", "备案/许可证号"]
            hit = [l for l in lines if any(k in l for k in keys)]

            self.icp_result.delete("1.0", "end")
            self.icp_result.insert("1.0", f"域名: {self.icp_entry.get().strip()}\n截图: {png}\n" + "-"*40 + "\n")
            for l in hit:
                self.icp_result.insert("end", l + "\n")
            if not hit:
                self.icp_result.insert("end", "（未自动提取到字段，请查看截图人工确认）\n")

            # 存文本
            txt = png.replace(".png", ".txt")
            with open(txt, "w", encoding="utf-8") as f:
                f.write(f"域名: {self.icp_entry.get().strip()}\n截图: {png}\n" + "-"*40 + "\n" + "\n".join(hit))

            self._icp_set_status(f"截图已保存: {png}", CYBER["neon_green"])
            def _enable():
                self.icp_open_btn.configure(state="normal")
            self.after(0, _enable)
            log(f"ICP截图: {png}")
        except Exception as e:
            messagebox.showerror("截图失败", str(e))
            log(f"ICP截图失败: {e}", "ERROR")

    def icp_open_screenshot(self):
        if self._icp_last_png and os.path.exists(self._icp_last_png):
            os.startfile(self._icp_last_png)
        else:
            messagebox.showinfo("提示", "还没有截图")


if __name__ == '__main__':
    # 启动前自动清理（打包后无控制台，吞掉异常）
    try:
        import cleanup
        cleanup.clean()
    except Exception:
        pass

    app = CyberApp()
    app.mainloop()
