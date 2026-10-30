"""
ICP 备案自动查询 + 截图脚本
==========================
用法（在你自己电脑上跑，会弹出浏览器窗口）:
    cd D:\自动化流程\ai-vuln-pipeline
    .\\venv\\Scripts\\python.exe icp_auto.py lldong.com

流程:
1. 自动弹出浏览器，打开站长之家 ICP 查询
2. 自动填入域名、自动点"立即查询"
3. 如果弹登录二维码 → 你用手机微信扫一下（10秒的事）
4. 备案结果出来后，回到黑色控制台窗口按【回车】
5. 自动截图 + 自动抓备案主体/备案号文本，存到 output/ 目录

为什么不能全自动:
站长之家/工信部都有登录墙和滑块验证码，硬脚本会被封IP。
但浏览器窗口一弹出来，你扫一下码就完事，比写一堆反检测代码快得多。
"""
import sys, os, time, datetime
from playwright.sync_api import sync_playwright

def main(domain):
    ts = datetime.datetime.now().strftime("%Y%m%d_%H%M%S")
    safe = domain.replace(".", "_")
    os.makedirs("output", exist_ok=True)
    png_path = f"output/icp_{safe}_{ts}.png"
    txt_path = f"output/icp_{safe}_{ts}.txt"

    with sync_playwright() as p:
        browser = p.chromium.launch(headless=False)
        ctx = browser.new_context(
            user_agent="Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36",
            viewport={"width": 1440, "height": 900},
        )
        page = ctx.new_page()

        print(f"[1/3] 打开站长之家ICP查询...")
        page.goto("https://icp.chinaz.com/", timeout=30000, wait_until="domcontentloaded")
        time.sleep(2)

        print(f"[2/3] 自动填入域名 {domain} 并点击查询...")
        try:
            inp = page.query_selector("input[placeholder*='请输入']") or page.query_selector("input[type='text']")
            inp.fill(domain)
            time.sleep(0.3)
            page.click("text=立即查询")
        except Exception as e:
            print(f"    自动填表异常({e})，请在浏览器里手动输入域名点查询")

        print("\n" + "="*55)
        print("  如果弹出微信登录二维码 → 用手机微信扫一下")
        print("  如果出现滑块验证码 → 拖动滑块")
        print("  等备案结果表格（主办单位/备案号）完整显示后")
        print("  回到这个黑色窗口按【回车键】")
        print("="*55)
        input("  >> 结果出来后按回车截图: ")

        print(f"[3/3] 截图保存: {png_path}")
        page.screenshot(path=png_path, full_page=False)

        body = page.inner_text("body")
        lines = [l.strip() for l in body.splitlines() if l.strip()]
        keys = ["主办单位", "备案号", "网站名称", "网站首页", "单位性质",
                "审核日期", "没有找到", "未备案", "无备案", "备案/许可证号"]
        hit = [l for l in lines if any(k in l for k in keys)]
        with open(txt_path, "w", encoding="utf-8") as f:
            f.write(f"ICP备案查询结果\n域名: {domain}\n时间: {datetime.datetime.now()}\n"
                    f"截图: {png_path}\n" + "-"*40 + "\n")
            f.write("\n".join(hit) if hit else "（未自动提取到字段，请直接看截图）")

        print(f"       文本: {txt_path}")
        print(f"\n完成！把 {png_path} 上传补天作为归属证据。")
        browser.close()

if __name__ == "__main__":
    if len(sys.argv) < 2:
        print("用法: python icp_auto.py <域名>")
        sys.exit(1)
    main(sys.argv[1])
