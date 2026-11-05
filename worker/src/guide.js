// /archive 是接口而不是网页。GET 打开时返回中文说明，避免访问者误判为服务异常。
export const PAGE_URL = 'https://vrbtc.github.io/crypto-address-generator/';

export const GUIDE_HTML = `<!doctype html>
<html lang="zh-CN">
<head>
<meta charset="utf-8">
<meta name="viewport" content="width=device-width, initial-scale=1">
<title>归档接口说明</title>
<style>
  body { margin: 0; padding: 40px 20px; background: #f6f8fa; color: #1f2328;
         font: 16px/1.7 -apple-system, "Segoe UI", "Microsoft YaHei", sans-serif; }
  main { max-width: 720px; margin: 0 auto; background: #fff; border: 1px solid #d0d7de;
         border-radius: 12px; padding: 28px 32px; }
  h1 { font-size: 1.35rem; margin: 0 0 8px; }
  h2 { font-size: 1.05rem; margin: 24px 0 4px; }
  p { margin: 12px 0; color: #57606a; }
  a.btn { display: inline-block; margin: 8px 0 4px; padding: 10px 18px; border-radius: 8px;
          background: #238636; color: #fff; text-decoration: none; font-weight: 600; }
  a { color: #0969da; }
  code { padding: 2px 6px; background: #f6f8fa; border-radius: 6px;
         font-family: Consolas, "Courier New", monospace; }
  pre { padding: 14px; background: #f6f8fa; border-radius: 6px; overflow-x: auto;
        font: 0.85rem/1.6 Consolas, "Courier New", monospace; white-space: pre-wrap; }
</style>
</head>
<body>
<main>
  <h1>这是归档接口，不是网页</h1>
  <p><code>/archive</code> 只接受 POST 请求，由地址生成器页面在后台自动调用。用浏览器地址栏打开属于 GET 请求，所以看不到页面内容。</p>
  <a class="btn" href="${PAGE_URL}">打开地址生成器</a>
  <p>也可以访问本域名根路径 <a href="/">https://s.320212.xyz/</a>，会自动跳转到生成器页面。输入文本生成地址后归档自动完成，无需手动调用接口。</p>
  <h2>查看全部生成记录</h2>
  <p><a href="/records">https://s.320212.xyz/records</a> 是可直接打开的记录表格页（时间、原文片段与三个地址）。首次需用专属链接授权一次，之后浏览器会记住，直接打开即可，无需调用接口。</p>
  <h2>接口自检</h2>
  <p>健康检查（可直接打开）：<a href="/health">https://s.320212.xyz/health</a></p>
  <p>手动调用示例（可直接运行，会向私有仓库追加一条测试记录）：</p>
  <pre>curl -X POST https://s.320212.xyz/archive \\
  -H 'Content-Type: application/json' \\
  -H 'Origin: https://vrbtc.github.io' \\
  -d '{"time":"2026-11-05 10:00:00","input_head":"","input_tail":"","eth":"0xb1a2adc8139fdc39db95ab66920463c0a47229f7","btc_legacy":"1HyQAhSW7HrrE2VV9f3uBD9HTyajeihPZ1","btc_segwit":"bc1qhgk22w8sylxl7c40awxpyhypmtk0erwtjwnfph"}'</pre>
  <p>归档只记录时间、地址与脱敏片段，不记录原文、SHA256 私钥或 WIF 私钥。</p>
</main>
</body>
</html>`;
