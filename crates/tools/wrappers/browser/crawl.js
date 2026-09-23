'use strict';
// Drive the target as a real browser to understand it: render the app, optionally authenticate, crawl
// its client-side routes and record every same-origin API call it makes. Only newline-delimited
// observation records ({kind,value,detail}) go to stdout; everything else goes to stderr so searu's
// parser sees a clean stream.
const { chromium } = require('playwright');

function arg(name, fallback) {
  const i = process.argv.indexOf(name);
  return i >= 0 && i + 1 < process.argv.length ? process.argv[i + 1] : fallback;
}

const target = arg('--url');
const out = arg('--out');
const email = arg('--login-email');
const password = arg('--login-password');
const depth = parseInt(arg('--depth', '2'), 10);
const maxRoutes = parseInt(arg('--max-routes', '25'), 10);

function emit(kind, value, detail) {
  if (!value) return;
  const record = detail ? { kind, value, detail } : { kind, value };
  process.stdout.write(JSON.stringify(record) + '\n');
}

function originOf(u) {
  try { return new URL(u).origin; } catch { return null; }
}
function pathOf(u) {
  try { return new URL(u).pathname; } catch { return null; }
}
function routeOf(u) {
  const hash = u.indexOf('#');
  return hash >= 0 ? '/#' + u.slice(hash + 1) : pathOf(u);
}

(async () => {
  if (!target) { console.error('browser: missing --url'); process.exit(2); }
  const origin = originOf(target);
  const deadline = Date.now() + 120000;

  const browser = await chromium.launch({ args: ['--no-sandbox'] });
  const context = await browser.newContext({ ignoreHTTPSErrors: true });
  const page = await context.newPage();

  const seenApi = new Set();
  const seenParam = new Set();
  const isApiPath = (p) => /^\/(rest|api|graphql)(\/|$)/.test(p);

  page.on('request', (req) => {
    try {
      const u = req.url();
      if (originOf(u) !== origin) return;
      const p = pathOf(u);
      if (!p) return;
      const rt = req.resourceType();
      if (rt !== 'xhr' && rt !== 'fetch' && !isApiPath(p)) return;
      const key = req.method() + ' ' + p;
      if (!seenApi.has(key)) { seenApi.add(key); emit('endpoint', p, req.method()); }
      for (const name of new URL(u).searchParams.keys()) {
        const k = p + '?' + name;
        if (!seenParam.has(k)) { seenParam.add(k); emit('param', name, p); }
      }
      const body = req.postData();
      if (body) {
        let names = [];
        try {
          const j = JSON.parse(body);
          if (j && typeof j === 'object') names = Object.keys(j);
        } catch { names = body.split('&').map((kv) => kv.split('=')[0]).filter(Boolean); }
        for (const name of names) {
          const k = p + '#' + name;
          if (!seenParam.has(k)) { seenParam.add(k); emit('param', name, p); }
        }
      }
    } catch { /* ignore a single malformed request */ }
  });

  async function visit(u) {
    try { await page.goto(u, { waitUntil: 'domcontentloaded', timeout: 15000 }); } catch { /* keep going */ }
    try { await page.waitForTimeout(1500); } catch { /* ignore */ }
  }

  await visit(target);

  if (email && password) {
    try {
      await visit(origin + '/#/login');
      const pw = await page.$('input[type=password]');
      if (pw) {
        const em = await page.$('input[type=email], input[name*=email i], input[type=text], #email');
        if (em) await em.fill(email);
        await pw.fill(password);
        await page.click('button[type=submit], #loginButton, button:has-text("Log in")').catch(() => {});
        await page.keyboard.press('Enter').catch(() => {});
        await page.waitForTimeout(2000);
        emit('note', 'login-attempted', email);
      } else {
        emit('note', 'login-form-not-found', origin + '/#/login');
      }
    } catch (e) { emit('note', 'login-error', String((e && e.message) || e)); }
  }

  const visited = new Set();
  const queue = [{ u: target, d: 0 }];
  let shots = 0;
  while (queue.length && visited.size < maxRoutes && Date.now() < deadline) {
    const { u, d } = queue.shift();
    if (visited.has(u)) continue;
    visited.add(u);
    await visit(u);
    const route = routeOf(u);
    emit('route', route);
    if (out) { try { await page.screenshot({ path: `${out}/route-${shots++}.png` }); } catch { /* ignore */ } }
    try {
      const forms = await page.$$eval('form', (fs) =>
        fs.map((f) => Array.from(f.querySelectorAll('input,select,textarea'))
          .map((i) => i.getAttribute('name') || i.getAttribute('formcontrolname') || i.getAttribute('id'))
          .filter(Boolean)));
      for (const fields of forms) { if (fields.length) emit('form', route, fields.join(',')); }
    } catch { /* ignore */ }
    if (d < depth) {
      let hrefs = [];
      try { hrefs = await page.$$eval('a[href]', (as) => as.map((a) => a.getAttribute('href')).filter(Boolean)); } catch { /* ignore */ }
      for (const href of hrefs) {
        let full;
        try { full = new URL(href, page.url()).toString(); } catch { continue; }
        if (originOf(full) !== origin) continue;
        if (!visited.has(full) && !queue.some((q) => q.u === full)) queue.push({ u: full, d: d + 1 });
      }
    }
  }

  emit('note', 'routes-visited', String(visited.size));
  await browser.close();
})().catch((e) => { console.error(e); process.exit(1); });
