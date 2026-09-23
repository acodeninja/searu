'use strict';
// Drive the target as a real browser to understand it: render the app, dismiss its welcome/cookie
// overlays (which otherwise intercept every click), optionally authenticate, then actively drive the
// SPA — follow anchors (Angular sets href on `<a routerLink>`), open the side-nav and account/cart
// menus so their links load, submit the search box, scroll for lazy content — recording every
// same-origin API call it makes. Only newline-delimited observation records ({kind,value,detail}) go to
// stdout; everything else goes to stderr. Navigation only: it opens menus, follows links and searches;
// it never clicks buy/delete/logout.
const { chromium } = require('playwright');

function arg(name, fallback) {
  const i = process.argv.indexOf(name);
  return i >= 0 && i + 1 < process.argv.length ? process.argv[i + 1] : fallback;
}

const target = arg('--url');
const out = arg('--out');
const email = arg('--login-email');
const password = arg('--login-password');
const depth = parseInt(arg('--depth', '3'), 10);
const maxRoutes = parseInt(arg('--max-routes', '60'), 10);
const maxSeconds = parseInt(arg('--max-seconds', '240'), 10);
// Extra routes to drive that no link exposes (an app's authenticated or hidden routes); comma-separated
// paths like `/#/wallet,/#/administration`. A playbook supplies these for a recognised target.
const seed = arg('--seed', '');

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
  const deadline = Date.now() + maxSeconds * 1000;

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
    try { await page.waitForTimeout(1000); } catch { /* ignore */ }
  }

  // A welcome banner and a cookie-consent bar overlay the app on first load and intercept every click,
  // so no menu/search interaction works until they are dismissed. Cheap no-op once they are gone.
  async function dismissOverlays() {
    for (const selector of [
      'button[aria-label="Close Welcome Banner"]',
      'button[aria-label="dismiss cookie message"]',
      'a.cc-btn.cc-dismiss',
      '.cc-dismiss',
    ]) {
      try {
        const el = await page.$(selector);
        if (el) { await el.click({ timeout: 1500 }).catch(() => {}); await page.waitForTimeout(150); }
      } catch { /* ignore */ }
    }
  }

  // Every same-origin route linked by a real anchor on the current DOM. Angular sets href on
  // `<a routerLink>`, so once a menu is open its links appear here — no fragile click-navigation needed.
  async function collectHrefs() {
    const urls = [];
    try {
      const hrefs = await page.$$eval('a[href]', (as) => as.map((a) => a.getAttribute('href')).filter(Boolean));
      for (const href of hrefs) {
        try { urls.push(new URL(href, page.url()).toString()); } catch { /* skip */ }
      }
    } catch { /* ignore */ }
    return urls.filter((u) => originOf(u) === origin);
  }

  // Benign driving of the current route: open the side-nav and account/cart menus so their links load,
  // submit the search box (a read-only GET), scroll for lazy content. Menus/search only — never a
  // mutating control. The request listener turns any resulting XHR into endpoint/param observations.
  async function drive() {
    for (const selector of [
      'button[aria-label*="Open Sidenav" i]',
      'button[aria-label*="Account" i]',
      '#navbarAccount',
      'button[aria-label*="shopping cart" i]',
    ]) {
      try {
        const el = await page.$(selector);
        if (el) { await el.click({ timeout: 1500 }).catch(() => {}); await page.waitForTimeout(250); }
      } catch { /* ignore */ }
    }
    try {
      const icon = await page.$('button[aria-label*="Open search" i], button[aria-label*="Search" i]');
      if (icon) { await icon.click({ timeout: 1500 }).catch(() => {}); await page.waitForTimeout(200); }
      const box = await page.$('#searchQuery input, app-mat-search-bar input, input[aria-label*="search" i], input[type=text]');
      if (box) { await box.fill('a').catch(() => {}); await page.keyboard.press('Enter').catch(() => {}); await page.waitForTimeout(600); }
    } catch { /* ignore */ }
    try { await page.evaluate(() => window.scrollTo(0, document.body.scrollHeight)); await page.waitForTimeout(200); } catch { /* ignore */ }
  }

  const visited = new Set();
  const enqueued = new Set();
  const queue = [];
  const enqueue = (url, d) => {
    if (originOf(url) !== origin || enqueued.has(url) || d > depth) return;
    enqueued.add(url);
    queue.push({ u: url, d });
  };
  enqueue(target, 0);
  for (const raw of seed.split(',')) {
    const p = raw.trim();
    if (!p) continue;
    if (/^https?:/i.test(p)) { enqueue(p, 0); continue; }
    if (p.startsWith('/')) { enqueue(origin + p, 0); continue; }
    enqueue(origin + '/' + p, 0);
  }

  await visit(target);
  await dismissOverlays();

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
        await dismissOverlays();
        emit('note', 'login-attempted', email);
      } else {
        emit('note', 'login-form-not-found', origin + '/#/login');
      }
    } catch (e) { emit('note', 'login-error', String((e && e.message) || e)); }
  }

  let shots = 0;
  while (queue.length && visited.size < maxRoutes && Date.now() < deadline) {
    const { u, d } = queue.shift();
    if (visited.has(u)) continue;
    visited.add(u);

    await visit(u);
    emit('route', routeOf(page.url()));
    if (out) { try { await page.screenshot({ path: `${out}/route-${shots++}.png` }); } catch { /* ignore */ } }
    try {
      const forms = await page.$$eval('form', (fs) =>
        fs.map((f) => Array.from(f.querySelectorAll('input,select,textarea'))
          .map((i) => i.getAttribute('name') || i.getAttribute('formcontrolname') || i.getAttribute('id'))
          .filter(Boolean)));
      for (const fields of forms) { if (fields.length) emit('form', routeOf(page.url()), fields.join(',')); }
    } catch { /* ignore */ }

    if (d < depth && Date.now() < deadline) {
      for (const url of await collectHrefs()) enqueue(url, d + 1);
      await drive();
      const landed = page.url();
      if (originOf(landed) === origin) { emit('route', routeOf(landed)); enqueue(landed, d + 1); }
      for (const url of await collectHrefs()) enqueue(url, d + 1);
    }
  }

  emit('note', 'routes-visited', String(visited.size));
  await browser.close();
})().catch((e) => { console.error(e); process.exit(1); });
