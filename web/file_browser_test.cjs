// Real browser test for shared files. Build the CLI and install Playwright/Chromium first.
const assert = require('node:assert/strict');
const {spawn, spawnSync} = require('node:child_process');
const fs = require('node:fs');
const os = require('node:os');
const path = require('node:path');
const {chromium} = require('playwright');
const binary = path.resolve(process.env.SECURE_INPUT_BINARY || './secure-input');
const port = process.env.SECURE_INPUT_TEST_PORT || '18988';
const base = 'http://127.0.0.1:' + port;
const dir = fs.mkdtempSync(path.join(os.tmpdir(), 'secure-input-files-'));
const server = spawn(binary, ['serve', '--addr', '127.0.0.1:' + port], {stdio: 'ignore'});
const sleep = ms => new Promise(r => setTimeout(r, ms));
// 1x1 red PNG.
const png = Buffer.from('iVBORw0KGgoAAAANSUhEUgAAAAEAAAABCAYAAAAfFcSJAAAADUlEQVR42mP8z8DwHwAFBQIAX8jx0gAAAABJRU5ErkJggg==', 'base64');

function share(name, content, extra = []) {
  const file = path.join(dir, name);
  fs.writeFileSync(file, content);
  const result = spawnSync(binary, ['share', '--server', base, '--file', file, ...extra], {encoding: 'utf8'});
  assert.equal(result.status, 0, result.stderr);
  const url = result.stdout.trim();
  return {url, id: new URL(url).pathname.split('/').pop()};
}

(async () => {
  for (let i = 0; i < 50; i++) { try { if ((await fetch(base)).ok) break; } catch {} await sleep(100); }
  const browser = await chromium.launch({headless: true});
  try {
    const context = await browser.newContext({acceptDownloads: true});
    await context.grantPermissions(['clipboard-read', 'clipboard-write'], {origin: base});
    const page = await context.newPage();
    const errors = [];
    page.on('pageerror', e => errors.push(String(e)));
    page.on('console', m => { if (m.type() === 'error' && !m.text().includes('410')) errors.push(m.text()); });
    let dialogs = 0;
    page.on('dialog', d => { dialogs++; d.accept(); });

    // Encrypted text: the server only relays ciphertext; the page decrypts and shows it.
    const text = '# Report\n\n<script>alert("xss")</script> secret-测试-🔐\n';
    const markupName = '<img src=x onerror=alert(1)>report.md';
    const doc = share('report.md', text, ['--name', markupName, '--message', 'Build summary <i>for you</i>']);
    let apiBody;
    page.on('response', async r => { if (r.url().includes('/api/files/') && r.request().method() === 'GET') apiBody = await r.text().catch(() => ''); });
    await page.goto(doc.url);
    await page.locator('#preview pre').waitFor();
    assert.equal(await page.locator('#preview pre').textContent(), text);
    assert.equal(await page.locator('#file-name').textContent(), markupName);
    assert.equal(await page.locator('#file-name img').count(), 0);
    assert.equal(await page.locator('#message').textContent(), 'Build summary <i>for you</i>');
    assert.match(await page.locator('#countdown').textContent(), /Removed from the server automatically in (29:[0-5]\d|30:00)/);
    assert(apiBody && !apiBody.includes('secret') && !apiBody.includes('report') && JSON.parse(apiBody).encrypted);
    assert(!(await page.content()).includes('<script>alert'), 'file text must not become markup');
    await page.locator('#copy').click();
    assert.equal(await page.evaluate(() => navigator.clipboard.readText()), text);
    const [download] = await Promise.all([page.waitForEvent('download'), page.locator('#download').click()]);
    assert.match(download.suggestedFilename(), /report\.md$/);
    assert.equal(fs.readFileSync(await download.path(), 'utf8'), text);
    // Delete from the server; the open tab keeps its copy.
    await page.locator('#delete').click();
    await page.getByText('Deleted from the server. This tab keeps its copy until you close it.').waitFor();
    assert.equal(dialogs, 1);
    assert(await page.locator('#delete').isDisabled());
    assert.equal(await page.locator('#preview pre').textContent(), text);
    assert.equal((await fetch(base + '/api/files/' + doc.id)).status, 410);
    await page.reload();
    await page.getByText('This file has expired or was deleted.').waitFor();

    // Images are previewed from a blob: URL allowed by the CSP.
    const image = share('pixel.png', png);
    await page.goto(image.url);
    await page.locator('#preview img').waitFor();
    await page.waitForFunction(() => document.querySelector('#preview img').naturalWidth === 1);
    assert(await page.locator('#copy').isHidden());

    // Binary files offer only a download.
    const binaryFile = share('data.bin', Buffer.from([0, 1, 2, 3, 255, 254]));
    await page.goto(binaryFile.url);
    await page.getByText('No preview for this file type. Download it to open it.').waitFor();
    assert(await page.locator('#download').isEnabled());

    // A link without its key shows nothing, but deletion still works.
    const keyless = share('keyless.txt', 'keyless secret');
    await page.goto(keyless.url.split('#')[0]);
    await page.locator('#error:not([hidden])').waitFor();
    assert.match(await page.locator('#error').textContent(), /missing its decryption key/);
    assert(await page.locator('#download').isDisabled());
    await page.locator('#delete').click();
    await page.getByText('Deleted from the server.').waitFor();
    assert.equal((await fetch(base + '/api/files/' + keyless.id)).status, 410);

    // A wrong key or altered ciphertext fails authentication instead of showing garbage.
    const altered = share('altered.txt', 'altered secret');
    await page.goto(altered.url.replace(/key=./, m => 'key=' + (m.endsWith('A') ? 'B' : 'A')));
    await page.locator('#error:not([hidden])').waitFor();
    assert.match(await page.locator('#error').textContent(), /could not be decrypted/);
    assert(await page.locator('#preview').isHidden());

    // The countdown ends with the server-side expiry.
    const clockPage = await context.newPage();
    await clockPage.clock.install();
    const timed = share('timed.txt', 'timed secret');
    await clockPage.goto(timed.url);
    await clockPage.locator('#preview pre').waitFor();
    await clockPage.clock.fastForward('29:00');
    assert.match(await clockPage.locator('#countdown').textContent(), /in 0:[0-5]\d/);
    assert.match(await clockPage.locator('#countdown').getAttribute('class'), /warn/);
    await clockPage.clock.fastForward('02:00');
    await clockPage.getByText('Expired and removed from the server. This tab keeps its copy until you close it.').waitFor();
    assert(await clockPage.locator('#delete').isDisabled());
    await clockPage.close();

    // Explicit plaintext works and is labelled; a key in its link means tampering.
    const plain = share('plain.txt', 'plain contents', ['--no-encryption']);
    assert(!plain.url.includes('#'));
    await page.goto(plain.url);
    await page.getByText('Encryption is disabled for this file.', {exact: false}).waitFor();
    await page.locator('#preview pre').waitFor();
    assert.equal(await page.locator('#preview pre').textContent(), 'plain contents');
    await page.goto('about:blank'); // a fragment-only change would not reload the page
    await page.goto(plain.url + '#key=' + 'A'.repeat(43));
    await page.locator('#error:not([hidden])').waitFor();
    assert.match(await page.locator('#error').textContent(), /not encrypted/);

    // The 512 KiB limit is enforced by the CLI.
    const big = path.join(dir, 'big.txt');
    fs.writeFileSync(big, Buffer.alloc(512 * 1024 + 1, 'x'));
    const tooBig = spawnSync(binary, ['share', '--server', base, '--file', big], {encoding: 'utf8'});
    assert.equal(tooBig.status, 1);
    assert.match(tooBig.stderr, /512 KiB/);

    assert.deepEqual(errors, []);
    console.log('PASS: encrypted text/image/binary previews, copy, download, delete, missing/wrong key, countdown expiry, plaintext opt-out, size limit.');
  } finally { await browser.close(); }
})().catch(error => { console.error(error); process.exitCode = 1; }).finally(() => { server.kill(); fs.rmSync(dir, {recursive: true, force: true}); });
