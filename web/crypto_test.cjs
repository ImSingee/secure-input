// Runs the exact browser crypto source, using Node's Web Crypto implementation.
const fs = require('node:fs');
const vm = require('node:vm');
const assert = require('node:assert/strict');
const { webcrypto } = require('node:crypto');
globalThis.crypto = webcrypto;
globalThis.isSecureContext = true;
vm.runInThisContext(fs.readFileSync('web/crypto.js', 'utf8'));
(async () => {
  const { config, id, plaintext } = JSON.parse(fs.readFileSync(0, 'utf8'));
  const fragment = '#e2ee=' + encodeURIComponent(config.publicKey);
  checkEncryption(config, fragment);
  assert.throws(() => checkEncryption(null, fragment));
  assert.throws(() => checkEncryption({ ...config, publicKey: 'wrong' }, fragment));
  assert.throws(() => checkEncryption({ ...config, version: 2 }, fragment));
  globalThis.isSecureContext = false;
  assert.throws(() => checkEncryption(config, fragment));
  globalThis.isSecureContext = true;
  checkEncryption(null, ''); // Explicit legacy mode only.
  const entries = JSON.parse(plaintext).entries;
  const first = await encryptSubmission(entries, config, id);
  const second = await encryptSubmission(entries, config, id);
  assert.notEqual(first.ephemeralPublicKey, second.ephemeralPublicKey);
  assert.notEqual(first.nonce, second.nonce);
  assert.notEqual(first.ciphertext, second.ciphertext);
  assert(!JSON.stringify(first).includes(entries[0].value));
  await assert.rejects(() => encryptSubmission([{key:'TOKEN',value:'x'.repeat(256*1024)}],config,id));
  process.stdout.write(JSON.stringify(first));
})().catch(error => { console.error(error); process.exitCode = 1; });
