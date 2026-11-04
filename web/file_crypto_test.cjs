// Runs the exact browser file-decryption source against Go-encrypted shares.
const fs = require('node:fs');
const vm = require('node:vm');
const assert = require('node:assert/strict');
const { webcrypto, createHash } = require('node:crypto');
globalThis.crypto = webcrypto;
globalThis.isSecureContext = true;
vm.runInThisContext(fs.readFileSync('web/crypto.js', 'utf8'));
(async () => {
  const { key, encrypted, plain } = JSON.parse(fs.readFileSync(0, 'utf8'));
  const raw = checkFileShare(true, '#key=' + key);
  // Fragment mismatches fail before anything is fetched or shown.
  assert.throws(() => checkFileShare(true, ''), /missing its decryption key/);
  assert.throws(() => checkFileShare(true, '#key=' + key.slice(1)), /malformed/);
  assert.throws(() => checkFileShare(true, '#key=' + key.slice(0, -1) + '!'), /malformed/);
  assert.throws(() => checkFileShare(false, '#key=' + key), /not encrypted/);
  assert.equal(checkFileShare(false, ''), null);
  globalThis.isSecureContext = false;
  assert.throws(() => checkFileShare(true, '#key=' + key), /HTTPS/);
  globalThis.isSecureContext = true;

  const opened = await openSharedFile(encrypted, raw);
  // Downgrades and mode confusion are refused in both directions.
  await assert.rejects(() => openSharedFile(plain, raw), /Expected an encrypted file/);
  await assert.rejects(() => openSharedFile(encrypted, null), /Expected an unencrypted file/);
  await assert.rejects(() => openSharedFile({ ...encrypted, file: plain.file }, raw), /Expected an encrypted file/);
  const flip = value => { const b = Buffer.from(value, 'base64'); b[b.length - 1] ^= 1; return b.toString('base64'); };
  const e = encrypted.encrypted;
  for (const changed of [
    { ...e, meta: flip(e.meta) }, { ...e, content: flip(e.content) }, { ...e, metaNonce: flip(e.metaNonce) },
    { ...e, meta: e.content, metaNonce: e.contentNonce, content: e.meta, contentNonce: e.metaNonce },
  ]) {
    // A swapped 512 KiB content part is already too large to be metadata.
    await assert.rejects(() => openSharedFile({ encrypted: changed }, raw), /could not be decrypted|too large/);
  }
  const otherKey = webcrypto.getRandomValues(new Uint8Array(32));
  await assert.rejects(() => openSharedFile(encrypted, otherKey), /could not be decrypted/);
  await assert.rejects(() => openSharedFile({ encrypted: { ...e, content: e.content + ' ' } }, raw), /Invalid base64/);

  const legacy = await openSharedFile(plain, null);
  assert.deepEqual(legacy.meta, opened.meta);
  assert.deepEqual(Buffer.from(legacy.content), Buffer.from(opened.content));
  assert.throws(() => checkFileMeta({ name: 'a/b', type: 'text/plain' }), /file name/);
  assert.throws(() => checkFileMeta({ name: 'a', type: 'text/plain\n' }), /file type/);

  process.stdout.write(JSON.stringify({
    meta: opened.meta,
    sha256: createHash('sha256').update(opened.content).digest('hex'),
  }));
})().catch(error => { console.error(error); process.exitCode = 1; });
