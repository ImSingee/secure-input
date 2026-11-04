// Version 1: X25519 / HKDF-SHA-256 / AES-256-GCM. No plaintext fallback.
function decodePublicKey(value) {
  const raw = atob(value);
  if (raw.length !== 32 || btoa(raw) !== value) throw new Error('Invalid encryption public key.');
  return Uint8Array.from(raw, c => c.charCodeAt(0));
}

function encodeBase64(bytes) {
  // Avoid spreading large ciphertexts into a function's argument list.
  let raw = '';
  for (const byte of new Uint8Array(bytes)) raw += String.fromCharCode(byte);
  return btoa(raw);
}

function checkEncryption(config, fragment) {
  const pinnedKey = new URLSearchParams(fragment.replace(/^#/, '')).get('e2ee');
  if (pinnedKey !== null && (!config || config.publicKey !== pinnedKey)) {
    throw new Error('Encryption settings do not match the CLI link. Do not enter values; request a new link.');
  }
  if (!config) return;
  if (config.version !== 1) throw new Error('Unsupported encryption version.');
  if (!globalThis.isSecureContext || !globalThis.crypto || !crypto.subtle) {
    throw new Error('Encryption requires HTTPS (or localhost) and a browser with X25519 Web Crypto support.');
  }
  decodePublicKey(config.publicKey);
}

async function encryptSubmission(entries, config, requestID) {
  const recipient = await crypto.subtle.importKey('raw', decodePublicKey(config.publicKey), 'X25519', false, []);
  const ephemeral = await crypto.subtle.generateKey('X25519', false, ['deriveBits']);
  const ephemeralPublicKey = encodeBase64(await crypto.subtle.exportKey('raw', ephemeral.publicKey));
  const shared = new Uint8Array(await crypto.subtle.deriveBits({ name: 'X25519', public: recipient }, ephemeral.privateKey, 256));
  const nonce = crypto.getRandomValues(new Uint8Array(12));
  const encoder = new TextEncoder();
  const context = encoder.encode('secure-input/v1\x00' + requestID + '\x00' + config.publicKey + '\x00' + ephemeralPublicKey);
  const material = await crypto.subtle.importKey('raw', shared, 'HKDF', false, ['deriveKey']);
  shared.fill(0);
  const key = await crypto.subtle.deriveKey(
    { name: 'HKDF', hash: 'SHA-256', salt: nonce, info: context }, material,
    { name: 'AES-GCM', length: 256 }, false, ['encrypt']);
  const plaintext = encoder.encode(JSON.stringify({ entries }));
  if (plaintext.length > 256 * 1024) throw new Error('The submission is too large.');
  try {
    const ciphertext = await crypto.subtle.encrypt(
      { name: 'AES-GCM', iv: nonce, additionalData: context, tagLength: 128 }, key, plaintext);
    return { version: 1, ephemeralPublicKey, nonce: encodeBase64(nonce), ciphertext: encodeBase64(ciphertext) };
  } finally {
    plaintext.fill(0);
  }
}

// Shared files, version 1: AES-256-GCM with a random key from the URL fragment.
function decodeBase64Bytes(value, size) {
  if (typeof value !== 'string') throw new Error('Invalid base64 data.');
  let raw;
  try {
    raw = atob(value);
  } catch (err) {
    throw new Error('Invalid base64 data.');
  }
  if (btoa(raw) !== value || (size !== undefined && raw.length !== size)) {
    throw new Error('Invalid base64 data.');
  }
  return Uint8Array.from(raw, c => c.charCodeAt(0));
}

function decodeFileKey(value) {
  if (!/^[A-Za-z0-9_-]{43}$/.test(value)) throw new Error('The decryption key in this link is malformed. Ask the agent for the full link.');
  try {
    return decodeBase64Bytes(value.replace(/-/g, '+').replace(/_/g, '/') + '=', 32);
  } catch (err) {
    throw new Error('The decryption key in this link is malformed. Ask the agent for the full link.');
  }
}

// Returns the raw key for an encrypted share, or null for an explicitly
// unencrypted one. A key in the link for an "unencrypted" file means the server
// changed the mode, so nothing is shown.
function checkFileShare(encrypted, fragment) {
  const value = new URLSearchParams(fragment.replace(/^#/, '')).get('key');
  if (!encrypted) {
    if (value !== null) throw new Error('This link carries a decryption key, but the server says the file is not encrypted. Refusing to show it.');
    return null;
  }
  if (value === null) throw new Error('This link is missing its decryption key (the part after #). Ask the agent for the full link.');
  if (!globalThis.isSecureContext || !globalThis.crypto || !crypto.subtle) {
    throw new Error('Decryption requires HTTPS (or localhost) and a browser with Web Crypto support.');
  }
  return decodeFileKey(value);
}

function utf8Length(value) {
  return new TextEncoder().encode(value).length;
}

function checkFileMeta(meta) {
  if (!meta || typeof meta !== 'object') throw new Error('Invalid file metadata.');
  const { name, type } = meta;
  const message = meta.message === undefined ? '' : meta.message;
  if (typeof name !== 'string' || name === '' || utf8Length(name) > 255 || name === '.' || name === '..' || /[\/\\\u0000-\u001f\u007f-\u009f]/.test(name)) {
    throw new Error('Invalid file name.');
  }
  if (typeof type !== 'string' || !/^[\x20-\x7e]{1,255}$/.test(type)) throw new Error('Invalid file type.');
  if (typeof message !== 'string' || utf8Length(message) > 2000) throw new Error('Invalid file message.');
  return { name, type, message };
}

// body is the GET /api/files/{id} response; key comes from checkFileShare.
async function openSharedFile(body, key) {
  if (!body || typeof body !== 'object') throw new Error('Invalid server response.');
  if (key === null) {
    if (!body.file || body.encrypted) throw new Error('Expected an unencrypted file from the server.');
    return { meta: checkFileMeta(body.file), content: decodeBase64Bytes(body.file.content) };
  }
  const e = body.encrypted;
  if (!e || body.file || e.version !== 1) throw new Error('Expected an encrypted file; refusing to show anything else.');
  const parts = {
    meta: [decodeBase64Bytes(e.metaNonce, 12), decodeBase64Bytes(e.meta)],
    content: [decodeBase64Bytes(e.contentNonce, 12), decodeBase64Bytes(e.content)],
  };
  if (parts.meta[1].length > 16 * 1024 + 16 || parts.content[1].length > 512 * 1024 + 16) {
    throw new Error('The encrypted file is too large.');
  }
  const aesKey = await crypto.subtle.importKey('raw', key, 'AES-GCM', false, ['decrypt']);
  const open = async part => {
    try {
      return new Uint8Array(await crypto.subtle.decrypt({
        name: 'AES-GCM', iv: parts[part][0], tagLength: 128,
        additionalData: new TextEncoder().encode('secure-input/file/v1\x00' + part),
      }, aesKey, parts[part][1]));
    } catch (err) {
      throw new Error('The file could not be decrypted. The link may be incomplete, or the file was altered.');
    }
  };
  let meta;
  try {
    meta = JSON.parse(new TextDecoder('utf-8', { fatal: true }).decode(await open('meta')));
  } catch (err) {
    if (err.message.startsWith('The file could not be decrypted')) throw err;
    throw new Error('Invalid file metadata.');
  }
  return { meta: checkFileMeta(meta), content: await open('content') };
}
