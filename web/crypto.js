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
