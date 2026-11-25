import { AdminPasskeyRow, Env } from './types';
import { addMsIso, generateId, getPlatformName, nowUtcIso, randomHex, writeAuditLog } from './utils';

function base64UrlEncode(bytes: Uint8Array): string {
  let bin = '';
  for (let i = 0; i < bytes.length; i++) bin += String.fromCharCode(bytes[i]);
  return btoa(bin).replace(/\+/g, '-').replace(/\//g, '_').replace(/=+$/g, '');
}

function base64UrlDecode(str: string): Uint8Array {
  const padded = str.replace(/-/g, '+').replace(/_/g, '/') + '==='.slice((str.length + 3) % 4);
  const bin = atob(padded);
  const out = new Uint8Array(bin.length);
  for (let i = 0; i < bin.length; i++) out[i] = bin.charCodeAt(i);
  return out;
}

function bytesEqual(a: Uint8Array, b: Uint8Array): boolean {
  if (a.length !== b.length) return false;
  let diff = 0;
  for (let i = 0; i < a.length; i++) diff |= a[i] ^ b[i];
  return diff === 0;
}

/** 将 ASN.1 DER 编码的 ECDSA (P-256) 签名转换为 Web Crypto 所需的 64 字节 raw (r || s) */
function derToRawEcdsaP256(der: Uint8Array): Uint8Array | null {
  if (der.length < 8 || der[0] !== 0x30) return null;
  let offset = 2;
  if (der[1] & 0x80) offset += der[1] & 0x7f;
  if (der[offset] !== 0x02) return null;
  const rLen = der[offset + 1];
  const rStart = offset + 2;
  const rBytes = der.slice(rStart, rStart + rLen);
  offset = rStart + rLen;
  if (der[offset] !== 0x02) return null;
  const sLen = der[offset + 1];
  const sStart = offset + 2;
  const sBytes = der.slice(sStart, sStart + sLen);

  const normalize32 = (src: Uint8Array): Uint8Array | null => {
    let start = 0;
    while (start < src.length && src[start] === 0) start++;
    const trimmed = src.slice(start);
    if (trimmed.length > 32) return null;
    const out = new Uint8Array(32);
    out.set(trimmed, 32 - trimmed.length);
    return out;
  };

  const r = normalize32(rBytes);
  const s = normalize32(sBytes);
  if (!r || !s) return null;
  const raw = new Uint8Array(64);
  raw.set(r, 0);
  raw.set(s, 32);
  return raw;
}

async function importPasskeyPublicKey(spkiB64Url: string, algorithm: number): Promise<CryptoKey> {
  const spki = base64UrlDecode(spkiB64Url);
  if (algorithm === -7) {
    return crypto.subtle.importKey('spki', spki, { name: 'ECDSA', namedCurve: 'P-256' }, false, ['verify']);
  }
  if (algorithm === -257) {
    return crypto.subtle.importKey('spki', spki, { name: 'RSASSA-PKCS1-v1_5', hash: 'SHA-256' }, false, ['verify']);
  }
  throw new Error(`不支持的通行密钥算法 (${algorithm})，仅支持 ES256 (-7) 与 RS256 (-257)。`);
}

async function issueChallenge(env: Env, purpose: 'register' | 'login'): Promise<string> {
  const now = nowUtcIso();
  const expiresAt = addMsIso(now, 5 * 60 * 1000);
  const challenge = base64UrlEncode(crypto.getRandomValues(new Uint8Array(32)));

  // 顺便清理过期 challenge
  await env.DB.batch([
    env.DB.prepare('DELETE FROM admin_passkey_challenges WHERE expires_at <= ?').bind(now),
    env.DB.prepare(
      `INSERT INTO admin_passkey_challenges (challenge, purpose, expires_at, created_at) VALUES (?, ?, ?, ?)`
    ).bind(challenge, purpose, expiresAt, now),
  ]);
  return challenge;
}

async function consumeChallenge(env: Env, challenge: string, purpose: 'register' | 'login'): Promise<boolean> {
  const row = await env.DB.prepare(
    'SELECT challenge, purpose, expires_at FROM admin_passkey_challenges WHERE challenge = ?'
  )
    .bind(challenge)
    .first<{ challenge: string; purpose: string; expires_at: string }>();
  if (!row) return false;
  await env.DB.prepare('DELETE FROM admin_passkey_challenges WHERE challenge = ?').bind(challenge).run();
  if (row.purpose !== purpose) return false;
  if (Date.now() > Date.parse(row.expires_at)) return false;
  return true;
}

/** 生成 Passkey 注册参数（仅限已登录的人类管理员调用） */
export async function createPasskeyRegisterOptions(request: Request, env: Env) {
  const url = new URL(request.url);
  const [challenge, platformName, existing] = await Promise.all([
    issueChallenge(env, 'register'),
    getPlatformName(env),
    env.DB.prepare('SELECT credential_id, transports FROM admin_passkeys').all<{
      credential_id: string;
      transports: string;
    }>(),
  ]);

  return {
    challenge,
    rp: {
      name: platformName,
      id: url.hostname,
    },
    user: {
      id: base64UrlEncode(new TextEncoder().encode(`admin:${url.hostname}`)),
      name: `admin@${url.hostname}`,
      displayName: `${platformName} Admin`,
    },
    pubKeyCredParams: [
      { type: 'public-key', alg: -7 },
      { type: 'public-key', alg: -257 },
    ],
    timeout: 120000,
    attestation: 'none',
    authenticatorSelection: {
      residentKey: 'preferred',
      userVerification: 'preferred',
    },
    excludeCredentials: (existing.results ?? []).map((r) => ({
      type: 'public-key',
      id: r.credential_id,
      transports: JSON.parse(r.transports || '[]'),
    })),
  };
}

/** 校验并保存新注册的 Passkey */
export async function verifyAndSavePasskey(
  request: Request,
  env: Env,
  actor: string,
  body: {
    credential_id?: string;
    client_data_json?: string;
    authenticator_data?: string;
    public_key_spki?: string;
    algorithm?: number;
    transports?: string[];
    label?: string;
  }
): Promise<{ ok: true; passkey: AdminPasskeyRow } | { ok: false; error: string }> {
  const credentialId = String(body.credential_id || '').trim();
  const clientDataB64 = String(body.client_data_json || '').trim();
  const authDataB64 = String(body.authenticator_data || '').trim();
  const spkiB64 = String(body.public_key_spki || '').trim();
  const algorithm = Number(body.algorithm);
  const label = String(body.label || 'Admin Passkey').trim().slice(0, 64) || 'Admin Passkey';

  if (!credentialId || !clientDataB64 || !authDataB64 || !spkiB64) {
    return { ok: false, error: '缺少通行密钥注册必要字段，请使用现代浏览器重试。' };
  }
  if (algorithm !== -7 && algorithm !== -257) {
    return { ok: false, error: `不支持的密钥算法 (${algorithm})，请使用支持 ES256/RS256 的设备。` };
  }

  let clientData: { type?: string; challenge?: string; origin?: string };
  try {
    clientData = JSON.parse(new TextDecoder().decode(base64UrlDecode(clientDataB64)));
  } catch {
    return { ok: false, error: 'clientDataJSON 解析失败。' };
  }

  const url = new URL(request.url);
  if (clientData.type !== 'webauthn.create') {
    return { ok: false, error: '无效的 WebAuthn 注册类型。' };
  }
  if (clientData.origin !== url.origin) {
    return { ok: false, error: `Origin 不匹配（期望 ${url.origin}）。` };
  }
  if (!clientData.challenge || !(await consumeChallenge(env, clientData.challenge, 'register'))) {
    return { ok: false, error: '注册挑战已过期或无效，请重新点击添加通行密钥。' };
  }

  // 校验 authenticatorData 的 rpIdHash 与 UP 标志
  const authData = base64UrlDecode(authDataB64);
  if (authData.length < 37) return { ok: false, error: 'authenticatorData 长度无效。' };
  const expectedRpHash = new Uint8Array(await crypto.subtle.digest('SHA-256', new TextEncoder().encode(url.hostname)));
  if (!bytesEqual(authData.slice(0, 32), expectedRpHash)) {
    return { ok: false, error: 'RP ID 校验失败。' };
  }
  if ((authData[32] & 0x01) === 0) {
    return { ok: false, error: '未检测到用户存在确认（UP 标志缺失）。' };
  }
  const signCount = new DataView(authData.buffer, authData.byteOffset + 33, 4).getUint32(0, false);

  // 确认公钥可被 Web Crypto 正确导入
  try {
    await importPasskeyPublicKey(spkiB64, algorithm);
  } catch (err) {
    return { ok: false, error: err instanceof Error ? err.message : '公钥格式无效。' };
  }

  const now = nowUtcIso();
  const id = generateId('pk');
  const transports = Array.isArray(body.transports) ? body.transports.map(String).slice(0, 6) : [];

  try {
    await env.DB.prepare(
      `INSERT INTO admin_passkeys (id, credential_id, public_key_spki, algorithm, label, sign_count, transports, created_at)
       VALUES (?, ?, ?, ?, ?, ?, ?, ?)`
    )
      .bind(id, credentialId, spkiB64, algorithm, label, signCount, JSON.stringify(transports), now)
      .run();
  } catch {
    return { ok: false, error: '该通行密钥已绑定过，无需重复添加。' };
  }

  await writeAuditLog(env, 'ADMIN', actor, 'PASSKEY_REGISTERED', {
    passkey_id: id,
    label,
    algorithm,
    rp_id: url.hostname,
  });

  return {
    ok: true,
    passkey: {
      id,
      credential_id: credentialId,
      public_key_spki: spkiB64,
      algorithm,
      label,
      sign_count: signCount,
      transports: JSON.stringify(transports),
      created_at: now,
      last_used_at: null,
    },
  };
}

/** 生成 Passkey 登录挑战参数（公开接口，仅当已绑定至少 1 个 Passkey 时可用） */
export async function createPasskeyLoginOptions(request: Request, env: Env) {
  const url = new URL(request.url);
  const rows = await env.DB.prepare('SELECT credential_id, transports FROM admin_passkeys').all<{
    credential_id: string;
    transports: string;
  }>();
  const creds = rows.results ?? [];
  if (creds.length === 0) {
    return { available: false, count: 0 };
  }

  const challenge = await issueChallenge(env, 'login');
  return {
    available: true,
    count: creds.length,
    options: {
      challenge,
      rpId: url.hostname,
      timeout: 120000,
      userVerification: 'preferred',
      allowCredentials: creds.map((c) => ({
        type: 'public-key',
        id: c.credential_id,
        transports: JSON.parse(c.transports || '[]'),
      })),
    },
  };
}

/** 校验 Passkey 登录断言签名 */
export async function verifyPasskeyLogin(
  request: Request,
  env: Env,
  body: {
    credential_id?: string;
    client_data_json?: string;
    authenticator_data?: string;
    signature?: string;
  }
): Promise<{ ok: true; passkey: AdminPasskeyRow } | { ok: false; error: string }> {
  const credentialId = String(body.credential_id || '').trim();
  const clientDataB64 = String(body.client_data_json || '').trim();
  const authDataB64 = String(body.authenticator_data || '').trim();
  const sigB64 = String(body.signature || '').trim();

  if (!credentialId || !clientDataB64 || !authDataB64 || !sigB64) {
    return { ok: false, error: '通行密钥登录参数不完整。' };
  }

  const stored = await env.DB.prepare('SELECT * FROM admin_passkeys WHERE credential_id = ?')
    .bind(credentialId)
    .first<AdminPasskeyRow>();
  if (!stored) {
    return { ok: false, error: '未找到匹配的通行密钥，请使用管理员密钥登录后重新绑定。' };
  }

  const clientDataBytes = base64UrlDecode(clientDataB64);
  let clientData: { type?: string; challenge?: string; origin?: string };
  try {
    clientData = JSON.parse(new TextDecoder().decode(clientDataBytes));
  } catch {
    return { ok: false, error: 'clientDataJSON 格式无效。' };
  }

  const url = new URL(request.url);
  if (clientData.type !== 'webauthn.get') {
    return { ok: false, error: '无效的 WebAuthn 登录类型。' };
  }
  if (clientData.origin !== url.origin) {
    return { ok: false, error: `Origin 不匹配（期望 ${url.origin}）。` };
  }
  if (!clientData.challenge || !(await consumeChallenge(env, clientData.challenge, 'login'))) {
    return { ok: false, error: '登录挑战已过期或无效，请重试。' };
  }

  const authData = base64UrlDecode(authDataB64);
  if (authData.length < 37) return { ok: false, error: 'authenticatorData 长度无效。' };
  const expectedRpHash = new Uint8Array(await crypto.subtle.digest('SHA-256', new TextEncoder().encode(url.hostname)));
  if (!bytesEqual(authData.slice(0, 32), expectedRpHash)) {
    return { ok: false, error: 'RP ID 校验失败。' };
  }
  if ((authData[32] & 0x01) === 0) {
    return { ok: false, error: '未检测到用户存在确认（UP 标志缺失）。' };
  }
  const newSignCount = new DataView(authData.buffer, authData.byteOffset + 33, 4).getUint32(0, false);
  if (stored.sign_count > 0 && newSignCount > 0 && newSignCount <= stored.sign_count) {
    return { ok: false, error: '检测到通行密钥签名计数器异常（疑似克隆凭证），已拒绝登录。' };
  }

  // 拼接验签原文：authenticatorData || SHA-256(clientDataJSON)
  const clientDataHash = new Uint8Array(await crypto.subtle.digest('SHA-256', clientDataBytes));
  const signedData = new Uint8Array(authData.length + clientDataHash.length);
  signedData.set(authData, 0);
  signedData.set(clientDataHash, authData.length);

  const sigBytes = base64UrlDecode(sigB64);
  const pubKey = await importPasskeyPublicKey(stored.public_key_spki, stored.algorithm);

  let verified = false;
  if (stored.algorithm === -7) {
    const rawSig = derToRawEcdsaP256(sigBytes);
    if (!rawSig) return { ok: false, error: 'ECDSA 签名格式无效。' };
    verified = await crypto.subtle.verify({ name: 'ECDSA', hash: 'SHA-256' }, pubKey, rawSig, signedData);
  } else if (stored.algorithm === -257) {
    verified = await crypto.subtle.verify({ name: 'RSASSA-PKCS1-v1_5' }, pubKey, sigBytes, signedData);
  }

  if (!verified) {
    return { ok: false, error: '通行密钥签名校验失败。' };
  }

  const now = nowUtcIso();
  await env.DB.prepare('UPDATE admin_passkeys SET sign_count = ?, last_used_at = ? WHERE id = ?')
    .bind(newSignCount, now, stored.id)
    .run();

  return { ok: true, passkey: { ...stored, sign_count: newSignCount, last_used_at: now } };
}

export function generatePasskeyNonce(): string {
  return randomHex(16);
}
