import type { NodeResolveResponse } from './types';

const FIXED_SEED_DOMAIN = 'manh2309.org';

function createRequestId(): string {
  if (typeof crypto !== 'undefined' && typeof crypto.randomUUID === 'function') {
    return crypto.randomUUID();
  }
  return `req-${Date.now()}-${Math.random().toString(36).slice(2, 8)}`;
}

async function postJSON(url: string, body: unknown): Promise<any> {
  const requestId = createRequestId();
  const payload =
    body && typeof body === 'object' && !Array.isArray(body)
      ? ({ request_id: requestId, ...(body as Record<string, unknown>) } as Record<string, unknown>)
      : body;
  const res = await fetch(url, {
    method: 'POST',
    headers: { 'content-type': 'application/json', 'x-request-id': requestId },
    body: JSON.stringify(payload),
  });
  if (!res.ok) {
    throw new Error(await res.text());
  }
  return res.json();
}

export async function loginAccount(
  windowBase: string,
  email: string,
  password: string,
): Promise<{ token: string; number: string; encrypted_key: string }> {
  const data = (await postJSON(`${windowBase}/account/login`, {
    email,
    password,
  })) as { token: string; number: string; encrypted_key: string };
  return data;
}

function seedLabelFromNumber(number: string): string {
  const n = number.trim();
  if (!n) return '';
  return n.split('-', 1)[0]?.trim() ?? '';
}

function normalizeNodeWS(value: string): string {
  const v = value.trim();
  if (!v) return '';
  if (v.startsWith('ws://') || v.startsWith('wss://')) return v;
  if (v.includes('/')) return `wss://${v}`;
  return `wss://${v}/ws`;
}

function normalizeWindowBase(value: string): string {
  const v = value.trim();
  if (!v) return '';
  if (v.startsWith('http://') || v.startsWith('https://')) return v;
  return `https://${v}`;
}

function pickOne(items: string[]): string {
  if (!items.length) return '';
  const idx = Math.floor(Math.random() * items.length);
  return items[idx] ?? '';
}

export async function resolveSeed(number: string): Promise<{ windowBase: string; nodeWs: string }> {
  const label = seedLabelFromNumber(number);
  if (!label) {
    throw new Error('number prefix is empty');
  }

  const host = `${label}.${FIXED_SEED_DOMAIN}`;
  const url = `https://dns.google/resolve?name=${encodeURIComponent(host)}&type=TXT`;
  const res = await fetch(url);
  if (!res.ok) {
    throw new Error('dns resolve failed');
  }

  const data = (await res.json()) as {
    Answer?: Array<{ data?: string }>;
  };

  const nodeCandidates: string[] = [];
  const windowCandidates: string[] = [];

  for (const answer of data.Answer ?? []) {
    const raw = String(answer.data ?? '').replaceAll('"', '').trim();
    if (!raw) continue;
    const fields = raw.split(/\s+/);
    for (const field of fields) {
      const [key, ...rest] = field.split('=');
      if (!key || rest.length === 0) continue;
      const value = rest.join('=').trim();
      if (!value) continue;
      if (key === 'node') nodeCandidates.push(normalizeNodeWS(value));
      if (key === 'window') windowCandidates.push(normalizeWindowBase(value));
    }
  }

  const windowBase = pickOne(windowCandidates);
  const nodeWs = pickOne(nodeCandidates);
  if (!windowBase) throw new Error('window record not found in DNS TXT');
  if (!nodeWs) throw new Error('node record not found in DNS TXT');

  return { windowBase, nodeWs };
}

export async function createAccount(
  windowBase: string,
  email: string,
  publicKey: string,
  password: string,
  encryptedKey: string,
): Promise<string> {
  const data = (await postJSON(`${windowBase}/account/new`, {
    email,
    public_key: publicKey,
    password,
    encrypted_key: encryptedKey,
  })) as { number: string };
  return data.number;
}

export async function resetRequest(windowBase: string, email: string): Promise<void> {
  await postJSON(`${windowBase}/account/reset-request`, { email });
}

export async function resetDo(
  windowBase: string,
  token: string,
  publicKey: string,
  password: string,
  encryptedKey: string,
): Promise<string> {
  const data = (await postJSON(`${windowBase}/account/reset`, {
    token,
    public_key: publicKey,
    password,
    encrypted_key: encryptedKey,
  })) as { number: string; status: string };
  return data.number;
}

export async function sendSMS(
  windowBase: string,
  to: string,
  from: string,
  messageBody: string,
  sig: string,
  timestamp: number,
): Promise<void> {
  await postJSON(`${windowBase}/sms/send`, {
    to,
    from,
    message: { body: messageBody },
    sig,
    timestamp,
  });
}

export async function sendICEOffer(
  windowBase: string,
  payload: { from: string; to: string; offer: unknown },
): Promise<void> {
  await postJSON(`${windowBase}/ice/offer`, payload);
}

export async function sendICEAnswer(
  windowBase: string,
  payload: { from: string; to: string; answer: unknown },
): Promise<void> {
  await postJSON(`${windowBase}/ice/answer`, payload);
}

export async function sendICECandidate(
  windowBase: string,
  payload: { from: string; to: string; candidate: unknown },
): Promise<void> {
  await postJSON(`${windowBase}/ice/candidate`, payload);
}

export async function sendCallAuthChallenge(
  windowBase: string,
  payload: { from: string; to: string; challenge: string },
): Promise<void> {
  await postJSON(`${windowBase}/call/auth-challenge`, payload);
}

export async function sendCallAuthResponse(
  windowBase: string,
  payload: { from: string; to: string; challenge: string; sig: string },
): Promise<void> {
  await postJSON(`${windowBase}/call/auth-response`, payload);
}

export async function sendCallReject(
  windowBase: string,
  payload: { from: string; to: string; reason: string },
): Promise<void> {
  await postJSON(`${windowBase}/call/reject`, payload);
}

export async function sendCallAuthOK(
  windowBase: string,
  payload: { from: string; to: string },
): Promise<void> {
  await postJSON(`${windowBase}/call/auth-ok`, payload);
}

export async function sendCallHangup(
  windowBase: string,
  payload: { from: string; to: string },
): Promise<void> {
  await postJSON(`${windowBase}/call/hangup`, payload);
}

export async function getPublicKeyByNumber(windowBase: string, number: string): Promise<string> {
  const res = await fetch(`${windowBase}/pubkey/${encodeURIComponent(number)}`);
  if (!res.ok) {
    throw new Error(await res.text());
  }
  const data = (await res.json()) as { public_key?: string };
  if (!data.public_key) {
    throw new Error('public key not found');
  }
  return data.public_key;
}
