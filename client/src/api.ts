// 固定サーバーアドレス（DNS解決不要）
export const SERVER_BASE = 'https://tell.manh2309.org:35000';
export const SERVER_WS   = 'wss://tell.manh2309.org:35000/ws';

function createRequestId(): string {
  if (typeof crypto !== 'undefined' && typeof crypto.randomUUID === 'function') {
    return crypto.randomUUID();
  }
  return `req-${Date.now()}-${Math.random().toString(36).slice(2, 8)}`;
}

async function postJSON(url: string, body: unknown, token?: string): Promise<any> {
  const requestId = createRequestId();
  const payload =
    body && typeof body === 'object' && !Array.isArray(body)
      ? ({ request_id: requestId, ...(body as Record<string, unknown>) } as Record<string, unknown>)
      : body;
  const headers: Record<string, string> = {
    'content-type': 'application/json',
    'x-request-id': requestId,
  };
  if (token) {
    headers['Authorization'] = `Bearer ${token}`;
  }
  const res = await fetch(url, {
    method: 'POST',
    headers,
    body: JSON.stringify(payload),
  });
  if (!res.ok) {
    throw new Error(await res.text());
  }
  return res.json();
}

// ---- アカウント ----

export async function createAccount(
  windowBase: string,
  username: string,
  password: string,
): Promise<string> {
  const data = (await postJSON(`${windowBase}/account/new`, { username, password })) as { number: string };
  return data.number;
}

export async function loginAccount(
  windowBase: string,
  username: string,
  password: string,
): Promise<{ token: string; number: string }> {
  return (await postJSON(`${windowBase}/account/login`, { username, password })) as {
    token: string;
    number: string;
  };
}

// ---- SMS ----

export async function sendSMS(
  windowBase: string,
  to: string,
  from: string,
  messageBody: string,
  timestamp: number,
  token: string,
): Promise<void> {
  await postJSON(
    `${windowBase}/sms/send`,
    { to, from, message: { body: messageBody }, timestamp },
    token,
  );
}

// ---- ICE シグナリング（JWT 必須）----

export async function sendICEOffer(
  windowBase: string,
  payload: { from: string; to: string; offer: unknown },
  token: string,
): Promise<void> {
  await postJSON(`${windowBase}/ice/offer`, payload, token);
}

export async function sendICEAnswer(
  windowBase: string,
  payload: { from: string; to: string; answer: unknown },
  token: string,
): Promise<void> {
  await postJSON(`${windowBase}/ice/answer`, payload, token);
}

export async function sendICECandidate(
  windowBase: string,
  payload: { from: string; to: string; candidate: unknown },
  token: string,
): Promise<void> {
  await postJSON(`${windowBase}/ice/candidate`, payload, token);
}

// ---- 通話シグナリング（JWT 必須）----

export async function sendCallAuthOK(
  windowBase: string,
  payload: { from: string; to: string },
  token: string,
): Promise<void> {
  await postJSON(`${windowBase}/call/auth-ok`, payload, token);
}

export async function sendCallReject(
  windowBase: string,
  payload: { from: string; to: string; reason: string },
  token: string,
): Promise<void> {
  await postJSON(`${windowBase}/call/reject`, payload, token);
}

export async function sendCallHangup(
  windowBase: string,
  payload: { from: string; to: string },
  token: string,
): Promise<void> {
  await postJSON(`${windowBase}/call/hangup`, payload, token);
}
