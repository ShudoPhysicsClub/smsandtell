// WebSocket を使用したサーバー通信（HTTP POST 廃止）
export const SERVER_BASE = 'https://mail.shudo-physics.com:35000';
export const SERVER_WS = 'wss://mail.shudo-physics.com:35000/ws';
// グローバル WebSocket 接続
let wsConnection = null;
const pendingRequests = new Map();
let wsInboundHandler = null;
export function setWSInboundHandler(handler) {
    wsInboundHandler = handler;
}
function settlePendingByRequestId(requestId, msg) {
    if (!requestId || !pendingRequests.has(requestId))
        return false;
    const pending = pendingRequests.get(requestId);
    clearTimeout(pending.timeout);
    pendingRequests.delete(requestId);
    if (msg.error) {
        pending.reject(new Error(String(msg.error)));
    }
    else {
        pending.resolve(msg);
    }
    return true;
}
function settleOldestPending(msg) {
    const first = pendingRequests.entries().next().value;
    if (!first)
        return false;
    const [rid, pending] = first;
    clearTimeout(pending.timeout);
    pendingRequests.delete(rid);
    if (msg.error) {
        pending.reject(new Error(String(msg.error)));
    }
    else {
        pending.resolve(msg);
    }
    return true;
}
function createRequestId() {
    if (typeof crypto !== 'undefined' && typeof crypto.randomUUID === 'function') {
        return crypto.randomUUID();
    }
    return `req-${Date.now()}-${Math.random().toString(36).slice(2, 8)}`;
}
/**
 * WebSocket 接続を確立する
 */
function ensureWSConnection() {
    return new Promise((resolve, reject) => {
        if (wsConnection && wsConnection.readyState === WebSocket.OPEN) {
            resolve(wsConnection);
            return;
        }
        const ws = new WebSocket(SERVER_WS);
        ws.onopen = () => {
            wsConnection = ws;
            resolve(ws);
        };
        ws.onerror = () => {
            reject(new Error('WebSocket connection failed'));
        };
        ws.onmessage = (event) => {
            let msg;
            try {
                msg = JSON.parse(String(event.data));
            }
            catch {
                return;
            }
            const requestId = String(msg.request_id ?? '');
            if (settlePendingByRequestId(requestId, msg))
                return;
            // 互換対応: request_id を返さない旧サーバー応答でも先頭保留を解決する
            const looksLikeDirectResponse = (typeof msg.token === 'string' && typeof msg.number === 'string') ||
                typeof msg.error === 'string' ||
                typeof msg.status === 'string';
            if (looksLikeDirectResponse) {
                if (settleOldestPending(msg))
                    return;
            }
            wsInboundHandler?.(msg);
        };
        ws.onclose = () => {
            wsConnection = null;
        };
    });
}
/**
 * WebSocket でリクエストを送信して レスポンスを待つ
 */
async function sendWSRequest(action, payload) {
    const ws = await ensureWSConnection();
    const requestId = createRequestId();
    const message = { request_id: requestId, action, ...payload };
    return new Promise((resolve, reject) => {
        const timeout = setTimeout(() => {
            pendingRequests.delete(requestId);
            reject(new Error(`Request timeout for ${action}`));
        }, 30000);
        pendingRequests.set(requestId, { resolve, reject, timeout });
        ws.send(JSON.stringify(message));
    });
}
// ---- アカウント ----
export async function createAccount(windowBase, username, password) {
    console.log('[API WebSocket] Creating account:', { username });
    const response = await sendWSRequest('account/new', { username, password });
    if (response.error) {
        throw new Error(response.error);
    }
    console.log('[API WebSocket] Account created:', response.number);
    return response.number;
}
export async function loginAccount(windowBase, username, password) {
    console.log('[API WebSocket] Logging in:', { username });
    const response = await sendWSRequest('account/login', { username, password });
    if (response.error) {
        throw new Error(response.error);
    }
    console.log('[API WebSocket] Login successful:', response.number);
    return { token: response.token, number: response.number };
}
// ---- SMS ----
export async function sendSMS(windowBase, to, from, messageBody, timestamp, token) {
    console.log('[API WebSocket] Sending SMS:', { to, from, timestamp });
    const response = await sendWSRequest('sms/send', {
        to,
        message: { body: messageBody },
        timestamp,
    });
    if (response.error) {
        throw new Error(response.error);
    }
    console.log('[API WebSocket] SMS sent to:', to);
}
// ---- ICE シグナリング ----
export async function sendICEOffer(windowBase, payload, token) {
    console.log('[API WebSocket] Sending ICE offer to:', payload.to);
    const response = await sendWSRequest('ice/offer', {
        to: payload.to,
        offer: payload.offer,
    });
    if (response.error) {
        throw new Error(response.error);
    }
}
export async function sendICEAnswer(windowBase, payload, token) {
    console.log('[API WebSocket] Sending ICE answer to:', payload.to);
    const response = await sendWSRequest('ice/answer', {
        to: payload.to,
        answer: payload.answer,
    });
    if (response.error) {
        throw new Error(response.error);
    }
}
export async function sendICECandidate(windowBase, payload, token) {
    console.log('[API WebSocket] Sending ICE candidate to:', payload.to);
    const response = await sendWSRequest('ice/candidate', {
        to: payload.to,
        candidate: payload.candidate,
    });
    if (response.error) {
        throw new Error(response.error);
    }
}
// ---- 通話シグナリング ----
export async function sendCallAuthOK(windowBase, payload, token) {
    console.log('[API WebSocket] Sending call auth-ok to:', payload.to);
    const response = await sendWSRequest('call/auth-ok', {
        to: payload.to,
    });
    if (response.error) {
        throw new Error(response.error);
    }
}
export async function sendCallReject(windowBase, payload, token) {
    console.log('[API WebSocket] Rejecting call from:', payload.to);
    const response = await sendWSRequest('call/reject', {
        to: payload.to,
        reason: payload.reason,
    });
    if (response.error) {
        throw new Error(response.error);
    }
}
export async function sendCallHangup(windowBase, payload, token) {
    console.log('[API WebSocket] Hanging up call with:', payload.to);
    const response = await sendWSRequest('call/hangup', {
        to: payload.to,
    });
    if (response.error) {
        throw new Error(response.error);
    }
}
/**
 * WebSocket 接続をクローズ（ログアウト時に呼び出し）
 */
export function closeWSConnection() {
    if (wsConnection) {
        wsConnection.close();
        wsConnection = null;
    }
}
/**
 * 認証後の WebSocket をセットアップ（メッセージ受信用）
 */
export async function setupAuthenticatedWS(wsUrl, number, token) {
    const ws = new WebSocket(wsUrl);
    return new Promise((resolve, reject) => {
        ws.onopen = () => {
            // 認証メッセージを送信
            ws.send(JSON.stringify({ action: 'auth', number, token, request_id: createRequestId() }));
        };
        ws.onerror = () => {
            reject(new Error('WebSocket connection failed'));
        };
        ws.onmessage = (event) => {
            const msg = JSON.parse(String(event.data));
            if (msg.status === 'authenticated') {
                wsConnection = ws;
                resolve(ws);
            }
        };
    });
}
//# sourceMappingURL=api.js.map