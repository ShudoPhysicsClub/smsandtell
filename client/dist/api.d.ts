export declare const SERVER_BASE = "https://mail.shudo-physics.com:35000";
export declare const SERVER_WS = "wss://mail.shudo-physics.com:35000/ws";
export declare function setWSInboundHandler(handler: ((msg: Record<string, any>) => void) | null): void;
export declare function createAccount(windowBase: string, username: string, password: string): Promise<string>;
export declare function loginAccount(windowBase: string, username: string, password: string): Promise<{
    token: string;
    number: string;
}>;
export declare function sendSMS(windowBase: string, to: string, from: string, messageBody: string, timestamp: number, token: string): Promise<void>;
export declare function sendICEOffer(windowBase: string, payload: {
    from: string;
    to: string;
    offer: unknown;
}, token: string): Promise<void>;
export declare function sendICEAnswer(windowBase: string, payload: {
    from: string;
    to: string;
    answer: unknown;
}, token: string): Promise<void>;
export declare function sendICECandidate(windowBase: string, payload: {
    from: string;
    to: string;
    candidate: unknown;
}, token: string): Promise<void>;
export declare function sendCallAuthOK(windowBase: string, payload: {
    from: string;
    to: string;
}, token: string): Promise<void>;
export declare function sendCallReject(windowBase: string, payload: {
    from: string;
    to: string;
    reason: string;
}, token: string): Promise<void>;
export declare function sendCallHangup(windowBase: string, payload: {
    from: string;
    to: string;
}, token: string): Promise<void>;
/**
 * WebSocket 接続をクローズ（ログアウト時に呼び出し）
 */
export declare function closeWSConnection(): void;
/**
 * 認証後の WebSocket をセットアップ（メッセージ受信用）
 */
export declare function setupAuthenticatedWS(wsUrl: string, number: string, token: string): Promise<WebSocket>;
