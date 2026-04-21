export type NodeResolveResponse = {
  ws_url: string;
  candidates?: string[];
  window_base?: string;
  window_candidates?: string[];
};

export type NodeInbound = {
  action?: string;
  data?: unknown;
  messages?: unknown[];
  challenge?: string;
  status?: string;
  error?: string;
};

export type ScreenKey = 'login' | 'signup' | 'chat';
