export type NodeInbound = {
  action?: string;
  data?: unknown;
  messages?: unknown[];
  challenge?: string;
  status?: string;
  error?: string;
};

export type ScreenKey = 'login' | 'signup' | 'chat';
