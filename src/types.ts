export type ChatRequest = { message: string; options?: Record<string, unknown>; };
export type Resource = { title: string; url: string; source?: string; };
export type ChatResponse = { answer: string; latency_ms: number; resources: Resource[]; api: "chat_completions"|"responses"; };
export type Settings = { sys_prompt: string; allowedDomains?: string[]; resourcesMax?: number; ragTopK?: number; chatRequireAuth?: boolean; };
export type LogEntry = { id: string; ts: string; user?: string; question: string; answer: string; resources: Resource[]; latency_ms: number; api: ChatResponse["api"]; };
