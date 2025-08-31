import type { ChatRequest, ChatResponse, Settings, LogEntry } from "../types";
declare global { interface Window { netlifyIdentity: any; } }

export function getIdentityUser(): any | null {
  return window.netlifyIdentity?.currentUser() ?? null;
}

async function getAuthHeader(): Promise<Record<string,string>> {
  const user = getIdentityUser(); if (!user) return {};
  const token = await user.jwt(); return { Authorization: `Bearer ${token}` };
}

export function isAdmin(user: any | null): boolean {
  if (!user) return false;
  const emails = (import.meta.env.VITE_ADMIN_EMAILS as string | undefined)?.split(",").map(s => s.trim().toLowerCase()) ?? [];
  const allowed = emails.includes((user.email || "").toLowerCase());
  const roles: string[] = user?.app_metadata?.roles ?? [];
  return allowed || roles.includes("admin");
}

export async function apiGet<T>(path: string): Promise<T> {
  const headers = await getAuthHeader();
  const res = await fetch(path, { headers }); if (!res.ok) throw new Error(await res.text()); return res.json();
}
export async function apiPost<T>(path: string, body: any): Promise<T> {
  const headers = await getAuthHeader();
  const res = await fetch(path, { method:"POST", headers: { "Content-Type":"application/json", ...headers }, body: JSON.stringify(body) });
  if (!res.ok) throw new Error(await res.text()); return res.json();
}
export async function apiDelete<T>(path: string): Promise<T> {
  const headers = await getAuthHeader();
  const res = await fetch(path, { method:"DELETE", headers }); if (!res.ok) throw new Error(await res.text()); return res.json();
}

export const chat = (req: ChatRequest) => apiPost<ChatResponse>("/api/chat", req);
export const getSettings = () => apiGet<Settings>("/api/settings-get");
export const setSettings = (s: Partial<Settings>) => apiPost<{ok:true}>("/api/settings-set", s);
export const ragList = () => apiGet<any[]>("/api/rag-list");
export const ragUpsert = (doc:any) => apiPost<{ok:true; id:string}>("/api/rag-upsert", doc);
export const ragDelete = (id:string) => apiDelete<{ok:true}>(`/api/rag-delete?id=${encodeURIComponent(id)}`);
export const logsUser = () => apiGet<LogEntry[]>("/api/logs-user");
export const logsAdmin = () => apiGet<LogEntry[]>("/api/logs-admin");
export async function exportLogsUser(){ const h=await getAuthHeader(); const r=await fetch("/api/logs-export",{headers:h}); if(!r.ok) throw new Error(await r.text()); return r.blob(); }
export async function exportLogsAdmin(){ const h=await getAuthHeader(); const r=await fetch("/api/logs-export-admin",{headers:h}); if(!r.ok) throw new Error(await r.text()); return r.blob(); }
