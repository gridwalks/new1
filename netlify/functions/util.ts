import type { HandlerContext } from "@netlify/functions";
import { getStore } from "@netlify/blobs";
import crypto from "crypto";

export type User = { email?: string; roles?: string[]; sub?: string } | null;

// Always use explicit config from env; throw if missing to surface misconfig early
function blobsRequiredConfig() {
  const siteID = process.env.NETLIFY_BLOBS_SITE_ID || process.env.NETLIFY_SITE_ID;
  const token  = process.env.NETLIFY_BLOBS_TOKEN || process.env.NETLIFY_API_TOKEN;
  if (!siteID || !token) {
    const missing = {
      NETLIFY_BLOBS_SITE_ID: !!process.env.NETLIFY_BLOBS_SITE_ID,
      NETLIFY_SITE_ID: !!process.env.NETLIFY_SITE_ID,
      NETLIFY_BLOBS_TOKEN: !!process.env.NETLIFY_BLOBS_TOKEN,
      NETLIFY_API_TOKEN: !!process.env.NETLIFY_API_TOKEN,
    };
    throw new Error("Blobs config missing. Need NETLIFY_BLOBS_SITE_ID (or NETLIFY_SITE_ID) and NETLIFY_BLOBS_TOKEN (or NETLIFY_API_TOKEN). Seen: " + JSON.stringify(missing));
  }
  return { siteID, token };
}

export const settingsStore = getStore("settings-store", blobsRequiredConfig());
export const ragStore = getStore("rag-store", blobsRequiredConfig());
export const logsStore = getStore("logs-store", blobsRequiredConfig());

export async function loadSettings() {
  const cfg = (await settingsStore.getJSON("admin:config")) as any | null;
  return {
    sys_prompt: cfg?.sys_prompt || `You are AcceleraQA, a concise AI learning assistant for pharma Quality & Compliance.
Answer in under 180 words unless asked for depth. Include a fenced \\`\\`\\`json resources block when useful.`,
    allowedDomains: cfg?.allowedDomains ?? [],
    resourcesMax: cfg?.resourcesMax ?? 6,
    ragTopK: cfg?.ragTopK ?? 3,
    chatRequireAuth: cfg?.chatRequireAuth ?? (process.env.CHAT_REQUIRE_AUTH === "true"),
  };
}

export function getUser(context: HandlerContext): User {
  // @ts-ignore
  const u = (context as any)?.clientContext?.user as any | undefined;
  if (!u) return null;
  return { email: u.email, roles: u.app_metadata?.roles ?? [], sub: u.sub };
}

export function isAdminUser(user: User): boolean {
  const emails = (process.env.ADMIN_EMAILS || "").split(",").map(s => s.trim().toLowerCase()).filter(Boolean);
  const email = (user?.email || "").toLowerCase();
  const allow = emails.includes(email);
  const roles = user?.roles || [];
  return allow || roles.includes("admin");
}

export function requireAdmin(user: User) {
  if (!isAdminUser(user)) {
    const e: any = new Error("Forbidden");
    e.statusCode = 403;
    throw e;
  }
}

export function requireChatAuth(user: User, settings: any) {
  if (settings.chatRequireAuth && !user) {
    const e: any = new Error("Unauthorized");
    e.statusCode = 401;
    throw e;
  }
}

export function json(body: any, statusCode = 200) {
  return { statusCode, headers: { "Content-Type": "application/json" }, body: JSON.stringify(body) };
}
export function errorJSON(message: string, statusCode = 500, detail?: any) {
  const debug = process.env.DEBUG_ERROR_DETAILS === "true";
  return json({ error: message, ...(debug && detail ? { detail } : {}) }, statusCode);
}
export function nowISO(){ return new Date().toISOString(); }
export function id(prefix: string){ return `${prefix}:${crypto.randomUUID()}`; }
export async function logUserEntry(user: User, entry: any){
  const email = user?.email || "anon";
  const key = `user:${email}:${entry.ts}:${crypto.randomBytes(3).toString("hex")}`;
  await logsStore.setJSON(key, entry); return key;
}
export async function logAdminEntry(entry: any){
  const key = `admin:${entry.ts}:${crypto.randomBytes(3).toString("hex")}`;
  await logsStore.setJSON(key, entry); return key;
}
export async function listLogs(prefix: string, limit = 500){
  const out: any[] = []; const listed = await logsStore.list({ prefix });
  for (const b of listed.blobs){
    const val = await logsStore.getJSON(b.key); if (val) out.push({ id: b.key, ...val });
    if (out.length >= limit) break;
  }
  out.sort((a,b) => (a.ts < b.ts ? 1 : -1)); return out;
}
