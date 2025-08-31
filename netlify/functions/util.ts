import type { HandlerContext } from "@netlify/functions";
import { getStore } from "@netlify/blobs";
import crypto from "crypto";

export type User = { email?: string; roles?: string[]; sub?: string } | null;

// Always use explicit config from env; throw if missing
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

// Lazy store factory to avoid early init
export function store(name: string) {
  return getStore(name, blobsRequiredConfig());
}

export async function loadSettings() {
  const s = store("settings-store");
  const cfg = (await s.getJSON("admin:config")) as any | null;
  return {
    sys_prompt:
      (cfg?.sys_prompt as string | undefined) ||
      "You are AcceleraQA, a concise AI learning assistant for pharmaceutical Quality & Compliance. " +
      "Answer in under 180 words unless asked for depth. When helpful, include a JSON object named resources, " +
      "for example: { "resources": [ { "title": "21 CFR Part 11", "url": "https://www.ecfr.gov/" } ] }. " +
      "Prefer authoritative sources such as FDA, EMA, MHRA, ICH, ISO, NIST, and EudraLex.",
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

export function nowISO() { return new Date().toISOString(); }
export function id(prefix: string) { return `${prefix}:${crypto.randomUUID()}`; }

export async function logUserEntry(user: User, entry: any) {
  const email = user?.email || "anon";
  const key = `user:${email}:${entry.ts}:${crypto.randomBytes(3).toString("hex")}`;
  const s = store("logs-store");
  await s.setJSON(key, entry);
  return key;
}

export async function logAdminEntry(entry: any) {
  const key = `admin:${entry.ts}:${crypto.randomBytes(3).toString("hex")}`;
  const s = store("logs-store");
  await s.setJSON(key, entry);
  return key;
}

export async function listLogs(prefix: string, limit = 500) {
  const s = store("logs-store");
  const out: any[] = [];
  const listed = await s.list({ prefix });
  for (const b of listed.blobs) {
    const val = await s.getJSON(b.key);
    if (val) out.push({ id: b.key, ...val });
    if (out.length >= limit) break;
  }
  out.sort((a,b) => (a.ts < b.ts ? 1 : -1));
  return out;
}
