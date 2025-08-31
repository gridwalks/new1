import type { Handler } from "@netlify/functions";
import { loadSettings, json, errorJSON, getUser, logUserEntry, logAdminEntry, ragStore, requireChatAuth } from "./util";
import OpenAI from "openai";

function extractResources(answer: string){
  const fence = /```json\s*([\s\S]*?)\s*```/i.exec(answer);
  try { if (fence && fence[1]){ const parsed = JSON.parse(fence[1]); if (Array.isArray(parsed.resources)) return parsed.resources.filter((r:any)=>r&&r.title&&r.url).map((r:any)=>({ title:String(r.title), url:String(r.url), source:r.source?String(r.source):undefined })); } } catch {}
  const links:any[]=[]; const re=/\[([^\]]+)\]\((https?:[^\)\s]+)\)/g; let m; while((m=re.exec(answer))) links.push({ title:m[1], url:m[2] });
  return links;
}
function filterByDomains(resources:any[], allowed:string[]){ if(!allowed||allowed.length===0) return resources;
  const domains = allowed.map(d=>d.toLowerCase());
  return resources.filter(r=>{ try{ const u=new URL(r.url); const h=u.hostname.toLowerCase(); return domains.some(d=>h.endsWith(d)||h===d);}catch{return false;} });
}
async function ragRetrieve(message:string, k:number){
  if (k<=0) return [];
  const listed = await ragStore.list({ prefix:"doc:" }); const docs:any[]=[];
  for (const b of listed.blobs){ const d = await ragStore.getJSON(b.key); if (d) docs.push(d); }
  const q = message.toLowerCase(); const terms = new Set(q.split(/[^a-z0-9]+/).filter(Boolean));
  const scored = docs.map(d=>{ const text = `${d.title} ${d.content} ${(d.keywords||[]).join(" ")}`.toLowerCase(); let score=0; for (const t of terms) if (text.includes(t)) score++; return {doc:d, score}; }).filter(s=>s.score>0);
  scored.sort((a,b)=>b.score-a.score); return scored.slice(0,k).map(s=>s.doc);
}

export const handler: Handler = async (event, context) => {
  const started = Date.now(); const user = getUser(context); const settings = await loadSettings();
  try {
    requireChatAuth(user, settings);
    const body = JSON.parse(event.body || "{}"); const message = String(body.message || "").trim();
    if (!message) return errorJSON("Missing message", 400);
    const ragDocs = await ragRetrieve(message, settings.ragTopK || 0);
    const ragText = ragDocs.map((d:any)=>`- ${d.title}: ${d.content}`).join("\n");
    const sys = settings.sys_prompt;
    const userMsg = `User question:\n${message}\n\nIf helpful, include a single fenced JSON block named resources (title, url, source).`;
    const ragMsg = ragText ? `\n\nRelevant internal notes:\n${ragText}` : "";
    const client = new OpenAI({ apiKey: process.env.OPENAI_API_KEY });
    let api: "chat_completions" | "responses" = "chat_completions";
    let answer = "";
    try {
      const model = process.env.OPENAI_COMPLETIONS_MODEL || "gpt-4o-mini";
      const resp = await client.chat.completions.create({ model, messages:[{ role:"system", content: sys + ragMsg }, { role:"user", content: userMsg }], temperature: 0.2 });
      answer = resp.choices?.[0]?.message?.content || ""; if (!answer.trim()) throw new Error("Empty chat completion");
    } catch (e) {
      api = "responses";
      const model = process.env.OPENAI_MODEL || "gpt-4.1-mini";
      const r:any = await client.responses.create({ model, input:[{ role:"system", content: sys + ragMsg }, { role:"user", content: userMsg }], temperature: 0.2 } as any);
      const txt = (r.output_text || "").trim(); if (!txt) throw e; answer = txt;
    }
    let resources = extractResources(answer); resources = filterByDomains(resources, settings.allowedDomains || []);
    if ((settings.resourcesMax ?? 6) > 0) resources = resources.slice(0, settings.resourcesMax);
    const latency_ms = Date.now() - started;
    const entry = { ts: new Date().toISOString(), user: user?.email || "anon", question: message, answer, resources, latency_ms, api };
    await logUserEntry(user, entry); await logAdminEntry({ ...entry, ragDocs });
    return json({ answer, latency_ms, resources, api });
  } catch (e:any) {
    const latency_ms = Date.now() - started;
    return errorJSON(e.message || "Internal error", e.statusCode || 500, { latency_ms });
  }
};
