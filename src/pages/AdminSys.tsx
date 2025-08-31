import React from "react";
import { getSettings, setSettings } from "../lib/api";
import type { Settings } from "../types";
export default function AdminSys(){
  const [s, setS] = React.useState<Settings | null>(null);
  const [saving, setSaving] = React.useState(false);
  const [msg, setMsg] = React.useState<string|null>(null);
  React.useEffect(()=>{ getSettings().then(setS).catch(e=>setMsg(String(e))); }, []);
  async function onSave(e: React.FormEvent){
    e.preventDefault(); if (!s) return;
    setSaving(true); setMsg(null);
    try { await setSettings(s); setMsg("Saved."); } catch (e:any){ setMsg(e.message || "Save failed"); } finally { setSaving(false); }
  }
  if (!s) return <div className="p-6">Loading…</div>;
  return (
    <div className="mx-auto max-w-3xl px-4 py-6">
      <h1 className="text-2xl font-bold mb-4">System Settings</h1>
      <form onSubmit={onSave} className="space-y-4">
        <div><label className="block text-sm mb-1">System Prompt</label><textarea className="w-full h-48 p-3" value={s.sys_prompt} onChange={e=>setS({ ...s, sys_prompt: e.target.value })} /></div>
        <div><label className="block text-sm mb-1">Allowed Domains (comma-separated)</label><input className="w-full p-2" value={(s.allowedDomains||[]).join(", ")} onChange={e=>setS({ ...s, allowedDomains: e.target.value.split(",").map(x=>x.trim()).filter(Boolean) })} /></div>
        <div className="grid grid-cols-3 gap-3">
          <div><label className="block text-sm mb-1">Resources Max</label><input type="number" className="w-full p-2" value={s.resourcesMax ?? 6} onChange={e=>setS({ ...s, resourcesMax: Number(e.target.value || 6) })} /></div>
          <div><label className="block text-sm mb-1">RAG Top K</label><input type="number" className="w-full p-2" value={s.ragTopK ?? 3} onChange={e=>setS({ ...s, ragTopK: Number(e.target.value || 3) })} /></div>
          <div><label className="block text-sm mb-1">Require Auth</label><select className="w-full p-2" value={String(s.chatRequireAuth ?? false)} onChange={e=>setS({ ...s, chatRequireAuth: e.target.value === "true" })}><option value="false">false</option><option value="true">true</option></select></div>
        </div>
        <div className="flex items-center gap-3"><button type="submit" disabled={saving}>Save</button>{msg && <span className="text-sm text-neutral-400">{msg}</span>}</div>
      </form>
    </div>
  );
}
