import React from "react";
import { ragList, ragUpsert, ragDelete } from "../lib/api";
type Doc = { id?: string; title: string; url: string; content: string; keywords?: string[] };
export default function AdminRag(){
  const [docs, setDocs] = React.useState<Doc[]>([]);
  const [form, setForm] = React.useState<Doc>({ title:"", url:"", content:"", keywords:[] });
  const [msg, setMsg] = React.useState<string|null>(null);
  async function refresh(){ const d = await ragList(); setDocs(d); }
  React.useEffect(()=>{ refresh(); }, []);
  async function onSave(e: React.FormEvent){
    e.preventDefault(); const res = await ragUpsert(form); setMsg(`Saved ${res.id}`);
    setForm({ title:"", url:"", content:"", keywords:[] }); await refresh();
  }
  async function onDelete(id:string){ await ragDelete(id); await refresh(); }
  function edit(d: Doc){ setForm(d); }
  return (
    <div className="mx-auto max-w-5xl px-4 py-6">
      <h1 className="text-2xl font-bold mb-4">RAG Documents</h1>
      <form onSubmit={onSave} className="card p-4 space-y-3 mb-6">
        <div className="grid grid-cols-2 gap-3">
          <div><label className="block text-sm mb-1">Title</label><input className="w-full p-2" value={form.title} onChange={e=>setForm({ ...form, title: e.target.value })} required /></div>
          <div><label className="block text-sm mb-1">URL</label><input className="w-full p-2" value={form.url} onChange={e=>setForm({ ...form, url: e.target.value })} required /></div>
        </div>
        <div><label className="block text-sm mb-1">Keywords (comma-separated)</label><input className="w-full p-2" value={(form.keywords||[]).join(", ")} onChange={e=>setForm({ ...form, keywords: e.target.value.split(",").map(s=>s.trim()).filter(Boolean) })} /></div>
        <div><label className="block text-sm mb-1">Content</label><textarea className="w-full h-40 p-3" value={form.content} onChange={e=>setForm({ ...form, content: e.target.value })} /></div>
        <div className="flex items-center gap-3"><button type="submit">Save / Update</button>{msg && <span className="text-sm text-neutral-400">{msg}</span>}</div>
      </form>
      <div className="space-y-3">
        {docs.map(d => (
          <div key={d.id} className="card p-4">
            <div className="flex items-center justify-between">
              <div>
                <div className="font-semibold">{d.title}</div>
                <div className="text-xs text-neutral-400">{d.id}</div>
                <a href={d.url} target="_blank" rel="noreferrer" className="text-sm">{d.url}</a>
              </div>
              <div className="flex items-center gap-2">
                <button onClick={()=>edit(d)}>Edit</button>
                <button onClick={()=>d.id && onDelete(d.id)} className="bg-red-600 hover:bg-red-500">Delete</button>
              </div>
            </div>
            {d.keywords?.length ? <div className="text-xs text-neutral-400 mt-2">Keywords: {d.keywords.join(", ")}</div> : null}
          </div>
        ))}
      </div>
    </div>
  );
}
