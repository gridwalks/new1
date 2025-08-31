import React from "react";
import ChatMessage from "../components/ChatMessage";
import { chat, getSettings } from "../lib/api";
import type { Resource } from "../types";
export default function ChatApp(){
  const [input, setInput] = React.useState("");
  const [messages, setMessages] = React.useState<{role:"user"|"assistant";content:string}[]>([]);
  const [resources, setResources] = React.useState<Resource[]>([]);
  const [loading, setLoading] = React.useState(false);
  const [settings, setSettings] = React.useState<any>(null);
  const [error, setError] = React.useState<string|null>(null);
  React.useEffect(() => { getSettings().then(setSettings).catch(()=>{}); }, []);
  async function onSend(){
    if (!input.trim()) return;
    const text = input.trim();
    setInput(""); setMessages(m => [...m, {role:"user", content:text}]); setLoading(true); setError(null);
    try {
      const res = await chat({ message: text, options: {} });
      setMessages(m => [...m, {role:"assistant", content: res.answer}]);
      setResources(res.resources || []);
    } catch (e:any) { setError(e.message || "Request failed"); }
    finally { setLoading(false); }
  }
  function onKeyDown(e: React.KeyboardEvent<HTMLTextAreaElement>){
    if (e.key === "Enter" && !e.shiftKey){ e.preventDefault(); onSend(); }
  }
  return (
    <div className="mx-auto max-w-6xl px-4 py-6 grid grid-cols-1 md:grid-cols-3 gap-6">
      <div className="md:col-span-2 space-y-4">
        <div className="card p-4 h-[70vh] overflow-y-auto space-y-4">
          {messages.length===0 && <div className="text-neutral-400">Ask about 21 CFR Part 11, ICH E6(R3), CSV, privacy, and more.</div>}
          {messages.map((m,i)=>(<ChatMessage key={i} role={m.role} content={m.content}/>))}
          {loading && <div className="text-neutral-400">Thinking…</div>}
          {error && <div className="text-red-400">{error}</div>}
        </div>
        <div className="flex items-start gap-3">
          <textarea value={input} onChange={e=>setInput(e.target.value)} onKeyDown={onKeyDown} placeholder="Type your question… (Enter to send)" className="w-full min-h-[64px] p-3" />
          <button onClick={onSend} disabled={loading || !input.trim()}>Send</button>
        </div>
      </div>
      <aside className="md:col-span-1">
        <div className="card p-4 sticky top-20">
          <h2 className="font-semibold mb-2">Further learning</h2>
          <div className="space-y-3">
            {resources.length===0 ? (<p className="text-neutral-400">Resources from each answer will appear here.</p>) : (
              resources.map((r,i)=>(<div key={i}><a href={r.url} target="_blank" rel="noreferrer">{r.title}</a>{r.source && <div className="text-xs text-neutral-400">{r.source}</div>}</div>))
            )}
          </div>
          {settings && (<div className="text-xs text-neutral-500 mt-4">Domains allowed: {(settings.allowedDomains||[]).join(", ") || "any"}</div>)}
        </div>
      </aside>
    </div>
  );
}
