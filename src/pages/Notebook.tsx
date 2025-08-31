import React from "react";
import { logsUser, exportLogsUser } from "../lib/api";
import type { LogEntry } from "../types";
export default function Notebook(){
  const [logs, setLogs] = React.useState<LogEntry[]>([]);
  const [loading, setLoading] = React.useState(true);
  const [err, setErr] = React.useState<string|null>(null);
  React.useEffect(() => { logsUser().then(setLogs).catch(e=>setErr(String(e))).finally(()=>setLoading(false)); }, []);
  async function onExport(){
    const blob = await exportLogsUser(); const url = URL.createObjectURL(blob);
    const a = document.createElement("a"); a.href=url; a.download="acceleraqa-notebook.csv"; a.click(); URL.revokeObjectURL(url);
  }
  return (
    <div className="mx-auto max-w-5xl px-4 py-6">
      <div className="flex items-center justify-between mb-4">
        <h1 className="text-2xl font-bold">Notebook (last 30 days)</h1>
        <button onClick={onExport}>Export CSV</button>
      </div>
      {loading ? (<div>Loading…</div>) : err ? (<div className="text-red-400">{err}</div>) : (
        <div className="space-y-4">
          {logs.map(l => (
            <div key={l.id} className="card p-4">
              <div className="text-xs text-neutral-400">{new Date(l.ts).toLocaleString()}</div>
              <div className="mt-2"><div className="font-semibold">You</div><div className="text-neutral-200 whitespace-pre-wrap">{l.question}</div></div>
              <div className="mt-3"><div className="font-semibold">Answer</div><div className="text-neutral-200 whitespace-pre-wrap">{l.answer}</div></div>
              {l.resources?.length>0 && (<div className="mt-3"><div className="font-semibold">Resources</div><ul className="list-disc list-inside text-neutral-300">{l.resources.map((r,i)=>(<li key={i}><a href={r.url} target="_blank" rel="noreferrer">{r.title}</a></li>))}</ul></div>)}
            </div>
          ))}
        </div>
      )}
    </div>
  );
}
