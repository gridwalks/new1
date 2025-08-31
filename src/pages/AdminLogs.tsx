import React from "react";
import { logsAdmin, exportLogsAdmin } from "../lib/api";
import type { LogEntry } from "../types";
export default function AdminLogs(){
  const [logs, setLogs] = React.useState<LogEntry[]>([]);
  const [loading, setLoading] = React.useState(true);
  const [err, setErr] = React.useState<string|null>(null);
  React.useEffect(()=>{ logsAdmin().then(setLogs).catch(e=>setErr(String(e))).finally(()=>setLoading(false)); }, []);
  async function onExport(){ const b = await exportLogsAdmin(); const u = URL.createObjectURL(b); const a = document.createElement("a"); a.href=u; a.download="acceleraqa-logs-admin.csv"; a.click(); URL.revokeObjectURL(u); }
  return (
    <div className="mx-auto max-w-6xl px-4 py-6">
      <div className="flex items-center justify-between mb-4"><h1 className="text-2xl font-bold">Admin Logs</h1><button onClick={onExport}>Export CSV</button></div>
      {loading ? <div>Loading…</div> : err ? <div className="text-red-400">{err}</div> : (
        <div className="space-y-3">
          {logs.map(l => (
            <div key={l.id} className="card p-4">
              <div className="text-xs text-neutral-400">{new Date(l.ts).toLocaleString()} – {l.user || "anon"}</div>
              <div className="mt-1 text-sm text-neutral-300">API: {l.api} • {l.latency_ms} ms</div>
              <div className="mt-2 font-semibold">Q:</div><div className="whitespace-pre-wrap">{l.question}</div>
              <div className="mt-2 font-semibold">A:</div><div className="whitespace-pre-wrap">{l.answer}</div>
            </div>
          ))}
        </div>
      )}
    </div>
  );
}
