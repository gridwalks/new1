import { listLogs, getUser, requireAdmin } from "./util";
export const handler = async (event:any, context:any) => {
  const user = getUser(context); requireAdmin(user);
  const logs = await listLogs("admin:", 2000);
  const rows = [["ts","user","question","answer","latency_ms","api","resources"]];
  for (const l of logs) rows.push([l.ts,l.user||"",(l.question||"").replace(/\n/g," "),(l.answer||"").replace(/\n/g," "),String(l.latency_ms||""),l.api||"",JSON.stringify(l.resources||[])]);
  const csv = rows.map(r => r.map(x => `"${String(x).replace(/"/g,'""')}"`).join(",")).join("\n");
  return { statusCode:200, headers:{ "Content-Type":"text/csv", "Content-Disposition":"attachment; filename=acceleraqa-logs-admin.csv" }, body: csv };
};
