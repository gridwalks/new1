import { getUser, listLogs } from "./util";
export const handler = async (event:any, context:any) => {
  const user = getUser(context); if (!user) return { statusCode:401, body:"Unauthorized" };
  const logs = await listLogs(`user:${user.email}:`, 500);
  const rows = [["ts","question","answer","latency_ms","api","resources"]];
  for (const l of logs) rows.push([l.ts,(l.question||"").replace(/\n/g," "),(l.answer||"").replace(/\n/g," "),String(l.latency_ms||""),l.api||"",JSON.stringify(l.resources||[])]);
  const csv = rows.map(r => r.map(x => `"${String(x).replace(/"/g,'""')}"`).join(",")).join("\n");
  return { statusCode:200, headers:{ "Content-Type":"text/csv", "Content-Disposition":"attachment; filename=acceleraqa-notebook.csv" }, body: csv };
};
