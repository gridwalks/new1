import { json, listLogs, getUser, requireAdmin } from "./util";
export const handler = async (event:any, context:any) => {
  const user = getUser(context); requireAdmin(user);
  const logs = await listLogs("admin:", 1000);
  const out = logs.map(l => ({ id:l.id, ts:l.ts, user:l.user || "anon", question:l.question, answer:l.answer, resources:l.resources||[], latency_ms:l.latency_ms, api:l.api }));
  return json(out);
};
