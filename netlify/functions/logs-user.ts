import { json, listLogs, getUser } from "./util";
export const handler = async (event:any, context:any) => {
  const user = getUser(context); if (!user) return { statusCode:401, body:"Unauthorized" };
  const prefix = `user:${user.email}:`; const logs = await listLogs(prefix, 500);
  const out = logs.map(l => ({ id:l.id, ts:l.ts, user:user.email, question:l.question, answer:l.answer, resources:l.resources||[], latency_ms:l.latency_ms, api:l.api }));
  return json(out);
};
