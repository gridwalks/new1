import { json, ragStore, getUser, requireAdmin } from "./util";
export const handler = async (event:any, context:any) => {
  const user = getUser(context); requireAdmin(user);
  const id = new URLSearchParams(event.queryStringParameters || {}).get("id");
  if (!id) return { statusCode:400, body:"missing id" };
  await ragStore.delete(`doc:${id}`); return json({ ok:true });
};
