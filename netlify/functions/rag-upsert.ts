import { json, ragStore, getUser, requireAdmin, id } from "./util";
export const handler = async (event:any, context:any) => {
  const user = getUser(context); requireAdmin(user);
  const body = JSON.parse(event.body || "{}");
  const doc = { id: body.id || id("doc"), title: body.title, url: body.url, content: body.content || "", keywords: body.keywords || [], updatedAt: new Date().toISOString() };
  await ragStore.setJSON(`doc:${doc.id}`, doc);
  return json({ ok:true, id: doc.id });
};
