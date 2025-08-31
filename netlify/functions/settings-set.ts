import { json, loadSettings, settingsStore, getUser, requireAdmin } from "./util";
export const handler = async (event:any, context:any) => {
  const user = getUser(context); requireAdmin(user);
  const body = JSON.parse(event.body || "{}");
  const prev = await loadSettings();
  const merged = {
    sys_prompt: body.sys_prompt ?? prev.sys_prompt,
    allowedDomains: body.allowedDomains ?? prev.allowedDomains,
    resourcesMax: body.resourcesMax ?? prev.resourcesMax,
    ragTopK: body.ragTopK ?? prev.ragTopK,
    chatRequireAuth: body.chatRequireAuth ?? prev.chatRequireAuth,
  };
  await settingsStore.setJSON("admin:config", merged);
  return json({ ok:true });
};
