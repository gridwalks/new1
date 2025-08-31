export const handler = async ()=>({ statusCode:200, headers:{'Content-Type':'application/json'}, body: JSON.stringify({ ok:true, ts:new Date().toISOString() })});
