import { sessionEmail, users, admins } from './_auth.js';
export const config = { runtime: 'edge' };
export default async function handler(req) {
  const e = await sessionEmail(req);
  if (!e) return new Response('{}', { status: 401 });
  const adm = admins().includes(e);
  return Response.json({ voce: e, admin: adm, usuarios: adm ? Object.keys(users()).sort() : [] }, { headers: { 'Cache-Control': 'no-store' } });
}
