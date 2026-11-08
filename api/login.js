import { checkPassword, makeSession } from './_auth.js';
export const config = { runtime: 'edge' };
export default async function handler(req) {
  const u = new URL(req.url);
  if (req.method !== 'POST') return Response.redirect(new URL('/login', u.origin), 303);
  const f = await req.formData();
  const email = String(f.get('email') || '').trim().toLowerCase();
  let volta = String(f.get('volta') || '/');
  if (!volta.startsWith('/') || volta.startsWith('//')) volta = '/';
  if (await checkPassword(email, String(f.get('senha') || ''))) {
    return new Response(null, { status: 303, headers: { Location: volta, 'Set-Cookie': await makeSession(email) } });
  }
  return new Response(null, { status: 303, headers: { Location: '/login?erro=1' + (volta !== '/' ? '&volta=' + encodeURIComponent(volta) : '') } });
}
