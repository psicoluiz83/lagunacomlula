import { sessionEmail } from './api/_auth.js';
export const config = { matcher: ['/((?!login|api/login|api/logout|favicon).*)'] };
export default async function middleware(req) {
  const email = await sessionEmail(req);
  if (email) return new Response(null, { headers: { 'x-middleware-next': '1' } });
  const u = new URL(req.url);
  const to = new URL('/login', u.origin);
  if (u.pathname !== '/') to.searchParams.set('volta', u.pathname + u.search);
  return Response.redirect(to, 302);
}
