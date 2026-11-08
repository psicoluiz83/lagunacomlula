import { clearSession } from './_auth.js';
export const config = { runtime: 'edge' };
export default function handler() {
  return new Response(null, { status: 303, headers: { Location: '/login?saiu=1', 'Set-Cookie': clearSession() } });
}
