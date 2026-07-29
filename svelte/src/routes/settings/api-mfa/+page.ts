import { redirect } from '@sveltejs/kit';

/** Legacy settings path → `/settings/mfa`. */
export function load() {
  redirect(308, '/settings/mfa');
}
