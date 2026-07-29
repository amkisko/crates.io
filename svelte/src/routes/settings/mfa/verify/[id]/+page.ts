import { redirect } from '@sveltejs/kit';

/** Legacy verify path → `/mfa/verify/{id}`. */
export function load({ params }) {
  redirect(308, `/mfa/verify/${params.id}`);
}
