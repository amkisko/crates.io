import { redirect } from '@sveltejs/kit';

/** Legacy settings path → top-level capability URL. */
export function load({ params }) {
  redirect(308, `/webauthn-verify/${params.id}`);
}
