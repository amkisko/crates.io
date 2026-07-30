import { redirect } from '@sveltejs/kit';

/** Legacy verify path → `/verify/{id}`. */
export function load({ params }) {
  redirect(308, `/verify/${params.id}`);
}
