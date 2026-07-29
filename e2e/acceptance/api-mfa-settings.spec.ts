import { expect, test } from '@/e2e/helper';

test.describe('Acceptance | API MFA settings', { tag: '@acceptance' }, () => {
  test('settings MFA and activity pages load for signed-in user', async ({ page, msw, a11y }) => {
    let user = await msw.db.user.create({
      login: 'mfa-user',
      name: 'MFA User',
      email: 'mfa@example.com',
    });
    await msw.authenticateAs(user);

    await page.goto('/settings/mfa');
    await expect(page).toHaveURL('/settings/mfa');
    await expect(page.getByRole('heading', { name: /API MFA/i })).toBeVisible();
    await expect(page.locator('[data-test-settings-menu] [data-test-mfa]')).toBeVisible();
    await a11y.audit();

    await page.goto('/settings/activity');
    await expect(page).toHaveURL('/settings/activity');
    await expect(page.getByRole('heading', { name: /Recent security activity/i })).toBeVisible();
    await expect(page.locator('[data-test-activity-empty], [data-test-activity-list]')).toBeVisible();
    await a11y.audit();
  });
});
