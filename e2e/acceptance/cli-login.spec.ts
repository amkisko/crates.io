import { expect, test } from '@/e2e/helper';

test.describe('Acceptance | cli-login', { tag: '@acceptance' }, () => {
  test('approve page has no plaintext token after approve', async ({ page, msw, a11y }) => {
    let user = await msw.db.user.create({
      login: 'johnnydee',
      name: 'John Doe',
      email: 'john@doe.com',
    });
    await msw.authenticateAs(user);

    let session = await msw.db.cliLoginSession.create({
      status: 'pending',
    });

    await page.goto(`/settings/tokens/cli/${session.id}`);
    await expect(page.locator('[data-test-cli-login-heading]')).toHaveText('Authorize cargo login');
    await expect(page.locator('[data-test-cli-login-form]')).toBeVisible();

    await a11y.audit();

    await page.locator('[data-test-name]').fill('playwright-cli');
    await page.locator('[data-test-approve]').click();

    await expect(page.locator('[data-test-cli-login-success]')).toBeVisible();
    await expect(page.locator('[data-test-cli-login-success]')).toContainText('Return to the terminal');

    // Approve response and success UI must never expose the plaintext token.
    await expect(page.locator('body')).not.toContainText('cio_');
    await expect(page.locator('body')).not.toContainText('?token=');
    await expect(page.locator('[data-test-token]')).toHaveCount(0);
    await expect(page.getByRole('button', { name: /copy/i })).toHaveCount(0);

    await a11y.audit();
  });

  test('unauthenticated visitors see sign-in prompt', async ({ page, msw, a11y }) => {
    let session = await msw.db.cliLoginSession.create({ status: 'pending' });
    await page.goto(`/settings/tokens/cli/${session.id}`);
    await expect(page.locator('[data-test-cli-login-signin]')).toBeVisible();
    await expect(page.locator('[data-test-cli-login-signin-button]')).toBeVisible();
    await a11y.audit();
  });
});
