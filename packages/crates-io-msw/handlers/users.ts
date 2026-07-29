import confirmEmail from './users/confirm-email.js';
import getUser from './users/get.js';
import me from './users/me.js';
import mfa from './users/mfa.js';
import resend from './users/resend.js';
import securityEvents from './users/security-events.js';
import stats from './users/stats.js';
import updateUser from './users/update.js';

export default [getUser, updateUser, resend, me, mfa, securityEvents, confirmEmail, stats];
