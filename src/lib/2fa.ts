import { FixedRefillTokenBucket } from "../lib/rate-limit";

export const totpBucket = new FixedRefillTokenBucket<number>(5, 60 * 30);
export const recoveryCodeBucket = new FixedRefillTokenBucket<number>(5, 60 * 60);

import type { User } from "../lib/user";

export function get2FARedirect(user: User): string {
	if (user.registeredPasskey) {
		return "/2fa/passkey";
	}
	if (user.registeredSecurityKey) {
		return "/2fa/security-key";
	}
	if (user.registeredTOTP) {
		return "/2fa/totp";
	}
	return "/2fa/setup";
}

export function getPasswordReset2FARedirect(user: User): string {
	if (user.registeredPasskey) {
		return "/reset-password/2fa/passkey";
	}
	if (user.registeredSecurityKey) {
		return "/reset-password/2fa/security-key";
	}
	if (user.registeredTOTP) {
		return "/reset-password/2fa/totp";
	}
	return "/2fa/setup";
}
