import { db } from "./db";
import { generateRandomRecoveryCode } from "./utils";
import { FixedRefillTokenBucket } from "./rate-limit";

import type { User } from "./user";

export const recoveryCodeBucket = new FixedRefillTokenBucket<number>(5, 60 * 60);

export function resetUser2FAWithRecoveryCode(userId: number, recoveryCode: string): boolean {
	db.execute("UPDATE session SET two_factor_verified = 0 WHERE user_id = ?", [userId]);
	const newRecoveryCode = generateRandomRecoveryCode();
	try {
		db.execute("BEGIN TRANSACTION", []);
		const result = db.execute("UPDATE user SET recovery_code = ? WHERE id = ? AND recovery_code = ?", [
			newRecoveryCode,
			userId,
			recoveryCode
		]);
		if (result.changes < 1) {
			db.execute("COMMIT", []);
			return false;
		}
		db.execute("DELETE FROM totp_credential WHERE user_id = ?", [userId]);
		db.execute("DELETE FROM passkey_credential WHERE user_id = ?", [userId]);
		db.execute("DELETE FROM security_key_credential WHERE user_id = ?", [userId]);
		db.execute("COMMIT", []);
	} catch (e) {
		if (db.inTransaction()) {
			db.execute("ROLLBACK", []);
		}
		throw e;
	}
	return true;
}

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
