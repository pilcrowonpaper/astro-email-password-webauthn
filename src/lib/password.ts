import { hash, verify } from "@node-rs/argon2";
import { sha1 } from "@oslojs/crypto/sha1";
import { encodeBase32, encodeHexLowerCase } from "@oslojs/encoding";
import { db } from "./db";
import { generateRandomOTP } from "./utils";

import type { APIContext } from "astro";
import type { User } from "./user";

export async function hashPassword(password: string): Promise<string> {
	return await hash(password, {
		memoryCost: 19456,
		timeCost: 2,
		outputLen: 32,
		parallelism: 1
	});
}

export async function verifyPasswordHash(hash: string, password: string): Promise<boolean> {
	return await verify(hash, password);
}

export async function verifyPasswordStrength(password: string): Promise<boolean> {
	const hash = encodeHexLowerCase(sha1(new TextEncoder().encode(password)));
	const hashPrefix = hash.slice(0, 5);
	const response = await fetch(`https://api.pwnedpasswords.com/range/${hashPrefix}`);
	const data = await response.text();
	const items = data.split("\n");
	for (const item of items) {
		const hashSuffix = item.slice(0, 35).toLowerCase();
		if (hash === hashPrefix + hashSuffix) {
			return false;
		}
	}
	return true;
}

export function createPasswordResetSession(userId: number, email: string): PasswordResetSession {
	const idBytes = new Uint8Array(20);
	crypto.getRandomValues(idBytes);
	const id = encodeBase32(idBytes).toLowerCase();

	const expiresAtUnix = Math.floor(Date.now() / 1000) + 60 * 60 * 10;
	const expiresAt = new Date(expiresAtUnix * 1000);

	const session: PasswordResetSession = {
		id,
		userId,
		email,
		expiresAt,
		code: generateRandomOTP(),
		emailVerified: false,
		twoFactorVerified: false
	};
	db.execute("INSERT INTO password_reset_session (id, user_id, email, code, expires_at) VALUES (?, ?, ?, ?, ?)", [
		session.id,
		session.userId,
		session.email,
		session.code,
		Math.floor(session.expiresAt.getTime() / 1000)
	]);
	return session;
}

export function invalidateUserPasswordResetSessions(userId: number) {
	db.execute("DELETE FROM password_reset_session WHERE user_id = ?", [userId]);
}

export const passwordResetSessionCookieName = "password_reset_session";

export function validatePasswordResetSessionRequest(context: APIContext): PasswordResetSessionValidationResult {
	const sessionId = context.cookies.get(passwordResetSessionCookieName)?.value ?? null;
	if (sessionId === null) {
		return { session: null, user: null };
	}
	const row = db.queryOne(
		`SELECT password_reset_session.id, password_reset_session.user_id, password_reset_session.email, password_reset_session.code, password_reset_session.expires_at, password_reset_session.email_verified, password_reset_session.two_factor_verified
user.id, user.email, user.username, user.email_verified, IIF(totp_credential.id IS NOT NULL, 1, 0), IIF(passkey_credential.id IS NOT NULL, 1, 0), IIF(security_key_credential.id IS NOT NULL, 1, 0) FROM password_reset_session
INNER JOIN user ON password_reset_session.user_id = user.id
LEFT JOIN totp_credential ON user.id = totp_credential.user_id
LEFT JOIN passkey_credential ON user.id = passkey_credential.user_id
LEFT JOIN security_key_credential ON user.id = security_key_credential.user_id
WHERE id = ?`,
		[sessionId]
	);
	if (row === null) {
		return { session: null, user: null };
	}
	const session: PasswordResetSession = {
		id: row.string(0),
		userId: row.number(1),
		email: row.string(2),
		code: row.string(3),
		expiresAt: new Date(row.number(4) * 1000),
		emailVerified: Boolean(row.number(5)),
		twoFactorVerified: Boolean(row.number(6))
	};
	if (Date.now() >= session.expiresAt.getTime()) {
		db.execute("DELETE FROM password_reset_session WHERE id = ?", [session.id]);
		deletePasswordResetSessionCookie(context);
		return { session: null, user: null };
	}
	const user: User = {
		id: row.number(7),
		email: row.string(8),
		username: row.string(9),
		emailVerified: Boolean(row.number(10)),
		registeredTOTP: Boolean(row.number(11)),
		registeredPasskey: Boolean(row.number(12)),
		registeredSecurityKey: Boolean(row.number(13)),
		registered2FA: false
	};
	if (user.registeredPasskey || user.registeredSecurityKey || user.registeredTOTP) {
		user.registered2FA = true;
	}
	return { session, user };
}

export function setPasswordResetSessionCookie(context: APIContext, session: PasswordResetSession): void {
	context.cookies.set(passwordResetSessionCookieName, session.id, {
		expires: session.expiresAt,
		sameSite: "lax",
		httpOnly: true,
		path: "/",
		secure: !import.meta.env.DEV
	});
}

export function deletePasswordResetSessionCookie(context: APIContext): void {
	context.cookies.set(passwordResetSessionCookieName, "", {
		maxAge: 0,
		sameSite: "lax",
		httpOnly: true,
		path: "/",
		secure: !import.meta.env.DEV
	});
}

export function invalidateUserPasswordResetSession(userId: number): void {
	db.execute("DELETE FROM password_reset_session WHERE user_id = ?", [userId]);
}

export function invalidatePasswordResetSession(sessionId: string): void {
	db.execute("DELETE FROM password_reset_session WHERE id = ?", [sessionId]);
}

export function verifyPasswordResetSessionEmail(sessionId: string, email: string): boolean {
	const result = db.execute("UPDATE password_reset_session SET email_verified = 1 WHERE id = ? AND email = ?", [
		sessionId,
		email
	]);
	return result.changes > 0;
}

export function verifyPasswordResetSession2FA(sessionId: string): void {
	db.execute("UPDATE password_reset_session SET two_factor_verified = 1 WHERE id = ?", [sessionId]);
}

export function sendPasswordResetEmail(email: string, code: string): void {
	console.log(`To ${email}: Your reset code is ${code}`);
}

interface PasswordResetSession {
	id: string;
	userId: number;
	email: string;
	code: string;
	expiresAt: Date;
	emailVerified: boolean;
	twoFactorVerified: boolean;
}

export type PasswordResetSessionValidationResult =
	| {
			session: PasswordResetSession;
			user: User;
	  }
	| {
			session: null;
			user: null;
	  };
