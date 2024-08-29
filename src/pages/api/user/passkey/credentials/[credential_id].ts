import { deletePasskeyCredential, getUserPasskeyCredential } from "@lib/server/webauthn";
import { decodeBase64urlIgnorePadding } from "@oslojs/encoding";

import type { APIContext } from "astro";

export async function DELETE(context: APIContext): Promise<Response> {
	const encodedCredentialId = context.params.id as string;
	if (context.locals.user === null || context.locals.session === null) {
		return new Response(null, {
			status: 401
		});
	}
	if (!context.locals.user.emailVerified) {
		return new Response(null, {
			status: 401
		});
	}
	if (context.locals.user.registered2FA && !context.locals.session.twoFactorVerified) {
		return new Response(null, {
			status: 401
		});
	}
	let credentialId: Uint8Array;
	try {
		credentialId = decodeBase64urlIgnorePadding(encodedCredentialId);
	} catch {
		return new Response(null, {
			status: 404
		});
	}
	const credential = getUserPasskeyCredential(context.locals.user.id, credentialId);
	if (credential === null) {
		return new Response(null, {
			status: 404
		});
	}
	deletePasskeyCredential(credentialId);
	return new Response(null, {
		status: 204
	});
}
