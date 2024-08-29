import { createWebAuthnChallenge, webauthnChallengeRateLimitBucket } from "@lib/server/webauthn";
import { encodeBase64 } from "@oslojs/encoding";

import type { APIContext } from "astro";

export async function POST(context: APIContext): Promise<Response> {
	const clientIP = context.request.headers.get("X-Forwarded-For");
	if (clientIP !== null) {
		if (!webauthnChallengeRateLimitBucket.check(clientIP, 1)) {
			return new Response(null, {
				status: 429
			});
		}
	}
	const challenge = createWebAuthnChallenge();
	return new Response(JSON.stringify({ challenge: encodeBase64(challenge) }));
}
