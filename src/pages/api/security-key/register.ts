import {
	parseAttestationObject,
	AttestationStatementFormat,
	parseClientDataJSON,
	coseAlgorithmES256,
	coseEllipticCurveP256,
	ClientDataType,
	coseAlgorithmRS256
} from "@oslojs/webauthn";
import { ECDSAPublicKey, p256 } from "@oslojs/crypto/ecdsa";
import { ObjectParser } from "@pilcrowjs/object-parser";
import { decodeBase64 } from "@oslojs/encoding";
import { verifyWebAuthnChallenge, createSecurityKeyCredential } from "@lib/webauthn";
import { verifySession2FA } from "@lib/session";
import { RSAPublicKey } from "@oslojs/crypto/rsa";
import { SqliteError } from "better-sqlite3";

import type { APIContext } from "astro";
import type { WebAuthnUserCredential } from "@lib/webauthn";
import type {
	COSEEC2PublicKey,
	COSERSAPublicKey,
	AttestationStatement,
	AuthenticatorData,
	ClientData
} from "@oslojs/webauthn";

// Stricter rate limiting can be omitted here since creating challenges are rate-limited
export async function POST(context: APIContext): Promise<Response> {
	if (context.locals.session === null || context.locals.user === null) {
		return new Response(null, {
			status: 401
		});
	}
	if (context.locals.user.registered2FA && !context.locals.session.twoFactorVerified) {
		return new Response(null, {
			status: 401
		});
	}

	const data: unknown = await context.request.json();
	const parser = new ObjectParser(data);
	let name: string, encodedAttestationObject: string, encodedClientDataJSON: string;
	try {
		name = parser.getString("name");
		encodedAttestationObject = parser.getString("attestation_object");
		encodedClientDataJSON = parser.getString("client_data_json");
	} catch {
		return new Response("Invalid or missing fields", {
			status: 400
		});
	}
	let attestationObjectBytes: Uint8Array, clientDataJSON: Uint8Array;
	try {
		attestationObjectBytes = decodeBase64(encodedAttestationObject);
		clientDataJSON = decodeBase64(encodedClientDataJSON);
	} catch {
		return new Response("Invalid or missing fields", {
			status: 400
		});
	}

	let attestationStatement: AttestationStatement;
	let authenticatorData: AuthenticatorData;
	try {
		let attestationObject = parseAttestationObject(attestationObjectBytes);
		attestationStatement = attestationObject.attestationStatement;
		authenticatorData = attestationObject.authenticatorData;
	} catch {
		return new Response("Invalid data", {
			status: 400
		});
	}
	if (attestationStatement.format !== AttestationStatementFormat.None) {
		return new Response("Invalid data", {
			status: 400
		});
	}
	if (!authenticatorData.verifyRelyingPartyIdHash("localhost")) {
		return new Response("Invalid data", {
			status: 400
		});
	}
	if (!authenticatorData.userPresent) {
		return new Response("Invalid data", {
			status: 400
		});
	}
	if (authenticatorData.credential === null) {
		return new Response("Invalid data", {
			status: 400
		});
	}

	let clientData: ClientData;
	try {
		clientData = parseClientDataJSON(clientDataJSON);
	} catch {
		return new Response("Invalid data", {
			status: 400
		});
	}
	if (clientData.type !== ClientDataType.Create) {
		return new Response("Invalid data", {
			status: 400
		});
	}
	if (!verifyWebAuthnChallenge(clientData.challenge)) {
		return new Response("Invalid data", {
			status: 400
		});
	}
	if (clientData.origin !== "http://localhost:4321") {
		return new Response("Invalid data", {
			status: 400
		});
	}
	if (clientData.crossOrigin !== null && clientData.crossOrigin) {
		return new Response("Invalid data", {
			status: 400
		});
	}

	let credential: WebAuthnUserCredential;
	if (authenticatorData.credential.publicKey.algorithm() === coseAlgorithmES256) {
		let cosePublicKey: COSEEC2PublicKey;
		try {
			cosePublicKey = authenticatorData.credential.publicKey.ec2();
		} catch {
			return new Response("Invalid data", {
				status: 400
			});
		}
		if (cosePublicKey.curve !== coseEllipticCurveP256) {
			return new Response("Unsupported algorithm", {
				status: 400
			});
		}
		// Store the credential ID, algorithm (ES256), and public key with the user's user ID
		const encodedPublicKey = new ECDSAPublicKey(p256, cosePublicKey.x, cosePublicKey.y).encodeSEC1Uncompressed();
		credential = {
			id: authenticatorData.credential.id,
			userId: context.locals.user.id,
			algorithmId: coseAlgorithmES256,
			name,
			publicKey: encodedPublicKey
		};
	} else if (authenticatorData.credential.publicKey.algorithm() === coseAlgorithmRS256) {
		let cosePublicKey: COSERSAPublicKey;
		try {
			cosePublicKey = authenticatorData.credential.publicKey.rsa();
		} catch {
			return new Response("Invalid data", {
				status: 400
			});
		}
		const encodedPublicKey = new RSAPublicKey(cosePublicKey.n, cosePublicKey.e).encodePKCS1();
		credential = {
			id: authenticatorData.credential.id,
			userId: context.locals.user.id,
			algorithmId: coseAlgorithmRS256,
			name,
			publicKey: encodedPublicKey
		};
	} else {
		return new Response("Unsupported algorithm", {
			status: 400
		});
	}

	try {
		createSecurityKeyCredential(credential);
	} catch (e) {
		if (e instanceof SqliteError && e.code === "SQLITE_CONSTRAINT_PRIMARYKEY") {
			return new Response("Invalid data", {
				status: 400
			});
		}
		return new Response("Internal error", {
			status: 500
		});
	}

	if (!context.locals.session.twoFactorVerified) {
		verifySession2FA(context.locals.session.id);
	}

	return new Response(null, {
		status: 204
	});
}
