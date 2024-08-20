import { get2FARedirect } from "@lib/2fa";
import type { APIContext } from "astro";

export function GET(context: APIContext): Response {
	if (context.locals.session === null || context.locals.user === null) {
		return context.redirect("/login");
	}
	if (context.locals.session.twoFactorVerified) {
		return context.redirect("/");
	}
	if (!context.locals.user.registered2FA) {
		return context.redirect("/2fa/setup");
	}
	return context.redirect(get2FARedirect(context.locals.user));
}
