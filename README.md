# Email and password example with 2FA and WebAuthn

Built with Astro and SQLite.

- Password checks with HaveIBeenPwned
- Sign in with passkeys
- Email verification
- 2FA with TOTP
- 2FA recovery codes
- 2FA with passkeys and security keys
- Password reset with 2FA
- Login throttling and rate limiting

Emails are not actually sent and just logged to the console. Rate limiting is implemented using JS `Map`s.

## Initialize project

Create `sqlite.db` and run `setup.sql`.

```
sqlite3 sqlite.db
```

Create a .env file. Generate a 128 bit (16 byte) string, base64 encode it, and set it as `ENCRYPTION_KEY`.

```bash
ENCRYPTION_KEY="L9pmqRJnO1ZJSQ2svbHuBA=="
```

Run the application:

```
pnpm dev
```

## Notes

- I do not consider user enumeration to be a real vulnerability so please don't open issues on it. If you really need to prevent it, just don't use emails.
- This example does not handle unexpected errors gracefully.
- There are some major code duplications (specifically for 2FA) to keep the codebase simple.
- Astro warns about unused functions (`get2FARedirect()`) but this is a bug with the language server.
- TODO: You may need to rewrite some queries and use transactions to avoid race conditions when using MySQL, Postgres, etc.
- TODO: Users are not shown their recovery code when they first register their second factor.
- TODO: Users can delete all their second factors (not an issue security wise).
