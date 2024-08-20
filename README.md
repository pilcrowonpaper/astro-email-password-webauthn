# Email and password example with 2FA and passkeys

Built with Astro and SQLite.

- Password check with HaveIBeenPwned
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

Run the application:

```
pnpm dev
```

## User enumeration

I do not consider user enumeration to be a real vulnerability so please don't open issues on it. If you really need to prevent it, just don't use emails.
