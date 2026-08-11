# Authelia Admin

A small web UI for managing users in [Authelia](https://www.authelia.com/)'s file-based authentication backend. Add, edit, disable and delete users, send email invites, and restore accounts from an encrypted backup — without hand-editing `users_database.yml`.

Built for a homelab setup: Caddy in front, Authelia doing SSO, everything on a Docker network.

## Security model — read this first

**This app has no login of its own.** It trusts the `Remote-User` and `Remote-Groups` request headers to decide who you are and whether you're an admin. That means:

- It **must** sit behind a reverse proxy that authenticates every request.
- That proxy **must** strip client-supplied `Remote-*` headers before setting its own.
- The container port **must not** be reachable by anything except the proxy.

If any of those aren't true, anyone who can reach the app can send `Remote-Groups: admins` and take over your user database.

Caddy's `forward_auth` does **not** strip these headers for you. See [GHSA-7r4p-vjf4-gxv4](https://github.com/caddyserver/caddy/security/advisories/GHSA-7r4p-vjf4-gxv4) — when the auth service returns 200 without setting a header in `copy_headers`, the client's own value passes straight through.

### Caddy example

Because `forward_auth` sorts before `request_header` in Caddy's default directive order, the strip has to go inside a `route` block, where directives run in the order written.

```caddyfile
(strip_remote) {
	request_header -Remote-User
	request_header -Remote-Groups
	request_header -Remote-Name
	request_header -Remote-Email
}

admin.example.com {
	route {
		import strip_remote
		forward_auth authelia:9091 {
			uri /api/authz/forward-auth?rd=https://admin.example.com/
			copy_headers Remote-User Remote-Groups Remote-Name Remote-Email
		}
		reverse_proxy admin:8084
	}
}
```

Put the app on a dedicated Docker network shared only with the proxy and Authelia, and don't publish its port to the host.

## Features

- List, add, edit, enable/disable and delete users
- **Email invites** — leave the password blank on creation and the user receives an Authelia password-reset email to set their own
- **Resend invite**, shown only for users who haven't yet set a password
- **Import from backup** — upload an encrypted archive and recreate missing users, each with a fresh invite
- CSRF protection, rate limiting on sensitive routes, and admin-only write access

## Requirements

- Authelia with the file authentication backend
- `authentication_backend.file.watch: true`, so changes are picked up without a restart
- `authentication_backend.password_reset.disable: false`
- A reverse proxy configured as described above
- SMTP configured in Authelia (invites use Authelia's own notifier)

## Setup

```yaml
services:
  admin:
    build: .
    container_name: authelia-admin
    volumes:
      - /opt/authelia/config/users_database.yml:/config/users_database.yml
      - /opt/admin/state:/state
    networks:
      - authnet
    restart: unless-stopped
    read_only: true
    tmpfs:
      - /tmp:size=32m,mode=1777
      - /root:size=8m,mode=0700
    cap_drop:
      - ALL
    security_opt:
      - no-new-privileges:true

networks:
  authnet:
    external: true
```

Mount only `users_database.yml`, not the whole Authelia config directory — that directory also holds your JWT secret, session secret, storage encryption key and OIDC private keys, none of which this app needs.

The `state` directory holds `pending.json`, which tracks which users have been invited but haven't set a password yet. It contains bcrypt hashes, so keep it out of version control.

### Invite lifespan

Invites use Authelia's password-reset flow, so the link expires after `identity_validation.reset_password.jwt_lifespan` (default 5 minutes). Worth raising for invites:

```yaml
identity_validation:
  reset_password:
    jwt_lifespan: '2 hours'
```

Note that this affects ordinary password resets too.

## Backup format

The import expects a GPG symmetrically-encrypted gzipped tarball containing `users_database.yml` at the root:

```bash
tar -czf backup.tar.gz -C /opt/authelia/config users_database.yml
gpg --symmetric --cipher-algo AES256 --output backup.tar.gz.gpg backup.tar.gz
```

Create it however suits you — a cron job, a script, by hand. This app only reads the format.

**The passphrase is never stored by this app.** You enter it in the import form, it's used once to decrypt into a temporary directory, and everything is deleted afterwards. Keep it somewhere separate from the backups themselves.

### What import does and doesn't do

- Users already present in `users_database.yml` are **skipped**, never overwritten
- New users are created with a random password they can't use, then sent an invite to choose their own
- Two-factor devices are **not** restored — those live in Authelia's own database, so everyone re-enrols their passkey or TOTP

It's a way to rebuild accounts after a disaster, not a full restore.

## Notes

- Passwords are hashed with bcrypt. Match whatever `authentication_backend.file.password.algorithm` is set to, or Authelia won't accept them.
- Usernames are case-sensitive in Authelia; `paul` and `Paul` are different accounts.

## Licence

AGPL-3.0
