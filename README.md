# ComfyUI Auth

A server-level authentication custom node for ComfyUI. It protects the UI,
HTTP APIs, static files, and WebSocket connections behind a username/password
login page. Accounts can be authenticated using local SHA-256 hashes or LDAP.

## Install

Clone or copy this directory into ComfyUI's `custom_nodes` directory:

```text
ComfyUI/custom_nodes/comfyui-auth/
```

Install the LDAP client dependency in the same Python environment that runs
ComfyUI:

```bash
python -m pip install -r ComfyUI/custom_nodes/comfyui-auth/requirements.txt
```

### Local users

Create the user configuration:

```bash
cd ComfyUI/custom_nodes/comfyui-auth
cp users.conf.example users.conf
printf '%s' 'choose-a-strong-password' | sha256sum
```

Copy the resulting 64-character hash into `users.conf`. Add one account per
line using this exact format:

```ini
alice = 7d1e2a...
bob = 4e738c...
```

Blank lines and lines beginning with `#` or `;` are ignored. Usernames are
case-sensitive. Restart ComfyUI, then open its URL and sign in. The example
entry is `admin` / `password`; **replace or remove it before use**.

To log out, visit `/comfyui-auth/logout`.

### LDAP users

Copy and edit the dedicated LDAP configuration file:

```bash
cp ldap.conf.example ldap.conf
```

Its format is:

```ini
LDAP_SERVER = ldap://ldap.example.com:389
SEARCH_BASE = DC=example,DC=com
WHITELIST = alice, bob
```

The `DC` components of `SEARCH_BASE` define the accepted login suffix. In the
example above, LDAP routing applies only to usernames ending in `@example.com`.
The comparison is case-insensitive.

For a login such as `alice@example.com`, the plugin performs these steps in order:

1. Derive `example.com` from `SEARCH_BASE` and match the login suffix.
2. Check that `alice` (without `@example.com`) exists in `WHITELIST`.
3. Only after the whitelist check succeeds, bind to `LDAP_SERVER` using the
   complete `alice@example.com` username and the submitted password.

If the suffix does not match the LDAP domain, the login is checked against
`users.conf` instead. A matching LDAP-domain username never falls back to a
local password after an LDAP or whitelist failure.

`users.conf` and `ldap.conf` are independently optional, but at least one valid
authentication provider must be configured. Changes to both files are picked
up without restarting ComfyUI. Removing a local user or an LDAP whitelist entry
also invalidates that user's existing session.

## Configuration

Optional environment variables:

- `COMFYUI_AUTH_USERS_FILE`: absolute or relative path to a different users file.
- `COMFYUI_AUTH_LDAP_FILE`: absolute or relative path to a different LDAP file.
- `COMFYUI_AUTH_SESSION_MAX_AGE`: session lifetime in seconds (default `86400`,
  minimum `300`).
- `COMFYUI_AUTH_SECURE_COOKIE`: set to `1` when HTTPS is terminated by a reverse
  proxy, so the session cookie is always marked `Secure`.

The plugin generates `.session_secret` on first startup and sets its mode to
`0600`. Keep this file private and persistent; deleting it signs out every user.

## Security notes

- Put ComfyUI behind HTTPS when it is accessible over a network. Passwords and
  cookies are otherwise exposed to network observers. If TLS terminates at a
  reverse proxy, set `COMFYUI_AUTH_SECURE_COOKIE=1`.
- Plain SHA-256 password hashes are supported because that is the requested
  configuration format, but they are not resistant to offline password
  cracking. Use long, unique passwords and protect `users.conf` with filesystem
  permissions (for example, `chmod 600 users.conf`).
- LDAP authentication follows `ldap_auth_test.py`: it creates an `ldap3.Server`
  with `use_ssl=True` and validates credentials through a direct user bind.
  Verify that the configured server/port and its certificate policy are correct
  for your LDAP deployment.
- Login attempts are limited in memory to 10 attempts per client address per
  5 minutes. Restarting ComfyUI clears the limiter.
- If neither a valid local nor LDAP provider is available, authentication fails
  closed and the login page displays the configuration error.
