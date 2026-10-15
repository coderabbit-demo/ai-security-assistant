# ai-security-assistant
This is an AI security assistant for checking about any suspicious security incidents that occur. 

## JWT signing key

Before starting the application, set `JWT_SECRET` to a unique secret generated
from at least 32 cryptographically random bytes. Provision it through your
deployment's secret manager or protected environment; never commit it. There is
no default, and startup fails if the value is missing or shorter than 32 bytes.
For local development, generate a key for the current shell with:

```sh
export JWT_SECRET="$(python -c 'import secrets; print(secrets.token_hex(32))')"
python app.py
```

Use the same secret across all application workers and preserve it across
restarts. When deploying this fix, provision a fresh secret instead of either
previously committed key. Replacing `JWT_SECRET` and restarting all workers
invalidates existing tokens, including tokens signed with the exposed keys;
users must log in again. Do not retain the exposed keys for verification.

Run the authentication regression tests with `python -m unittest discover -s tests`.
