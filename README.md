# fly-oidc-discharge

A service that mints short-lived Fly.io API tokens inside GitHub Actions
based on OIDC Connect. No (usable) Fly token need to be stored in GitHub secrets.

The problem:

OIDC is a popular form to deploy and authenticate from Github Actions.
[OpenID Connect](https://docs.github.com/en/actions/concepts/security/openid-connect)
lets you scope permissions for a CI workflow so it doesnt need to store
any long-lived credentials to access cloud providers.
Sadly, this isn't supported for fly.io.

The solution:

fly.io implements 'macaroons', a form of signed capabilities. This service bridges OIDC and Macaroons:
In fly.io terminology, it means each Fly token gets a [third-party caveat](https://fly.io/blog/macaroons-escalated-quickly/)
pointing at this service, which leaves the token inert until the service adds a discharge.
This services only adds a discharge after it validates the GitHub OIDC token
and makes sure matches the policy defined in this service.
`fly deploy`, `fly secrets set`, and the rest work unchanged after the service added the discharge.

```mermaid
sequenceDiagram
    participant Job as GitHub Actions job
    participant Svc as fly-oidc-discharge
    participant Fly as Fly.io API
    Job->>Job: fly tokens 3p ticket (caveated token)
    Job->>Svc: POST /.well-known/macfly/3p {ticket}, Authorization: Bearer OIDC JWT
    Svc->>Svc: verify JWT signature, issuer, audience, expiry
    Svc->>Svc: the shared secret that opens the ticket selects the credential
    Svc->>Svc: match claims against that credential's rules only
    Svc->>Svc: sign discharge, add ValidityWindow
    Svc-->>Job: {discharge}, X-Discharge-Credential
    Job->>Fly: FlyV1 caveated,discharge
```

| What leaks | What the attacker gains |
|---|---|
| Caveated token (GitHub secret) | nothing without a discharge |
| Discharged token (compromised CI step) | that one environment, until the window ends |
| One shared secret (this service) | nothing without the matching caveated token |
| A caveated token and its shared secret | the full access of that one Fly token |

## Run it

You can launch the service using the published image.
It carries no default policy, so you'll have to write your own and deploy it
(probably inside fly.io).

You need two files next to each other: `policy.yaml`, and a `fly.toml` that carries the app name,
the `[env]` block, and the `[[files]]` entry that maps the policy into the machine. Examples in
this repository should work with modifications (below).

```bash
git clone https://github.com/gz/fly-oidc-discharge && cd fly-oidc-discharge
cp policy.example.yaml policy.yaml   # then edit it
$EDITOR fly.toml                     # app name, region, OIDC_DISCHARGE_LOCATION
fly launch --flycast --no-deploy --copy-config   # private app, no public IP, keeps this fly.toml
fly secrets set SHARED_SECRET_PROD="$(cat PROD.secret)"
fly deploy --image ghcr.io/gz/fly-oidc-discharge:v1
```

`fly.toml` ships the policy in the `[[files]]` section.
Set `OIDC_DISCHARGE_LOCATION` to the URL the runner will use, which must match the caveat
location exactly.

### Reaching it

The default has no public IP, so the caller must be inside the Fly organization's private network.

| Deployment | Reachable by |
|---|---|
| Flycast, no public IP (default) | self-hosted runners in the org, or runners joined to a WireGuard or Tailscale path into the private network |
| Public IP | any runner, including GitHub-hosted |

For GitHub-hosted runners with no VPN, give the app a public address instead:

```bash
fly ips allocate-v4 --shared
fly ips allocate-v6
```

A public deployment is exposed to anyone, so the OIDC check and the policy are all that stand in
front of it. Both run before the ticket is examined.

### TLS

Three shapes, and the location string has to match whichever you pick.

| Deployment | Who holds the certificate | Location |
|---|---|---|
| Flycast, private (default) | nobody, plain HTTP inside Fly's private WireGuard mesh | `http://<app>.flycast` |
| Public IP | Fly, with a certificate it issues and renews | `https://<app>.fly.dev` |
| Certificate in the app | this service | `https://<a name you control>` |

The default carries no certificate because Flycast serves plain HTTP, and the traffic never leaves
Fly's private network. Going public is the easy upgrade: allocate an address, set
`force_https = true`, and Fly terminates TLS for `<app>.fly.dev` or for a custom domain you add
with `fly certs add`. Nothing in the service changes.

The service terminates TLS itself only when both `TLS_CERT` and `TLS_PRIVATE_KEY` are set, holding
PEM content. Reach for that when you want the private topology and an encrypted hop anyway, or when
the certificate must not sit with the proxy. Fly then has to pass TCP through untouched, which is
the commented service block in `fly.toml`.

That path needs a DNS name you control, because a Flycast name cannot be certified. Let's Encrypt
issues for it over DNS-01, which proves control through a DNS record rather than an inbound
connection, so a private app can hold a publicly trusted certificate and the runner verifies it
with no custom CA:

```bash
uv run --with certbot --with certbot-dns-route53 certbot certonly \
  --non-interactive --agree-tos --email you@example.com \
  --dns-route53 --preferred-challenges dns-01 \
  -d discharge.example.com
fly secrets set \
  TLS_CERT="$(cat /etc/letsencrypt/live/discharge.example.com/fullchain.pem)" \
  TLS_PRIVATE_KEY="$(cat /etc/letsencrypt/live/discharge.example.com/privkey.pem)"
```

Swap the `--dns-*` plugin for your provider. Renew on a schedule and set the secrets again, which
restarts the machine with the new certificate. A weekly job that reads the live certificate with
`openssl s_client`, renews within 30 days of expiry, and calls `fly secrets set` covers it.

Both halves are required together. The service refuses to start with only one rather than falling
back to plain HTTP, which would silently downgrade a caller that expects `https`, and it refuses an
`http://` location while serving TLS.

Outside Fly, mount the policy at `POLICY_FILE` (default `/etc/fly-oidc-discharge/policy.yaml`) or
pass it inline in `POLICY_YAML`.

```bash
docker run -p 8080:8080 \
  -e OIDC_DISCHARGE_LOCATION=https://discharge.example.com \
  -e SHARED_SECRET_PROD="$(cat prod.secret)" \
  -v "$PWD/policy.yaml:/etc/fly-oidc-discharge/policy.yaml:ro" \
  ghcr.io/gz/fly-oidc-discharge:v1
```

Images are built for `linux/amd64` and `linux/arm64` and tagged `vX`, `vX.Y`, `vX.Y.Z`, `main`, and
`sha-<commit>`. A public repository also gets a signed provenance attestation, which GitHub does not
offer for user-owned private ones:

```bash
gh attestation verify oci://ghcr.io/gz/fly-oidc-discharge:v1 --repo gz/fly-oidc-discharge
```

## Wire up a repository

1. Generate one secret per credential and give them to the service.

   ```bash
   for env in PROD STAGING; do openssl rand -base64 32 > "$env.secret"; done
   fly secrets set \
     SHARED_SECRET_PROD="$(cat PROD.secret)" \
     SHARED_SECRET_STAGING="$(cat STAGING.secret)"
   ```

2. Mint one caveated token per environment. Use the same location string everywhere, no trailing
   slash, and the secret belonging to that environment.

   ```bash
   fly tokens create deploy --app my-app-prod --expiry 9999h > prod.tok
   fly tokens 3p add --location http://my-discharge.flycast \
       --secret-file PROD.secret --access-token "$(cat prod.tok)"
   ```

   Best practice: Store the printed `FlyV1 fm2_...` token as a GitHub **environment** secret of the matching
   environment, so only jobs targeting that environment can read it.
   Delete `*.tok`: the caveated token should be the only copy.
   Delete `*.secret`: The secret content is only needed where the service runs after tokens are minted.
   If you intent to re-mint new tokens with the same secret, store it in a safe place instead.

3. Add the credential and its rules to `policy.yaml`, then `fly deploy`.

4. Use it in a job.

   ```yaml
   jobs:
     deploy:
       environment: prod
       permissions:
         id-token: write
       steps:
         - uses: superfly/flyctl-actions/setup-flyctl@master
         - id: fly
           uses: gz/fly-oidc-discharge@v1
           with:
             caveated-token: ${{ secrets.FLY_CAVEATED_TOKEN }}
             location: http://my-discharge.flycast
         - run: flyctl deploy
           env:
             FLY_API_TOKEN: ${{ steps.fly.outputs.token }}
   ```

   The refs above are mutable for readability. Pin every action to a full commit
   SHA in a job that holds deployment authority, because a moved ref runs new code
   next to your Fly token.

## Admission Policy

A credential is one Fly token, identified by the shared secret its caveat was sealed with.
The shared secrets are attached to the rules defined in the policy file that need to match in the JWT.
Two credentials sharing a secret is rejected at startup, because a ticket could not select between them.

```yaml
default_discharge_ttl: 15m

credentials:
  - name: prod
    shared_secret_env: SHARED_SECRET_PROD
    discharge_ttl: 10m
    rules:
      - name: prod deploy
        claims:
          repository: acme/web
          job_workflow_ref: acme/web/.github/workflows/deploy.yml@refs/heads/main
          environment: prod

  - name: staging
    shared_secret_env: SHARED_SECRET_STAGING
    rules:
      - name: staging deploy
        claims:
          repository: acme/web
          job_workflow_ref: acme/web/.github/workflows/deploy.yml@refs/heads/main
          environment: staging
```

A job is allowed when every claim of one rule of its credential matches. `*` matches any run of
characters, including `/`. Every rule must pin `repository`, `repository_owner`, `sub`, or
`job_workflow_ref`. Claim names follow the
[GitHub OIDC token](https://docs.github.com/en/actions/security-for-github-actions/security-hardening-your-deployments/about-security-hardening-with-openid-connect#understanding-the-oidc-token);
booleans such as `ref_protected` match as `"true"` or `"false"`.

Rules constrain their own credential and nothing else. A permissive rule stays permissive for that
credential: a rule of `repository` plus `ref` admits any job on that ref, including one that
declares `environment: prod`. Add the `environment` claim to every credential you want restricted to
one environment.

## Configuration

| Variable | Default | Meaning |
|---|---|---|
| `OIDC_DISCHARGE_LOCATION` | required | URL given to `fly tokens 3p add --location` |
| `POLICY_FILE` | `/etc/fly-oidc-discharge/policy.yaml` | policy location |
| `POLICY_YAML` | | policy as inline YAML; takes precedence over `POLICY_FILE` |
| `OIDC_ISSUER` | `https://token.actions.githubusercontent.com` | OIDC issuer to trust |
| `OIDC_AUDIENCE` | `OIDC_DISCHARGE_LOCATION` | `aud` the job must request |
| `LISTEN_ADDR` | `:8080` | listen address |
| `TLS_CERT` | | certificate chain in PEM, or `TLS_CERT_FILE` naming a file |
| `TLS_PRIVATE_KEY` | | private key in PEM, or `TLS_PRIVATE_KEY_FILE` naming a file |

Each credential names its own secret variable in the policy, through `shared_secret_env` or
`shared_secret_file`. Discharge lifetime comes from `default_discharge_ttl` and the optional
per-credential `discharge_ttl`.

Another OIDC issuer works as long as its tokens carry claims a rule can pin. Point `OIDC_ISSUER` at
it, and remember that `repository` and `job_workflow_ref` are GitHub-specific claim names.

The issuer's discovery document is resolved on the first token rather than at startup, so a machine
woken by Fly Proxy serves without a network round trip on its startup path and cannot crash-loop
because the issuer was briefly unreachable. Startup attempts to warm it and logs a warning if it
fails, so a wrong `OIDC_ISSUER` shows up as that warning followed by 401s.
