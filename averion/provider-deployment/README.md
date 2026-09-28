# Averion provider deployment (non-prod)

This directory is the provider edge for Postiz release candidate `c3f00d015c591d7927e338f4641c1b1b379c733d`. It does not add product features, an Averion adapter, or a live Meta integration.

The only published listener is TCP 5000. It is default-deny. The four Meta OAuth redirect paths answer GET and HEAD with a static page that has no form and does not call Postiz. Dashboard writes, public API writes, MCP, org API-key rotation, and autopost are not routed. Ops readiness is `GET /healthz` on port 15021, which is not in the Service.

Postgres, Redis, and Temporal stay on the cluster network. The edge has no egress. App pods, when added later, may egress only to those private services and cluster DNS. Meta hosts that are allowed to be opened later are the exact names in `egress/allowlist.txt`. Nothing else is allowlisted. External egress is closed in the network policy because this artifact does not ship a FQDN proxy. `LIVE_INFRA=SIMULATED`.

Secrets are injected with `secretKeyRef` or a gitignored `secrets/injected.env`. The image refuses to become ready when the encryption key is missing, a stock placeholder is present, or a write gate is open. See `SECRETS.md`.

The image digest is `provenance/build.json`. Deploy that digest. Do not deploy `:latest`, `:main`, or a moving tag. The base is `nginx:1.27.5-alpine` pinned by the vendored manifest under `image/base/`.

Reproduce the gates from the repository root:

```sh
node averion/provider-deployment/scripts/prove.mjs
```

The script rebuilds the ingress matrix from the controllers, builds the image twice, starts the edge config on localhost, and requests the write surfaces. A passing run exits 0.
