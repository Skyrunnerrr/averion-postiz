# Secret injection

The provider image contains the non-secret profile flags only. It does not contain `TOKEN_ENCRYPTION_KEY`, `JWT_SECRET`, database URLs, Redis URLs, or Meta app secrets.

Inject those at process start from a secret store:

- Kubernetes: `secretKeyRef` on `averion-postiz-provider` in `k8s/deployment.yaml`. There is no Secret manifest in git.
- Compose: `secrets/injected.env`, gitignored, copied from `secrets/injected.env.example`. The example has empty values.
- The edge entrypoint exits before nginx listens when a required value is missing, a stock placeholder is present (`postiz-password`, `changeme`, `sk-proj-`, `sk_live_`), or a write gate is not in the frozen closed position.

`OPENAI_API_KEY` must be unset or empty. `AUTOPOST_ENABLED` must be `false`. `ORG_API_KEY_BROWSER_EXPOSURE` must be `false`. `MCP_WRITE_DISABLED` and `PUBLIC_API_WRITE_DISABLED` must be `true`.

The encryption key is a 32-byte value, either 64 hex characters or standard base64. The entrypoint checks the length and does not print the value.
