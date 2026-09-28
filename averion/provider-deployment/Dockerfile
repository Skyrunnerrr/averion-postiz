# Optional daemon build of the same file set. The digest that deployments
# reference is the one from scripts/build-oci.mjs, recorded in provenance/build.json.
# Build context: averion/provider-deployment
FROM nginx@sha256:62223d644fa234c3a1cc785ee14242ec47a77364226f1c811d2f669f96dc2ac8
COPY ingress/nginx.provider.conf /etc/nginx/nginx.conf
COPY ingress/nginx.provider.conf /averion/ingress/nginx.provider.conf
COPY ingress/callback.html /averion/www/callback.html
COPY ingress/ingress-matrix.json /averion/ingress/ingress-matrix.json
COPY egress/egress-map.json /averion/egress/egress-map.json
COPY egress/allowlist.txt /averion/egress/allowlist.txt
COPY config/provider.flags.env /averion/config/provider.flags.env
COPY scripts/fail-closed.sh /averion/scripts/fail-closed.sh
COPY scripts/entrypoint.sh /averion/scripts/entrypoint.sh
COPY SECRETS.md /averion/SECRETS.md
RUN chmod 755 /averion/scripts/entrypoint.sh /averion/scripts/fail-closed.sh
ENTRYPOINT ["/averion/scripts/entrypoint.sh"]
