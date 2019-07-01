
# Traefik Forward Auth

The original [`thomseddon/traefik-forward-auth`](https://github.com/thomseddon/traefik-forward-auth) is a "minimal forward authentication service that provides Google oauth based login and authentication for the [traefik](https://github.com/containous/traefik) reverse proxy/load balancer."

This is a partial rewrite to support generic OIDC Providers that provide [OpenID Provider Issuer Discovery](https://openid.net/specs/openid-connect-discovery-1_0.html) but may not support the `UserInfo` endpoint.

[`noelcatt/traefik-forward-auth`](https://github.com/noelcatt/traefik-forward-auth) and [`funkypenguin/traefik-forward-auth`](https://github.com/funkypenguin/traefik-forward-auth) also made [`thomseddon/traefik-forward-auth`](https://github.com/thomseddon/traefik-forward-auth) apply to generic OIDC, but they are now based on an older version which does not support rules and also require the UserInfo endpoint to be supported.

## Differences to the original

The instructions for [`thomseddon/traefik-forward-auth`](https://github.com/thomseddon/traefik-forward-auth) are useful, keeping in mind that this version:

- Does not support legacy configuration (`cookie-domains`, `cookie-secret`, `cookie-secure`, `prompt`).
- Does not support Google-specific configuration (`providers`, `providers.google.client-id`, `providers.google.client-secret`, `providers.google.prompt`).
- Does support `provider-uri`, `client-id`, `client-secret` configuration.
- Uses an OIDC Discovery endpoint to find authorization and token endpoints.
- Does not require the OIDC Provider to support the optional UserInfo endpoint.
- Returns 401 rather than redirect to OIDC Login if an unauthenticated request is not for HTML (e.g. AJAX calls, images).
