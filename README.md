# google-gateway-auth

Shared Swift CLI authentication integration for tacogips Google gateways.

- `auth login --provider gcloud` delegates consent and credential storage to
  gcloud application-default authentication, using a private product/role/profile
  configuration directory. The Cloud Service roles share one Cloud profile.
- Subsequent commands obtain fresh access tokens without printing credentials.
- Explicit external token, JSON, and file inputs retain precedence.
- Provider-free login delegates to the gateway's native browser flow. A private
  maintainer-installed `~/.config/<product-directory>/oauth-client.json` supplies
  its default Desktop client. A successful native login clears the selected
  gcloud provider; failures preserve it.
- `<PRODUCT_PREFIX>GCLOUD_PATH` accepts an absolute gcloud executable path.
- Marketing supports `--product` selection and product-specific scopes.
- The provider operates only in executable composition roots. SDK users retain
  control over credentials and do not implicitly launch gcloud.

## Important setup requirement

Creating a Google Cloud project and enabling APIs does not register a Desktop
OAuth client. Workspace/Analytics/Marketing login requires an appropriately
registered client, including when gcloud performs the consent flow. Cloud Service
and Document OCR can use gcloud's built-in Cloud client.

Google's documented Desktop-client creation flow uses Google Auth Platform in
Cloud Console. No supported Desktop-client registration API is implemented here.
The former IAP OAuth Admin API was restricted to IAP and was shut down in March
2026. No browser automation or private Console API is used by this package.

## Build

```sh
swift build
swift test
swiftlint lint
```

## Configurable OAuth callbacks

Each product uses its own prefix with the same suffixes:
`OAUTH_REDIRECT_URI`, `OAUTH_LISTEN_HOST`, and `OAUTH_LISTEN_PORT`.
The public callback URI is separate from the local HTTP listener, allowing an
HTTPS reverse proxy to forward to a private listener. The default listener is
127.0.0.1 on an available port; port 0 selects an available port. IPv6 loopback
is supported. Public HTTP redirects are rejected. Web clients require an exact
registered callback URI; Desktop clients use HTTP loopback callbacks.

Service CLI composition roots handle `clients register --file ABSOLUTE_PATH
--product PRODUCT [--redirect-uri URI] [--listen-host ADDRESS] [--listen-port
PORT] [--replace]`. This privately imports an existing Google client and callback
settings for that product. It does not create a client in Google Cloud. Existing
configuration requires `--replace`. Environment values override stored settings.

The callback listener validates path, state and duplicate query parameters, has
bounded request size and a deadline, and closes when the authorization flow ends.
