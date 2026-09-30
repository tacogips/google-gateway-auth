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
