import Foundation

/// Imports an already Google-registered client into a gateway's local configuration.
public enum OAuthClientRegistration {
  public static func run(arguments: [String], environment: [String: String]) throws -> String {
    var values: [String: String] = [:]
    var replace = false
    var index = 2
    while index < arguments.count {
      let key = arguments[index]
      if key == "--replace" { replace = true; index += 1; continue }
      guard ["--file", "--product", "--redirect-uri", "--listen-host", "--listen-port"].contains(key),
        values[key] == nil, index + 1 < arguments.count else { throw GatewayAuthError("Invalid clients register option") }
      values[key] = arguments[index + 1]
      index += 2
    }
    guard let path = values["--file"], path.hasPrefix("/"),
      let product = GatewayAuthProduct(rawValue: values["--product"] ?? "service") else {
      throw GatewayAuthError("clients register requires an absolute --file and a known --product")
    }
    let data = try privateRead(URL(fileURLWithPath: path))
    let client = try parsedClient(data)
    var callback: [String: String] = [:]
    callback["OAUTH_REDIRECT_URI"] = values["--redirect-uri"]
    callback["OAUTH_LISTEN_HOST"] = values["--listen-host"]
    callback["OAUTH_LISTEN_PORT"] = values["--listen-port"]
    if client.kind == "web", callback["OAUTH_REDIRECT_URI"] == nil {
      callback["OAUTH_REDIRECT_URI"] = client.redirects.first
    }
    let settings = try OAuthCallbackSettings(prefix: "", environment: callback)
    if let redirect = settings.redirectURI {
      try OAuthCallbackSettings.validateClientRedirect(kind: client.kind, registered: client.redirects, redirect: redirect.absoluteString)
    }
    let directory = try configDirectory(environment: environment, product: product)
    let target = directory.appendingPathComponent("oauth-client.json")
    let callbackTarget = directory.appendingPathComponent("oauth-callback.json")
    guard replace || !FileManager.default.fileExists(atPath: target.path) else {
      throw GatewayAuthError("Default OAuth client already exists; use --replace to replace local configuration")
    }
    try privateWrite(data, to: target)
    try privateWrite(JSONEncoder().encode(callback), to: callbackTarget)
    let metadata: [String: Any] = ["ok": true, "registrationScope": "LOCAL_EXISTING_CLIENT", "product": product.rawValue,
      "clientKind": client.kind, "clientPath": target.path, "callbackConfigurationPath": callbackTarget.path]
    let output = try JSONSerialization.data(withJSONObject: metadata, options: [.sortedKeys])
    return String(data: output, encoding: .utf8) ?? "{}"
  }

  static func parsedClient(_ data: Data) throws -> (kind: String, redirects: [String]) {
    guard let root = try JSONSerialization.jsonObject(with: data) as? [String: Any],
      (root["installed"] == nil) != (root["web"] == nil) else { throw GatewayAuthError("Client JSON must contain exactly one installed or web client") }
    let kind = root["web"] == nil ? "installed" : "web"
    guard let client = root[kind] as? [String: Any],
      let identifier = client["client_id"] as? String, !identifier.isEmpty,
      ["https://accounts.google.com/o/oauth2/auth", "https://accounts.google.com/o/oauth2/v2/auth"].contains(client["auth_uri"] as? String ?? ""),
      client["token_uri"] as? String == "https://oauth2.googleapis.com/token",
      let redirects = client["redirect_uris"] as? [String], !redirects.isEmpty else {
      throw GatewayAuthError("OAuth client JSON has invalid Google endpoints or required fields")
    }
    for redirect in redirects { _ = try OAuthCallbackSettings.validatedRedirect(redirect) }
    if kind == "web", (client["client_secret"] as? String ?? "").isEmpty {
      throw GatewayAuthError("Web OAuth client requires a client secret")
    }
    return (kind, redirects)
  }
}

func configDirectory(environment: [String: String], product: GatewayAuthProduct) throws -> URL {
  let config = try environment["XDG_CONFIG_HOME"] ?? homeDirectory(environment) + "/.config"
  guard config.hasPrefix("/") else { throw GatewayAuthError("XDG_CONFIG_HOME must be an absolute path") }
  return URL(fileURLWithPath: config).appendingPathComponent(product.directory)
}
