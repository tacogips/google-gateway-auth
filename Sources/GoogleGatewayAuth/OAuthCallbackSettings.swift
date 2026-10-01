import Foundation

/// The public redirect and the local HTTP listener are separate for reverse proxies.
public struct OAuthCallbackSettings: Sendable {
  public let redirectURI: URL?
  public let listenHost: String
  public let listenPort: UInt16
  public let callbackPath: String

  public static func isConfigured(prefix: String, environment: [String: String] = ProcessInfo.processInfo.environment) -> Bool {
    ["OAUTH_REDIRECT_URI", "OAUTH_LISTEN_HOST", "OAUTH_LISTEN_PORT"].contains { environment[prefix + $0] != nil }
      || configurationURL(prefix: prefix, environment: environment).map { FileManager.default.fileExists(atPath: $0.path) } == true
  }

  public init(prefix: String, defaultPath: String = "/oauth/callback", requestedURI: String? = nil,
              environment: [String: String] = ProcessInfo.processInfo.environment) throws {
    var environment = environment
    if let url = Self.configurationURL(prefix: prefix, environment: environment), FileManager.default.fileExists(atPath: url.path) {
      let stored = try JSONDecoder().decode([String: String].self, from: privateRead(url))
      for (key, value) in stored where environment[prefix + key] == nil { environment[prefix + key] = value }
    }
    let value = requestedURI ?? environment[prefix + "OAUTH_REDIRECT_URI"]
    let redirect = try value.map(Self.validatedRedirect)
    let host = environment[prefix + "OAUTH_LISTEN_HOST"] ?? "127.0.0.1"
    guard ["localhost", "::1"].contains(host) || Self.isIPv4(host) else {
      throw GatewayAuthError("OAUTH_LISTEN_HOST must be localhost or a literal IPv4/IPv6 loopback address")
    }
    let port: UInt16
    if let input = environment[prefix + "OAUTH_LISTEN_PORT"] {
      guard let parsed = UInt16(input) else { throw GatewayAuthError("OAUTH_LISTEN_PORT must be between 0 and 65535") }
      port = parsed
    } else if let redirect, redirect.scheme == "http", let requestedPort = redirect.port {
      port = UInt16(requestedPort)
    } else { port = 0 }
    redirectURI = redirect
    listenHost = host == "localhost" ? "127.0.0.1" : host
    listenPort = port
    callbackPath = redirect.map { $0.path.isEmpty ? "/" : $0.path } ?? defaultPath
  }

  public static func validatedRedirect(_ value: String) throws -> URL {
    guard value.utf8.count <= 2048, !value.contains("%"),
      let components = URLComponents(string: value), let host = components.host,
      !host.isEmpty, components.user == nil, components.password == nil,
      components.query == nil, components.fragment == nil,
      components.port.map({ (1...65535).contains($0) }) ?? true,
      components.scheme == "https" || components.scheme == "http" && ["127.0.0.1", "localhost", "::1", "[::1]"].contains(host),
      components.path.utf8.allSatisfy({ $0 >= 33 && $0 <= 126 }),
      let url = components.url else {
      throw GatewayAuthError("OAuth redirect must be HTTPS or HTTP loopback, without user info, query or fragment")
    }
    return url
  }

  public static func validateClientRedirect(kind: String, registered: [String], redirect: String) throws {
    let url = try validatedRedirect(redirect)
    if kind == "web" {
      guard registered.contains(redirect) else { throw GatewayAuthError("Web OAuth redirect must exactly match a registered URI") }
    } else {
      guard kind == "installed", url.scheme == "http" else {
        throw GatewayAuthError("Desktop clients require an HTTP loopback callback; public HTTPS callbacks require a Web client")
      }
    }
  }

  private static func isIPv4(_ value: String) -> Bool {
    let parts = value.split(separator: ".", omittingEmptySubsequences: false)
    return parts.count == 4 && parts.allSatisfy { part in
      !part.isEmpty && part.utf8.allSatisfy({ (48...57).contains($0) }) && UInt8(part) != nil
    }
  }

  private static func configurationURL(prefix: String, environment: [String: String]) -> URL? {
    guard let product = GatewayAuthProduct.allCases.first(where: { $0.prefix == prefix }),
      let url = try? defaultConfigurationURL(environment: environment, product: product, filename: "oauth-callback.json") else { return nil }
    return url
  }
}
