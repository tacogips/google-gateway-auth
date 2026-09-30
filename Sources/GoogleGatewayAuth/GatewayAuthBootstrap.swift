import Foundation

public enum GatewayPreparation: Sendable {
  case invoke(GatewayInvocation)
  case handled(String)
}

private struct ProviderBinding: Codable {
  let provider: String
  let scopes: [String]
}

/// CLI-only integration. SDK callers retain their supplied environment and do
/// not start processes or read a user's provider selection implicitly.
public struct GatewayAuthBootstrap: Sendable {
  private let runner: any GcloudCommandRunning

  public init(runner: any GcloudCommandRunning = GcloudProcess()) { self.runner = runner }

  public static func prepareOrExit(product: GatewayAuthProduct, role: String) -> GatewayInvocation {
    do {
      switch try Self().prepare(
        arguments: Array(CommandLine.arguments.dropFirst()),
        environment: ProcessInfo.processInfo.environment, product: product, role: role
      ) {
      case .invoke(let invocation): return invocation
      case .handled(let output):
        FileHandle.standardOutput.write(Data((output + "\n").utf8))
        exit(0)
      }
    } catch {
      let message = (error as? GatewayAuthError)?.description ?? "Gateway authentication configuration failed"
      let body: [String: Any] = ["error": ["code": "AUTH_REQUIRED", "message": message, "exitCode": 4]]
      if let data = try? JSONSerialization.data(withJSONObject: body, options: [.sortedKeys]) {
        FileHandle.standardError.write(data); FileHandle.standardError.write(Data("\n".utf8))
      }
      exit(4)
    }
  }

  public func prepare(
    arguments: [String], environment: [String: String], product: GatewayAuthProduct, role: String
  ) throws -> GatewayPreparation {
    if arguments.contains(where: { $0 == "--provider" || $0.hasPrefix("--provider=") }), arguments.contains("--help") || arguments.contains("-h") {
      return .handled("Usage: auth login --provider gcloud [--credential ID | --profile ID] [--account EMAIL] [--scope URI ...] [--no-open] [--timeout SECONDS]")
    }
    if arguments.isEmpty || arguments == ["auth"] || arguments == ["oauth"]
        || arguments.contains("--help") || arguments.contains("-h") || arguments.contains("--version") {
      return .invoke(.init(arguments: arguments, environment: environment))
    }
    let options = try ProviderOptions(arguments: arguments)
    let auth = arguments.count >= 2 && ["auth", "oauth"].contains(arguments[0])
    if let provider = options.provider {
      guard auth, arguments[1] == "login", provider == "gcloud" else {
        throw GatewayAuthError("--provider gcloud is supported on auth login only")
      }
    }
    let profile = options.profile ?? product.defaultProfile(role: role, serviceProduct: options.serviceProduct)
    try validateComponent(profile)
    try validateComponent(role)
    let directory = try providerDirectory(environment: environment, product: product, role: role, profile: profile)
    let bindingURL = directory.appendingPathComponent("provider.json")
    var prepared = try defaultClientEnvironment(environment, product: product, profile: options.profile)
    if let path = prepared[product.prefix + "GCLOUD_PATH"] { prepared["GOOGLE_GATEWAY_GCLOUD_PATH"] = path }
    if options.provider == "gcloud" {
      try createPrivateDirectory(directory)
      let scopes = options.scopes.isEmpty ? try product.scopes(role: role, serviceProduct: options.serviceProduct) : options.scopes
      guard scopes.allSatisfy({ $0.hasPrefix("https://") || ["openid", "email", "profile"].contains($0) }) else {
        throw GatewayAuthError("--scope must be an OAuth scope URI or an identity scope")
      }
      var login = ["auth", "application-default", "login"]
      if let account = options.account { login.append(account) }
      login += ["--scopes=" + scopes.joined(separator: ","), "--disable-quota-project"]
      if product.requiresCustomClient {
        let client = try oauthClientData(environment: prepared, product: product, profile: options.profile)
        let clientURL = directory.appendingPathComponent("oauth-client.json")
        try privateWrite(client, to: clientURL)
        login.append("--client-id-file=" + clientURL.path)
      }
      if options.noOpen { login.append("--no-launch-browser") }
      try createPrivateDirectory(directory.appendingPathComponent("gcloud"))
      let gcloudEnvironment = isolatedEnvironment(prepared, directory: directory)
      let result = try runner.run(arguments: login, environment: gcloudEnvironment, interactive: true, timeout: options.timeout)
      guard result.status == 0 else { throw GatewayAuthError("gcloud login failed or was cancelled; provider selection was not changed") }
      // Verify token availability before marking this role/profile as selected.
      _ = try accessToken(environment: gcloudEnvironment)
      try privateWrite(JSONEncoder().encode(ProviderBinding(provider: "gcloud", scopes: scopes)), to: bindingURL)
      return .handled(try metadata(product: product, role: role, profile: profile, state: "READY"))
    }
    // Explicit external sources retain precedence, including invalid/conflicting
    // sources which the native resolver must reject rather than hide.
    let external = hasExternalCredential(environment: environment, product: product, profile: profile)
    guard FileManager.default.fileExists(atPath: bindingURL.path), !external else {
      return .invoke(.init(arguments: arguments, environment: prepared))
    }
    let binding: ProviderBinding
    do {
      try createPrivateDirectory(directory)
      binding = try JSONDecoder().decode(ProviderBinding.self, from: privateRead(bindingURL))
    } catch { throw GatewayAuthError("Stored provider selection is invalid") }
    guard binding.provider == "gcloud" else { throw GatewayAuthError("Stored provider is unsupported") }
    let gcloudEnvironment = isolatedEnvironment(prepared, directory: directory)
    if auth && arguments[1] == "revoke" {
      // Never revoke credentials in the user's normal gcloud configuration.
      let result = try runner.run(arguments: ["auth", "application-default", "revoke", "--quiet"],
                                  environment: gcloudEnvironment, interactive: false, timeout: 30)
      guard result.status == 0 else { throw GatewayAuthError("gcloud credential revocation failed") }
      try FileManager.default.removeItem(at: bindingURL)
      return .handled(try metadata(product: product, role: role, profile: profile, state: "REVOKED"))
    }
    if auth && arguments[1] == "login" {
      // A provider-free login uses the native registered client, not an implicit
      // gcloud browser invocation. The existing binding remains on failure.
      return .invoke(.init(arguments: arguments, environment: prepared, obsoleteBinding: bindingURL))
    }
    let token = try accessToken(environment: gcloudEnvironment)
    if auth && ["status", "refresh"].contains(arguments[1]) {
      return .handled(try metadata(product: product, role: role, profile: profile, state: "READY"))
    }
    let suffix = options.profile.map { "CREDENTIAL_" + normalized($0) + "_" } ?? ""
    prepared[product.prefix + suffix + "ACCESS_TOKEN"] = token
    return .invoke(.init(arguments: arguments, environment: prepared))
  }

  private func accessToken(environment: [String: String]) throws -> String {
    let result = try runner.run(arguments: ["auth", "application-default", "print-access-token"],
                                environment: environment, interactive: false, timeout: 30)
    let token = result.output.trimmingCharacters(in: .whitespacesAndNewlines)
    guard result.status == 0, !token.isEmpty, token.utf8.count <= 8192,
          !token.utf8.contains(where: { $0 < 33 || $0 == 127 }) else {
      throw GatewayAuthError("gcloud could not provide a token; run auth login --provider gcloud again")
    }
    return token
  }

  private func metadata(product: GatewayAuthProduct, role: String, profile: String, state: String) throws -> String {
    let data = try JSONSerialization.data(withJSONObject: ["provider": "gcloud", "product": product.rawValue,
                                                          "role": role, "profile": profile, "state": state], options: [.sortedKeys])
    return String(data: data, encoding: .utf8) ?? "{}"
  }
}

private struct ProviderOptions {
  var provider: String?
  var profile: String?
  var account: String?
  var serviceProduct: String?
  var scopes: [String] = []
  var noOpen = false
  var timeout: TimeInterval = 300

  init(arguments: [String]) throws {
    var index = 0
    while index < arguments.count {
      let argument = arguments[index]
      let fields = argument.split(separator: "=", maxSplits: 1).map(String.init)
      let name = fields[0]
      if ["--provider", "--credential", "--profile", "--oauth-profile", "--account", "--scope", "--timeout", "--product"].contains(name) {
        let value: String
        if fields.count == 2 { value = fields[1] } else {
          index += 1
          guard index < arguments.count, !arguments[index].hasPrefix("--") else { throw GatewayAuthError("\(name) requires a value") }
          value = arguments[index]
        }
        switch name {
        case "--provider":
          guard provider == nil else { throw GatewayAuthError("--provider cannot be repeated") }; provider = value
        case "--credential", "--profile", "--oauth-profile":
          guard profile == nil else { throw GatewayAuthError("Select one credential/profile") }; profile = value
        case "--account":
          guard value.contains("@"), !value.hasPrefix("-"), !value.utf8.contains(where: { $0 < 33 || $0 == 127 }) else {
            throw GatewayAuthError("--account must be an email address")
          }
          account = value
        case "--product": serviceProduct = value
        case "--scope": scopes.append(value)
        case "--timeout":
          guard let number = Double(value), number >= 1, number <= 600 else { throw GatewayAuthError("--timeout must be between 1 and 600 seconds") }
          timeout = number
        default: break
        }
      } else if name == "--no-open" { noOpen = true }
      index += 1
    }
    if provider != nil {
      let allowed = Set(["auth", "oauth", "login", "--provider", "--credential", "--profile", "--account", "--scope", "--timeout", "--no-open", "--product"])
      var position = 0
      while position < arguments.count {
        let name = String(arguments[position].split(separator: "=", maxSplits: 1)[0])
        guard allowed.contains(name) else { throw GatewayAuthError("Unsupported gcloud login option") }
        if name.hasPrefix("--"), name != "--no-open", !arguments[position].contains("=") { position += 1 }
        position += 1
      }
    }
  }
}
