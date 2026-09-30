import Foundation
import Testing
@testable import GoogleGatewayAuth

@Test func callbackSettingsSeparatePublicRedirectAndLocalListener() throws {
  let settings = try OAuthCallbackSettings(prefix: "TEST_", environment: [
    "TEST_OAUTH_REDIRECT_URI": "https://gateway.example.com/google/callback",
    "TEST_OAUTH_LISTEN_HOST": "0.0.0.0", "TEST_OAUTH_LISTEN_PORT": "43210"
  ])
  #expect(settings.redirectURI?.absoluteString == "https://gateway.example.com/google/callback")
  #expect(settings.listenHost == "0.0.0.0")
  #expect(settings.listenPort == 43210)
  #expect(settings.callbackPath == "/google/callback")
  try OAuthCallbackSettings.validateClientRedirect(kind: "web", registered: ["https://gateway.example.com/google/callback"],
    redirect: "https://gateway.example.com/google/callback")
  #expect(throws: GatewayAuthError.self) {
    try OAuthCallbackSettings.validateClientRedirect(kind: "web", registered: ["https://gateway.example.com/google/callback"],
      redirect: "https://gateway.example.com/other")
  }
  #expect(throws: GatewayAuthError.self) {
    try OAuthCallbackSettings.validateClientRedirect(kind: "installed", registered: [], redirect: "https://gateway.example.com/google/callback")
  }
}

@Test(arguments: ["http://example.com/cb", "https://user:secret@example.com/cb", "https://example.com/cb?x=1",
  "https://example.com/cb#frag", "http://127.0.0.1:0/cb", "http://127.0.0.1:65536/cb"])
func callbackSettingsRejectInvalidRedirects(_ value: String) {
  #expect(throws: GatewayAuthError.self) { try OAuthCallbackSettings.validatedRedirect(value) }
}

@Test func callbackListenerReceivesCustomPathAndStopsOnRelease() async throws {
  let port = try await completeCallback()
  let settings = try OAuthCallbackSettings(prefix: "TEST_", environment: ["TEST_OAUTH_LISTEN_PORT": String(port)])
  let replacement = try OAuthCallbackServer(settings: settings)
  #expect(replacement.redirectURI.port == port)
}

private func completeCallback() async throws -> Int {
  let settings = try OAuthCallbackSettings(prefix: "TEST_", defaultPath: "/custom/callback", environment: [:])
  let server = try OAuthCallbackServer(settings: settings)
  let received = Task.detached { try server.wait(expectedState: "fixture-state", timeout: 3) }
  var url = URLComponents(url: server.redirectURI, resolvingAgainstBaseURL: false)
  url?.queryItems = [URLQueryItem(name: "code", value: "fixture-code"), URLQueryItem(name: "state", value: "fixture-state")]
  let requestURL = try #require(url?.url)
  let (_, response) = try await URLSession.shared.data(from: requestURL)
  #expect((response as? HTTPURLResponse)?.statusCode == 200)
  let callback = try await received.value
  #expect(callback.code == "fixture-code")
  return try #require(server.redirectURI.port)
}

@Test func publicHTTPSCallbackUsesSeparateLocalHTTPListener() async throws {
  let settings = try OAuthCallbackSettings(prefix: "TEST_", environment: [
    "TEST_OAUTH_REDIRECT_URI": "https://gateway.example.com/custom/callback", "TEST_OAUTH_LISTEN_PORT": "0"
  ])
  let server = try OAuthCallbackServer(settings: settings)
  #expect(server.redirectURI.absoluteString == "https://gateway.example.com/custom/callback")
  #expect(server.listenerURI.scheme == "http")
  let received = Task.detached { try server.wait(expectedState: "state", timeout: 3) }
  var url = URLComponents(url: server.listenerURI, resolvingAgainstBaseURL: false)
  url?.queryItems = [URLQueryItem(name: "code", value: "fixture"), URLQueryItem(name: "state", value: "state")]
  _ = try await URLSession.shared.data(from: #require(url?.url))
  #expect(try await received.value.code == "fixture")
}

@Test func existingClientRegistrationIsPrivateAndNamespaced() throws {
  let root = FileManager.default.temporaryDirectory.appendingPathComponent(UUID().uuidString)
  defer { try? FileManager.default.removeItem(at: root) }
  try FileManager.default.createDirectory(at: root, withIntermediateDirectories: false, attributes: [.posixPermissions: 0o700])
  let source = root.appendingPathComponent("web.json")
  let fixture = Data(#"{"web":{"client_id":"fixture.apps.googleusercontent.com","client_secret":"fixture","auth_uri":"https://accounts.google.com/o/oauth2/v2/auth","token_uri":"https://oauth2.googleapis.com/token","redirect_uris":["https://gateway.example.com/callback"]}}"#.utf8)
  try privateWrite(fixture, to: source)
  let environment = ["XDG_CONFIG_HOME": root.appendingPathComponent("config").path]
  for product in GatewayAuthProduct.allCases {
    let arguments = ["clients", "register", "--file", source.path, "--product", product.rawValue,
      "--listen-port", "8765"]
    let result = try OAuthClientRegistration.run(arguments: arguments, environment: environment)
    #expect(result.contains("LOCAL_EXISTING_CLIENT"))
    #expect(!result.contains("client_secret"))
    let settings = try OAuthCallbackSettings(prefix: product.prefix, environment: environment)
    #expect(settings.redirectURI?.absoluteString == "https://gateway.example.com/callback")
    #expect(settings.listenPort == 8765)
    #expect(throws: GatewayAuthError.self) { try OAuthClientRegistration.run(arguments: arguments, environment: environment) }
    _ = try OAuthClientRegistration.run(arguments: arguments + ["--replace"], environment: environment)
    var override = environment
    override[product.prefix + "OAUTH_LISTEN_PORT"] = "9876"
    #expect(try OAuthCallbackSettings(prefix: product.prefix, environment: override).listenPort == 9876)
    #expect(try privateRead(configDirectory(environment: environment, product: product).appendingPathComponent("oauth-client.json")) == fixture)
  }
}
