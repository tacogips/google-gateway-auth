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
