import Foundation
import Testing
@testable import GoogleGatewayAuth

@Test func sharedCallbackValidationAcceptsGoogleMetadata() throws {
  let query = try #require(URLComponents(string:
    "http://callback/?state=expected&code=fixture&iss=https%3A%2F%2Faccounts.google.com&scope=scope-a&authuser=0&prompt=consent&hd=example.com")?.queryItems)
  let callback = try OAuthCallback.validated(queryItems: query, expectedState: "expected")
  #expect(callback.code == "fixture")
  #expect(callback.error == nil)
}

@Test(arguments: [
  "state=wrong&code=fixture", "state=expected&code=fixture&state=duplicate",
  "state=expected&code=fixture&scope=a&scope=b", "state=expected&code=fixture&iss=https://invalid.example",
  "state=expected&code=fixture&error=denied", "state=expected&code=", "state=expected&code=fixture&unexpected=value",
  "state=expected&code=%20invalid", "state=expected&error=", "state=expected&code=fixture&iss"
])
func sharedCallbackValidationRejectsInvalidResponse(_ query: String) throws {
  let items = try #require(URLComponents(string: "http://callback/?" + query)?.queryItems)
  #expect(throws: GatewayAuthError.self) {
    _ = try OAuthCallback.validated(queryItems: items, expectedState: "expected")
  }
}

@Test func sharedCallbackValidationAcceptsProviderErrorAndBoundsCode() throws {
  let error = try OAuthCallback.validated(queryItems: [
    URLQueryItem(name: "state", value: "expected"), URLQueryItem(name: "error", value: "access_denied"),
    URLQueryItem(name: "error_description", value: "User denied access")
  ], expectedState: "expected")
  #expect(error.error == "access_denied")
  #expect(error.code == nil)
  #expect(throws: GatewayAuthError.self) {
    _ = try OAuthCallback.validated(queryItems: [URLQueryItem(name: "state", value: "expected"),
      URLQueryItem(name: "code", value: String(repeating: "a", count: 8_193))], expectedState: "expected")
  }
}
