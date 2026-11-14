import Foundation
import Testing
@testable import GoogleGatewayAuth

private func sharedConfiguration(_ body: ([String: String], URL) throws -> Void) throws {
  let root = FileManager.default.temporaryDirectory.appendingPathComponent(UUID().uuidString)
  defer { try? FileManager.default.removeItem(at: root) }
  try body(["XDG_CONFIG_HOME": root.path], root)
}

@Test(arguments: GatewayAuthProduct.allCases)
func serviceClientIsSharedDefault(product: GatewayAuthProduct) throws {
  try sharedConfiguration { environment, root in
    let shared = root.appendingPathComponent("google-service-gateway/oauth-client.json")
    try privateWrite(Data("shared-client-fixture".utf8), to: shared)
    let prepared = try defaultClientEnvironment(environment, product: product, profile: nil)
    #expect(prepared[product.prefix + "OAUTH_CLIENT_PATH"] == shared.path)
    #expect(prepared[product.prefix + "TOKEN_STORE_PATH"] == nil)
  }
}

@Test(arguments: GatewayAuthProduct.allCases.filter { $0 != .service })
func productAndEnvironmentClientOverridesWin(product: GatewayAuthProduct) throws {
  try sharedConfiguration { environment, root in
    try privateWrite(Data("shared".utf8), to: root.appendingPathComponent("google-service-gateway/oauth-client.json"))
    let specific = root.appendingPathComponent(product.directory + "/oauth-client.json")
    try privateWrite(Data("specific".utf8), to: specific)
    #expect(try defaultClientEnvironment(environment, product: product, profile: nil)[product.prefix + "OAUTH_CLIENT_PATH"] == specific.path)
    for suffix in ["OAUTH_CLIENT_JSON", "OAUTH_CLIENT_PATH"] {
      var external = environment
      external[product.prefix + suffix] = "explicit-fixture"
      #expect(try defaultClientEnvironment(external, product: product, profile: nil) == external)
    }
  }
}

@Test(arguments: GatewayAuthProduct.allCases)
func sharedClientStillRequiresPrivateFile(product: GatewayAuthProduct) throws {
  try sharedConfiguration { environment, root in
    let shared = root.appendingPathComponent("google-service-gateway/oauth-client.json")
    try privateWrite(Data("fixture".utf8), to: shared)
    try FileManager.default.setAttributes([.posixPermissions: 0o644], ofItemAtPath: shared.path)
    #expect(throws: GatewayAuthError.self) {
      try defaultClientEnvironment(environment, product: product, profile: nil)
    }
  }
}

@Test(arguments: GatewayAuthProduct.allCases)
func sharedCallbackConfigurationAndEnvironmentOverride(product: GatewayAuthProduct) throws {
  try sharedConfiguration { environment, root in
    try privateWrite(Data(#"{"OAUTH_LISTEN_PORT":"8765"}"#.utf8),
      to: root.appendingPathComponent("google-service-gateway/oauth-callback.json"))
    #expect(try OAuthCallbackSettings(prefix: product.prefix, environment: environment).listenPort == 8765)
    var external = environment
    external[product.prefix + "OAUTH_LISTEN_PORT"] = "9876"
    #expect(try OAuthCallbackSettings(prefix: product.prefix, environment: external).listenPort == 9876)
    if product != .service {
      var customClient = environment
      customClient[product.prefix + "OAUTH_CLIENT_JSON"] = "explicit-fixture"
      #expect(try OAuthCallbackSettings(prefix: product.prefix, environment: customClient).listenPort == 0)
      customClient[product.prefix + "OAUTH_CLIENT_JSON"] = nil
      customClient[product.prefix + "OAUTH_CLIENT_PATH"] = root.appendingPathComponent("google-service-gateway/oauth-client.json").path
      #expect(try OAuthCallbackSettings(prefix: product.prefix, environment: customClient).listenPort == 8765)
      try privateWrite(Data("specific".utf8), to: root.appendingPathComponent(product.directory + "/oauth-client.json"))
      #expect(try OAuthCallbackSettings(prefix: product.prefix, environment: environment).listenPort == 0)
    }
  }
}

@Test func emptySharedCallbacksKeepNativeReceiverDefaults() throws {
  try sharedConfiguration { environment, root in
    try privateWrite(Data("{}".utf8), to: root.appendingPathComponent("google-service-gateway/oauth-callback.json"))
    for product in GatewayAuthProduct.allCases {
      #expect(!OAuthCallbackSettings.isConfigured(prefix: product.prefix, environment: environment))
    }
  }
}
