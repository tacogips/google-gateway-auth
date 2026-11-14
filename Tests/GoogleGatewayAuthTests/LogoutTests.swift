import Testing
@testable import GoogleGatewayAuth

@Test func localLogoutDeletesOnlyThroughProvidedStore() throws {
  var calls = 0
  let result = try GatewayLogout.perform(externalCredential: false) { calls += 1; return true }
  #expect(calls == 1)
  #expect(result.state == "LOGGED_OUT")
  #expect(result.localTokenDeleted)
  #expect(!result.externalCredentialPreserved)
}

@Test func logoutPreservesExternalJSONAndPaths() throws {
  let result = try GatewayLogout.perform(externalCredential: true) {
    Issue.record("External store must not be modified")
    return true
  }
  #expect(result.state == "EXTERNAL_CREDENTIAL_PRESERVED")
  #expect(!result.localTokenDeleted)
  #expect(result.externalCredentialPreserved)
}

@Test func logoutIsIdempotentAndReportsStoreFailures() throws {
  #expect(try GatewayLogout.perform(externalCredential: false) { false }.state == "LOGGED_OUT")
  #expect(throws: GatewayAuthError.self) {
    try GatewayLogout.perform(externalCredential: false) { throw GatewayAuthError("fixture deletion failure") }
  }
}

@Test func asynchronousLogoutUsesSameOwnershipPolicy() async throws {
  let external = try await GatewayLogout.performAsync(externalCredential: true) {
    Issue.record("External store must not be modified")
    return true
  }
  #expect(external.externalCredentialPreserved)
  let local = try await GatewayLogout.performAsync(externalCredential: false) { true }
  #expect(local.localTokenDeleted)
}
