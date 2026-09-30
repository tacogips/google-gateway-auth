import Foundation
import Testing
@testable import GoogleGatewayAuth

private final class RecordingGcloud: GcloudCommandRunning, @unchecked Sendable {
  private let lock = NSLock()
  struct Request {
    let arguments: [String]
    let environment: [String: String]
    let interactive: Bool
  }
  private var requests: [Request] = []
  var status: Int32 = 0
  var token = "test-opaque-token"
  func run(arguments: [String], environment: [String: String], interactive: Bool, timeout: TimeInterval) throws -> GcloudResult {
    lock.lock(); defer { lock.unlock() }
    requests.append(.init(arguments: arguments, environment: environment, interactive: interactive))
    return .init(status: status, output: interactive ? "" : token)
  }
  var calls: [Request] {
    lock.lock(); defer { lock.unlock() }; return requests
  }
}

private func withEnvironment(_ operation: ([String: String]) throws -> Void) throws {
  let root = FileManager.default.temporaryDirectory.appendingPathComponent(UUID().uuidString)
  defer { try? FileManager.default.removeItem(at: root) }
  try operation(["XDG_CONFIG_HOME": root.appendingPathComponent("config").path,
                 "XDG_STATE_HOME": root.appendingPathComponent("state").path])
}

@Test func helpNeverReadsProviderOrStartsGcloud() throws {
  let runner = RecordingGcloud()
  for product in GatewayAuthProduct.allCases {
    let result = try GatewayAuthBootstrap(runner: runner).prepare(arguments: ["auth"], environment: [:], product: product, role: "reader")
    guard case .invoke = result else { Issue.record("Help intercepted"); return }
  }
  #expect(runner.calls.isEmpty)
}

@Test func cloudProviderPersistsSelectionAndRefreshesWithoutTokenDisclosure() throws {
  try withEnvironment { environment in
    let runner = RecordingGcloud(); let auth = GatewayAuthBootstrap(runner: runner)
    let login = try auth.prepare(arguments: ["auth", "login", "--provider", "gcloud"], environment: environment, product: .service, role: "writer")
    guard case .handled(let output) = login else { Issue.record("Login not handled"); return }
    #expect(output.contains("READY")); #expect(!output.contains(runner.token))
    #expect(runner.calls[0].arguments.contains("--disable-quota-project"))
    #expect(runner.calls[0].interactive)
    let invocation = try auth.prepare(arguments: ["projects", "create", "--project-id", "example-project"], environment: environment, product: .service, role: "writer")
    guard case .invoke(let prepared) = invocation else { Issue.record("Operation intercepted"); return }
    #expect(prepared.environment["GOOGLE_SERVICE_GATEWAY_ACCESS_TOKEN"] == runner.token)
    #expect(runner.calls.count == 3)
    #expect(runner.calls.allSatisfy { $0.environment["CLOUDSDK_CONFIG"]?.contains("/providers/cloud/google-personal/gcloud") == true })
    let status = try auth.prepare(arguments: ["auth", "status"], environment: environment, product: .service, role: "writer")
    guard case .handled(let metadata) = status else { Issue.record("Status not handled"); return }
    #expect(!metadata.contains(runner.token))
  }
}

@Test func workspaceRequiresClientBeforeStartingGcloud() throws {
  try withEnvironment { environment in
    let runner = RecordingGcloud()
    #expect(throws: GatewayAuthError.self) {
      try GatewayAuthBootstrap(runner: runner).prepare(arguments: ["auth", "login", "--provider", "gcloud"], environment: environment, product: .gmail, role: "reader")
    }
    #expect(runner.calls.isEmpty)
  }
}

@Test func defaultDesktopClientSupportsBothProviderChoices() throws {
  try withEnvironment { environment in
    let config = try #require(environment["XDG_CONFIG_HOME"])
    let url = URL(fileURLWithPath: config).appendingPathComponent("google-calendar-gateway/oauth-client.json")
    try privateWrite(Data(#"{"installed":{"client_id":"test-client.apps.googleusercontent.com","client_secret":"test-client-secret"}}"#.utf8), to: url)
    let runner = RecordingGcloud(); let auth = GatewayAuthBootstrap(runner: runner)
    let native = try auth.prepare(arguments: ["auth", "login"], environment: environment, product: .calendar, role: "reader")
    guard case .invoke(let prepared) = native else { Issue.record("Native login intercepted"); return }
    #expect(prepared.environment["GOOGLE_CALENDAR_GATEWAY_OAUTH_CLIENT_PATH"] == url.path)
    _ = try auth.prepare(arguments: ["auth", "login", "--provider=gcloud"], environment: environment, product: .calendar, role: "reader")
    #expect(runner.calls[0].arguments.contains { $0.hasPrefix("--client-id-file=") })
    #expect(runner.calls[0].arguments.contains("--scopes=https://www.googleapis.com/auth/calendar.readonly"))
    #expect(!runner.calls[0].arguments.contains { $0.contains("test-client-secret") })
  }
}

@Test func failedLoginDoesNotSelectProvider() throws {
  try withEnvironment { environment in
    let runner = RecordingGcloud(); runner.status = 1
    let auth = GatewayAuthBootstrap(runner: runner)
    #expect(throws: GatewayAuthError.self) {
      try auth.prepare(arguments: ["auth", "login", "--provider", "gcloud"], environment: environment, product: .service, role: "reader")
    }
    let result = try auth.prepare(arguments: ["services", "list"], environment: environment, product: .service, role: "reader")
    guard case .invoke(let prepared) = result else { Issue.record("Failed login persisted"); return }
    #expect(prepared.environment["GOOGLE_SERVICE_GATEWAY_ACCESS_TOKEN"] == nil)
    #expect(runner.calls.count == 1)
  }
}

@Test func explicitExternalCredentialOverridesStoredProvider() throws {
  try withEnvironment { environment in
    let runner = RecordingGcloud(); let auth = GatewayAuthBootstrap(runner: runner)
    _ = try auth.prepare(arguments: ["auth", "login", "--provider", "gcloud"], environment: environment, product: .service, role: "reader")
    var external = environment; external["GOOGLE_SERVICE_GATEWAY_ACCESS_TOKEN"] = "external-input"
    let result = try auth.prepare(arguments: ["services", "list"], environment: external, product: .service, role: "reader")
    guard case .invoke(let prepared) = result else { Issue.record("External source intercepted"); return }
    #expect(prepared.environment["GOOGLE_SERVICE_GATEWAY_ACCESS_TOKEN"] == "external-input")
    #expect(runner.calls.count == 2)
  }
}

@Test func serviceRolesShareCloudProviderButProfilesRemainIsolated() throws {
  try withEnvironment { environment in
    let runner = RecordingGcloud(); let auth = GatewayAuthBootstrap(runner: runner)
    _ = try auth.prepare(arguments: ["auth", "login", "--provider", "gcloud", "--profile", "work"], environment: environment, product: .service, role: "reader")
    for (role, profile) in [("writer", "personal"), ("reader", "personal")] {
      let result = try auth.prepare(arguments: ["services", "list", "--oauth-profile", profile], environment: environment, product: .service, role: role)
      guard case .invoke(let prepared) = result else { Issue.record("Unexpected interception"); return }
      #expect(prepared.environment["GOOGLE_SERVICE_GATEWAY_CREDENTIAL_" + normalized(profile) + "_ACCESS_TOKEN"] == nil)
    }
    #expect(runner.calls.count == 2)
  }
}

@Test func revokeUsesIsolatedGcloudConfiguration() throws {
  try withEnvironment { environment in
    let runner = RecordingGcloud(); let auth = GatewayAuthBootstrap(runner: runner)
    _ = try auth.prepare(arguments: ["auth", "login", "--provider", "gcloud"], environment: environment, product: .ocr, role: "writer")
    let result = try auth.prepare(arguments: ["auth", "revoke", "--credential", "google-personal", "--confirm-credential", "google-personal"], environment: environment, product: .ocr, role: "writer")
    guard case .handled(let output) = result else { Issue.record("Revoke unhandled"); return }
    #expect(output.contains("REVOKED")); #expect(runner.calls.last?.arguments == ["auth", "application-default", "revoke", "--quiet"])
    #expect(runner.calls.last?.environment["CLOUDSDK_CONFIG"]?.contains("google-document-ocr-gateway/providers/writer/google-personal") == true)
  }
}

@Test func unsafeProfileAndUnsupportedProviderNeverLaunchProcess() throws {
  try withEnvironment { environment in
    let runner = RecordingGcloud(); let auth = GatewayAuthBootstrap(runner: runner)
    for args in [["auth", "login", "--provider", "unknown"], ["auth", "login", "--provider", "gcloud", "--profile", "../escape"]] {
      #expect(throws: GatewayAuthError.self) { try auth.prepare(arguments: args, environment: environment, product: .service, role: "reader") }
    }
    #expect(runner.calls.isEmpty)
  }
}

@Test func insecureDefaultClientRejected() throws {
  try withEnvironment { environment in
    let url = URL(fileURLWithPath: try #require(environment["XDG_CONFIG_HOME"])).appendingPathComponent("google-calendar-gateway/oauth-client.json")
    try FileManager.default.createDirectory(at: url.deletingLastPathComponent(), withIntermediateDirectories: true)
    try Data("{}".utf8).write(to: url)
    try FileManager.default.setAttributes([.posixPermissions: 0o644], ofItemAtPath: url.path)
    #expect(throws: GatewayAuthError.self) { try GatewayAuthBootstrap().prepare(arguments: ["auth", "login"], environment: environment, product: .calendar, role: "reader") }
  }
}

@Test func successfulNativeLoginClearsProviderOnlyAfterCompletion() throws {
  try withEnvironment { environment in
    let auth = GatewayAuthBootstrap(runner: RecordingGcloud())
    _ = try auth.prepare(arguments: ["auth", "login", "--provider", "gcloud"], environment: environment, product: .service, role: "writer")
    let result = try auth.prepare(arguments: ["auth", "login"], environment: environment, product: .service, role: "writer")
    guard case .invoke(let invocation) = result else { Issue.record("Native login not invoked"); return }
    let directory = try providerDirectory(environment: environment, product: .service, role: "writer", profile: "google-personal")
    let binding = directory.appendingPathComponent("provider.json")
    #expect(invocation.complete(exitCode: 4) == 4)
    #expect(FileManager.default.fileExists(atPath: binding.path))
    #expect(invocation.complete(exitCode: 0) == 0)
    #expect(!FileManager.default.fileExists(atPath: binding.path))
  }
}

@Test func everyProductUsesItsOwnPrefixClientAndStateNamespace() throws {
  try withEnvironment { environment in
    for product in GatewayAuthProduct.allCases {
      let runner = RecordingGcloud(); let auth = GatewayAuthBootstrap(runner: runner)
      var configured = environment
      configured[product.prefix + "OAUTH_CLIENT_JSON"] = #"{"installed":{"client_id":"test-client.apps.googleusercontent.com"}}"#
      _ = try auth.prepare(arguments: ["auth", "login", "--provider", "gcloud", "--credential", "work"], environment: configured, product: product, role: "writer")
      let result = try auth.prepare(arguments: ["operation", "--credential", "work"], environment: configured, product: product, role: "writer")
      guard case .invoke(let invocation) = result else { Issue.record("Operation not invoked"); return }
      #expect(invocation.environment[product.prefix + "CREDENTIAL_WORK_ACCESS_TOKEN"] == runner.token)
      #expect(runner.calls[0].environment["CLOUDSDK_CONFIG"]?.contains(product.directory + "/providers/" + (product == .service ? "cloud" : "writer") + "/work/gcloud") == true)
    }
  }
}

@Test func processOutputIsCapturedAndSubprocessFailureIsSanitized() throws {
  try withEnvironment { environment in
    let root = URL(fileURLWithPath: try #require(environment["XDG_STATE_HOME"]))
    try createPrivateDirectory(root)
    let script = root.appendingPathComponent("gcloud")
    try privateWrite(Data("#!/bin/sh\nprintf '%s' 'test-captured-token'\n".utf8), to: script)
    try FileManager.default.setAttributes([.posixPermissions: 0o700], ofItemAtPath: script.path)
    var env = environment; env["GOOGLE_GATEWAY_GCLOUD_PATH"] = script.path
    let result = try GcloudProcess().run(arguments: [], environment: env, interactive: false, timeout: 2)
    #expect(result.status == 0); #expect(result.output == "test-captured-token")
    try privateWrite(Data("#!/bin/sh\nsleep 5\n".utf8), to: script)
    try FileManager.default.setAttributes([.posixPermissions: 0o700], ofItemAtPath: script.path)
    #expect(throws: GatewayAuthError.self) { try GcloudProcess().run(arguments: [], environment: env, interactive: false, timeout: 0.1) }
  }
}


@Test func revokePreservesExistingExplicitSelectionAndConfirmationChecks() throws {
  try withEnvironment { environment in
    var configured = environment
    configured["GMAIL_GATEWAY_OAUTH_CLIENT_JSON"] = #"{"installed":{"client_id":"test-client"}}"#
    let runner = RecordingGcloud(); let auth = GatewayAuthBootstrap(runner: runner)
    _ = try auth.prepare(arguments: ["auth", "login", "--provider", "gcloud"], environment: configured, product: .gmail, role: "reader")
    for arguments in [["auth", "revoke"], ["auth", "revoke", "--credential", "gmail-personal", "--confirm-credential", "wrong"]] {
      #expect(throws: GatewayAuthError.self) { try auth.prepare(arguments: arguments, environment: configured, product: .gmail, role: "reader") }
    }
    #expect(runner.calls.count == 2)
  }
}
