import Foundation

public struct GcloudResult: Sendable {
  public let status: Int32
  public let output: String
  public init(status: Int32, output: String = "") { self.status = status; self.output = output }
}

public protocol GcloudCommandRunning: Sendable {
  func run(arguments: [String], environment: [String: String], interactive: Bool, timeout: TimeInterval) throws -> GcloudResult
}

/// Runs argument arrays directly, never through a shell. Captured token output
/// is kept off stdout/stderr and subprocess failures never include that output.
public struct GcloudProcess: GcloudCommandRunning {
  public init() {}

  public func run(
    arguments: [String], environment: [String: String], interactive: Bool, timeout: TimeInterval
  ) throws -> GcloudResult {
    let process = Process()
    let configured = environment["GOOGLE_GATEWAY_GCLOUD_PATH"]
    if let configured {
      guard configured.hasPrefix("/"), FileManager.default.isExecutableFile(atPath: configured) else {
        throw GatewayAuthError("GOOGLE_GATEWAY_GCLOUD_PATH must name an executable absolute path")
      }
      process.executableURL = URL(fileURLWithPath: configured)
      process.arguments = arguments
    } else {
      process.executableURL = URL(fileURLWithPath: "/usr/bin/env")
      process.arguments = ["gcloud"] + arguments
    }
    process.environment = environment
    let scratch = FileManager.default.temporaryDirectory.appendingPathComponent(UUID().uuidString)
    guard FileManager.default.createFile(atPath: scratch.path, contents: nil, attributes: [.posixPermissions: 0o600]) else {
      throw GatewayAuthError("Could not create private gcloud output buffer")
    }
    defer { try? FileManager.default.removeItem(at: scratch) }
    let buffer = try FileHandle(forUpdating: scratch)
    defer { try? buffer.close() }
    process.standardOutput = interactive ? FileHandle.standardError : buffer
    process.standardError = interactive ? FileHandle.standardError : FileHandle.nullDevice
    process.standardInput = interactive ? FileHandle.standardInput : FileHandle.nullDevice
    do { try process.run() } catch { throw GatewayAuthError("Could not start gcloud; install it or set GOOGLE_GATEWAY_GCLOUD_PATH") }
    let deadline = Date().addingTimeInterval(timeout)
    while process.isRunning && Date() < deadline { Thread.sleep(forTimeInterval: 0.05) }
    if process.isRunning {
      process.terminate()
      let stopDeadline = Date().addingTimeInterval(2)
      while process.isRunning && Date() < stopDeadline { Thread.sleep(forTimeInterval: 0.05) }
      if process.isRunning { kill(process.processIdentifier, SIGKILL) }
      process.waitUntilExit()
      throw GatewayAuthError("gcloud authentication timed out")
    }
    process.waitUntilExit()
    try buffer.seek(toOffset: 0)
    let data = try buffer.read(upToCount: 8193) ?? Data()
    guard data.count <= 8192 else { throw GatewayAuthError("gcloud returned oversized output") }
    return GcloudResult(status: process.terminationStatus, output: String(data: data, encoding: .utf8) ?? "")
  }
}
