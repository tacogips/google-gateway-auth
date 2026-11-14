import Foundation

/// Local logout never revokes a Google grant or mutates credentials supplied by callers.
public enum GatewayLogout {
  public struct Result: Codable, Sendable {
    public let state: String
    public let localTokenDeleted: Bool
    public let externalCredentialPreserved: Bool
  }

  public static func perform(externalCredential: Bool, removeToken: () throws -> Bool) throws -> Result {
    if externalCredential { return result(deleted: false, external: true) }
    return try result(deleted: removeToken(), external: false)
  }

  public static func performAsync(externalCredential: Bool, removeToken: () async throws -> Bool) async throws -> Result {
    if externalCredential { return result(deleted: false, external: true) }
    return try await result(deleted: removeToken(), external: false)
  }

  private static func result(deleted: Bool, external: Bool) -> Result {
    Result(state: external ? "EXTERNAL_CREDENTIAL_PRESERVED" : "LOGGED_OUT",
           localTokenDeleted: deleted, externalCredentialPreserved: external)
  }
}
