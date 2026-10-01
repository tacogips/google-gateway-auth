import Foundation
#if canImport(Darwin)
import Darwin
#else
import Glibc
#endif

func normalized(_ value: String) -> String {
  value.uppercased().map { $0.isLetter || $0.isNumber ? String($0) : "_" }.joined()
}

func validateComponent(_ value: String) throws {
  guard !value.isEmpty, value.count <= 128, value != ".", value != "..",
        value.utf8.allSatisfy({ (65...90).contains($0) || (97...122).contains($0) || (48...57).contains($0) || [45, 95].contains($0) }) else {
    throw GatewayAuthError("Credential/profile and role must use ASCII letters, digits, hyphens or underscores")
  }
}

func homeDirectory(_ environment: [String: String]) throws -> String {
  let home = environment["HOME"] ?? FileManager.default.homeDirectoryForCurrentUser.path
  guard home.hasPrefix("/") else { throw GatewayAuthError("HOME must be an absolute path") }
  return home
}

func providerDirectory(environment: [String: String], product: GatewayAuthProduct, role: String, profile: String) throws -> URL {
  let state = try environment["XDG_STATE_HOME"] ?? homeDirectory(environment) + "/.local/state"
  guard state.hasPrefix("/") else { throw GatewayAuthError("XDG_STATE_HOME must be an absolute path") }
  return URL(fileURLWithPath: state).appendingPathComponent(product.directory)
    .appendingPathComponent("providers").appendingPathComponent(product == .service ? "cloud" : role).appendingPathComponent(profile)
}

func createPrivateDirectory(_ directory: URL) throws {
  // Create each missing component privately and refuse any existing symlink.
  var cursor = URL(fileURLWithPath: "/")
  for part in directory.pathComponents.dropFirst() {
    cursor.appendPathComponent(part, isDirectory: true)
    var info = stat()
    if lstat(cursor.path, &info) == 0 {
      if info.st_mode & S_IFMT == S_IFLNK, info.st_uid == 0, ["/var", "/tmp"].contains(cursor.path) {
        guard stat(cursor.path, &info) == 0 else { throw GatewayAuthError("System directory is unavailable") }
      }
      guard info.st_mode & S_IFMT == S_IFDIR else { throw GatewayAuthError("Provider directory contains a non-directory or symlink") }
    } else {
      try FileManager.default.createDirectory(at: cursor, withIntermediateDirectories: false, attributes: [.posixPermissions: 0o700])
    }
  }
  var info = stat()
  guard lstat(directory.path, &info) == 0, info.st_uid == getuid(), info.st_mode & 0o077 == 0 else {
    throw GatewayAuthError("Provider directory must be private and owned by the current user")
  }
}

func privateWrite(_ data: Data, to url: URL) throws {
  try createPrivateDirectory(url.deletingLastPathComponent())
  if FileManager.default.fileExists(atPath: url.path) { _ = try privateRead(url) }
  let temporary = url.deletingLastPathComponent().appendingPathComponent(UUID().uuidString)
  guard FileManager.default.createFile(atPath: temporary.path, contents: data, attributes: [.posixPermissions: 0o600]) else {
    throw GatewayAuthError("Could not save provider configuration")
  }
  defer { try? FileManager.default.removeItem(at: temporary) }
  guard rename(temporary.path, url.path) == 0 else { throw GatewayAuthError("Could not save provider configuration") }
}

func privateRead(_ url: URL) throws -> Data {
  let descriptor = open(url.path, O_RDONLY | O_NOFOLLOW | O_NONBLOCK)
  guard descriptor >= 0 else { throw GatewayAuthError("Credential file is unavailable") }
  let handle = FileHandle(fileDescriptor: descriptor, closeOnDealloc: true)
  var info = stat()
  guard fstat(descriptor, &info) == 0, info.st_mode & S_IFMT == S_IFREG,
        info.st_uid == getuid(), info.st_mode & 0o077 == 0 else {
    throw GatewayAuthError("Credential file must be a private regular file owned by the current user")
  }
  let bytes = try handle.read(upToCount: 1_048_577) ?? Data()
  guard bytes.count <= 1_048_576 else { throw GatewayAuthError("Credential file is too large") }
  return bytes
}

func isolatedEnvironment(_ environment: [String: String], directory: URL) -> [String: String] {
  var result = environment
  result["CLOUDSDK_CONFIG"] = directory.appendingPathComponent("gcloud").path
  // An unrelated ADC override must not escape this role/profile's isolated store.
  result.removeValue(forKey: "GOOGLE_APPLICATION_CREDENTIALS")
  result.removeValue(forKey: "CLOUDSDK_AUTH_CREDENTIAL_FILE_OVERRIDE")
  result["CLOUDSDK_CORE_LOG_HTTP"] = "false"
  result["CLOUDSDK_CORE_VERBOSITY"] = "warning"
  return result
}

func hasExternalCredential(environment: [String: String], product: GatewayAuthProduct, profile: String) -> Bool {
  let suffixes = ["ACCESS_TOKEN", "TOKEN_STORE_JSON", "TOKEN_STORE_PATH", "SERVICE_ACCOUNT_JSON", "SERVICE_ACCOUNT_PATH"]
  return environment.keys.contains { key in
    let specific = product.prefix + "CREDENTIAL_" + normalized(profile) + "_"
    let legacy = "GOOGLE_DOCUMENTS_GATEWAY_CREDENTIAL_" + normalized(profile) + "_"
    let documentProduct = [.docs, .sheets, .drive].contains(product)
    return suffixes.contains { suffix in
      key == product.prefix + suffix || key == specific + suffix || documentProduct && key == legacy + suffix
    }
  }
}

func clientPrefix(environment: [String: String], product: GatewayAuthProduct, profile: String?) -> String {
  if let profile {
    let specific = product.prefix + "CREDENTIAL_" + normalized(profile) + "_"
    if environment[specific + "OAUTH_CLIENT_JSON"] != nil || environment[specific + "OAUTH_CLIENT_PATH"] != nil { return specific }
  }
  return product.prefix
}

func defaultClientEnvironment(_ environment: [String: String], product: GatewayAuthProduct, profile: String?) throws -> [String: String] {
  var result = environment
  let prefix = clientPrefix(environment: environment, product: product, profile: profile)
  let existing = environment.keys.contains { key in
    (key.hasPrefix(product.prefix) || key.hasPrefix("GOOGLE_DOCUMENTS_GATEWAY_")) && key.contains("OAUTH_CLIENT")
  }
  guard !existing else { return result }
  if let url = try defaultConfigurationURL(environment: environment, product: product, filename: "oauth-client.json") {
    _ = try privateRead(url)
    result[prefix + "OAUTH_CLIENT_PATH"] = url.path
  }
  return result
}

func oauthClientData(environment: [String: String], product: GatewayAuthProduct, profile: String?) throws -> Data {
  let prefix = clientPrefix(environment: environment, product: product, profile: profile)
  let inline = environment[prefix + "OAUTH_CLIENT_JSON"]
  let path = environment[prefix + "OAUTH_CLIENT_PATH"]
  guard inline == nil || path == nil else { throw GatewayAuthError("Select OAuth client JSON or path") }
  let data: Data
  if let inline { data = Data(inline.utf8) } else if let path {
    data = try privateRead(URL(fileURLWithPath: path))
  } else {
    throw GatewayAuthError("This API requires a registered Desktop OAuth client; configure the product's default oauth-client.json before gcloud login")
  }
  guard data.count <= 1_048_576,
        let object = try? JSONSerialization.jsonObject(with: data) as? [String: Any],
        let installed = object["installed"] as? [String: Any],
        let clientID = installed["client_id"] as? String, !clientID.isEmpty else {
    throw GatewayAuthError("OAuth client JSON must describe a registered Desktop client")
  }
  return data
}
