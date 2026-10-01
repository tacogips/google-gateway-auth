import Foundation

extension OAuthCallback {
  /// Validates Google's authorization response before any code or error is trusted.
  public static func validated(queryItems: [URLQueryItem], expectedState: String) throws -> OAuthCallback {
    var values: [String: String] = [:]
    for item in queryItems {
      guard values[item.name] == nil else {
        throw GatewayAuthError("OAuth callback contained duplicate parameters", kind: .callback)
      }
      values[item.name] = item.value ?? ""
    }
    guard !expectedState.isEmpty, values["state"] == expectedState,
      (values["error"] == nil) != (values["code"] == nil) else {
      throw GatewayAuthError("OAuth callback state or code is invalid", kind: .callback)
    }
    if let issuer = values["iss"], issuer != "https://accounts.google.com" {
      throw GatewayAuthError("OAuth callback issuer is invalid", kind: .callback)
    }
    let metadata: Set<String> = ["scope", "iss", "authuser", "prompt", "hd"]
    let required: Set<String> = values["error"] == nil ? ["state", "code"] : ["state", "error"]
    let allowed = required.union(metadata).union(values["error"] == nil ? [] : ["error_description", "error_uri"])
    guard Set(values.keys).isSubset(of: allowed),
      let result = values["code"] ?? values["error"], !result.isEmpty,
      result.utf8.count <= 8_192, result.utf8.allSatisfy({ $0 >= 33 && $0 != 127 }) else {
      throw GatewayAuthError("OAuth callback state or code is invalid", kind: .callback)
    }
    return OAuthCallback(code: values["code"], state: values["state"], error: values["error"])
  }
}
