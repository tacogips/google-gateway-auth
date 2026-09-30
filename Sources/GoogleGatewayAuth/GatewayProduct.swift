import Foundation

public enum GatewayAuthProduct: String, CaseIterable, Sendable {
  case calendar, gmail, docs, sheets, drive, analytics, marketing, ocr, service

  public var prefix: String {
    switch self {
    case .gmail: "GMAIL_GATEWAY_"
    case .ocr: "GOOGLE_DOCUMENT_OCR_GATEWAY_"
    default: "GOOGLE_\(rawValue.uppercased())_GATEWAY_"
    }
  }

  public var directory: String {
    switch self {
    case .gmail: "gmail-gateway"
    case .ocr: "google-document-ocr-gateway"
    default: "google-\(rawValue)-gateway"
    }
  }

  public var requiresCustomClient: Bool { self != .service && self != .ocr }

  public func defaultProfile(role: String, serviceProduct: String? = nil) -> String {
    switch self {
    case .gmail: "gmail-personal"
    case .calendar, .ocr, .service: "google-personal"
    case .docs, .sheets, .drive: rawValue + "-" + role
    case .analytics: "default-env"
    case .marketing: (serviceProduct ?? "google-ads") + "-" + role
    }
  }

  public func scopes(role: String) -> [String] {
    let read = role == "reader"
    let names: [String]
    switch self {
    case .calendar: names = read ? ["calendar.readonly"] : ["calendar.readonly", "calendar.events"]
    case .gmail:
      switch role {
      case "reader": names = ["gmail.readonly"]
      case "threads": names = ["gmail.readonly", "gmail.modify"]
      case "message-box": return ["https://mail.google.com/"]
      default: names = ["gmail.readonly", "gmail.send", "gmail.compose"]
      }
    case .docs: names = read ? ["documents.readonly"] : ["documents"]
    case .sheets: names = read ? ["spreadsheets.readonly"] : ["spreadsheets"]
    case .drive: names = read ? ["drive.readonly"] : ["drive"]
    case .analytics:
      if read { names = ["analytics.readonly", "tagmanager.readonly"] } else if role == "admin" {
        names = ["analytics", "analytics.edit", "analytics.readonly", "analytics.manage.users",
                 "analytics.manage.users.readonly", "tagmanager.readonly", "tagmanager.edit.containers",
                 "tagmanager.edit.containerversions", "tagmanager.publish", "tagmanager.delete.containers",
                 "tagmanager.manage.accounts", "tagmanager.manage.users"]
      } else {
        names = ["analytics", "analytics.edit", "tagmanager.edit.containers",
                 "tagmanager.edit.containerversions", "tagmanager.publish"]
      }
    case .marketing: names = ["adwords"]
    case .ocr, .service: names = ["cloud-platform"]
    }
    return names.map { "https://www.googleapis.com/auth/" + $0 }
  }

  public func scopes(role: String, serviceProduct: String?) throws -> [String] {
    guard let serviceProduct else { return scopes(role: role) }
    guard self == .marketing else { throw GatewayAuthError("--product selection is supported by Marketing gcloud login") }
    let names: [String]
    switch serviceProduct {
    case "google-ads": names = ["adwords"]
    case "adsense":
      guard role == "reader" else { throw GatewayAuthError("AdSense supports reader authorization only") }
      names = ["adsense.readonly"]
    case "admob":
      guard ["reader", "writer"].contains(role) else { throw GatewayAuthError("AdMob supports reader/writer authorization only") }
      names = role == "writer" ? ["admob.monetization"] : ["admob.readonly", "admob.report"]
    case "analytics-data":
      guard role == "reader" else { throw GatewayAuthError("Analytics Data supports reader authorization only") }
      names = ["analytics.readonly"]
    case "search-console":
      guard role == "reader" else { throw GatewayAuthError("Search Console supports reader authorization only") }
      names = ["webmasters.readonly"]
    default: throw GatewayAuthError("Unsupported Marketing product")
    }
    return names.map { "https://www.googleapis.com/auth/" + $0 }
  }

}

public struct GatewayAuthError: Error, CustomStringConvertible, Sendable {
  public let description: String
  public init(_ description: String) { self.description = description }
}

public struct GatewayInvocation: Sendable {
  public let arguments: [String]
  public let environment: [String: String]
  let obsoleteBinding: URL?

  init(arguments: [String], environment: [String: String], obsoleteBinding: URL? = nil) {
    self.arguments = arguments; self.environment = environment; self.obsoleteBinding = obsoleteBinding
  }

  /// Switches away from a selected gcloud provider only after native login has
  /// completed successfully. A failed or cancelled native login preserves it.
  public func complete(exitCode: Int32) -> Int32 {
    guard exitCode == 0, let obsoleteBinding else { return exitCode }
    do {
      _ = try privateRead(obsoleteBinding)
      try FileManager.default.removeItem(at: obsoleteBinding)
      return exitCode
    } catch {
      FileHandle.standardError.write(Data("Could not clear previous auth provider selection\n".utf8))
      return 4
    }
  }
}
