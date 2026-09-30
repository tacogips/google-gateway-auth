import Foundation
#if canImport(Darwin)
import Darwin
#else
import Glibc
#endif

public struct OAuthCallback: Sendable {
  public let code: String?
  public let state: String?
  public let error: String?
}

public final class OAuthCallbackServer: @unchecked Sendable {
  private let descriptor: Int32
  private let callbackPath: String
  public let redirectURI: URL
  public let listenerURI: URL

  public init(settings: OAuthCallbackSettings) throws {
    #if canImport(Darwin)
      let streamSocketType = SOCK_STREAM
    #else
      let streamSocketType = Int32(SOCK_STREAM.rawValue)
    #endif
    let descriptor = socket(settings.listenHost == "::1" ? AF_INET6 : AF_INET, streamSocketType, 0)
    guard descriptor >= 0 else {
      throw GatewayAuthError("could not create OAuth callback listener")
    }
    var enabled: Int32 = 1
    setsockopt(descriptor, SOL_SOCKET, SO_REUSEADDR, &enabled, socklen_t(MemoryLayout<Int32>.size))
    let bound: Int32
    if settings.listenHost == "::1" {
      var address = sockaddr_in6()
      #if canImport(Darwin)
        address.sin6_len = UInt8(MemoryLayout<sockaddr_in6>.size)
      #endif
      address.sin6_family = sa_family_t(AF_INET6)
      address.sin6_port = settings.listenPort.bigEndian
      _ = inet_pton(AF_INET6, "::1", &address.sin6_addr)
      bound = withUnsafePointer(to: &address) {
        $0.withMemoryRebound(to: sockaddr.self, capacity: 1) { bind(descriptor, $0, socklen_t(MemoryLayout<sockaddr_in6>.size)) }
      }
    } else {
      var address = sockaddr_in()
      #if canImport(Darwin)
        address.sin_len = UInt8(MemoryLayout<sockaddr_in>.size)
      #endif
      address.sin_family = sa_family_t(AF_INET)
      address.sin_port = settings.listenPort.bigEndian
      address.sin_addr = in_addr(s_addr: inet_addr(settings.listenHost))
      bound = withUnsafePointer(to: &address) {
        $0.withMemoryRebound(to: sockaddr.self, capacity: 1) { bind(descriptor, $0, socklen_t(MemoryLayout<sockaddr_in>.size)) }
      }
    }
    guard bound == 0, listen(descriptor, 1) == 0 else {
      close(descriptor)
      throw GatewayAuthError("could not bind OAuth callback listener")
    }
    var local = sockaddr_storage()
    var length = socklen_t(MemoryLayout<sockaddr_storage>.size)
    let named = withUnsafeMutablePointer(to: &local) {
      $0.withMemoryRebound(to: sockaddr.self, capacity: 1) { getsockname(descriptor, $0, &length) }
    }
    let port: UInt16 = withUnsafePointer(to: &local) {
      if settings.listenHost == "::1" {
        return $0.withMemoryRebound(to: sockaddr_in6.self, capacity: 1) { UInt16(bigEndian: $0.pointee.sin6_port) }
      }
      return $0.withMemoryRebound(to: sockaddr_in.self, capacity: 1) { UInt16(bigEndian: $0.pointee.sin_port) }
    }
    let host = settings.listenHost == "::1" ? "[::1]" : "127.0.0.1"
    guard named == 0, let redirect = URL(string: "http://\(host):\(port)\(settings.callbackPath)") else {
      close(descriptor)
      throw GatewayAuthError("could not determine OAuth callback port")
    }
    self.descriptor = descriptor
    listenerURI = redirect
    redirectURI = settings.redirectURI ?? redirect
    callbackPath = settings.callbackPath
  }

  deinit { close(descriptor) }

  public func wait(expectedState: String, timeout: TimeInterval) throws -> OAuthCallback {
    guard timeout.isFinite, timeout > 0, timeout <= 3600 else { throw GatewayAuthError("Invalid OAuth timeout") }
    let descriptor = descriptor
    let callbackPath = callbackPath
    do {
      let deadline = ProcessInfo.processInfo.systemUptime + timeout
      try waitForCallbackData(descriptor: descriptor, deadline: deadline)
      let connection = accept(descriptor, nil, nil)
      guard connection >= 0 else {
        throw GatewayAuthError("OAuth callback could not be accepted")
      }
      defer { close(connection) }
      let request = try readCallbackRequest(connection: connection, deadline: deadline)
      guard let firstLine = request.split(separator: "\r\n", maxSplits: 1).first else {
        throw GatewayAuthError("OAuth callback request was malformed", kind: .callback)
      }
      let parts = firstLine.split(separator: " ")
      guard parts.count == 3, parts[0] == "GET", parts[2] == "HTTP/1.1" || parts[2] == "HTTP/1.0",
        let components = URLComponents(string: "http://127.0.0.1\(parts[1])")
      else {
        throw GatewayAuthError("OAuth callback request was malformed", kind: .callback)
      }
      guard components.path == callbackPath else {
        throw GatewayAuthError("OAuth callback path was invalid", kind: .callback)
      }
      var query: [String: String] = [:]
      for item in components.queryItems ?? [] {
        guard query[item.name] == nil else {
          throw GatewayAuthError("OAuth callback contained duplicate parameters", kind: .callback)
        }
        query[item.name] = item.value ?? ""
      }
      guard query["state"] == expectedState, query["error"] != nil || !(query["code"] ?? "").isEmpty else {
        throw GatewayAuthError("OAuth callback state or code is invalid", kind: .callback)
      }
      let html =
        "<html><body><h1>Authorization received</h1><p>You can close this window.</p></body></html>"
      let response =
        "HTTP/1.1 200 OK\r\nContent-Type: text/html; charset=utf-8\r\nContent-Length: \(html.utf8.count)\r\nConnection: close\r\n\r\n\(html)"
      #if canImport(Darwin)
        var suppressPipeSignal: Int32 = 1
        setsockopt(connection, SOL_SOCKET, SO_NOSIGPIPE, &suppressPipeSignal, socklen_t(MemoryLayout<Int32>.size))
        let sendFlags: Int32 = 0
      #else
        let sendFlags = Int32(MSG_NOSIGNAL)
      #endif
      _ = response.withCString { send(connection, $0, strlen($0), sendFlags) }
      return OAuthCallback(code: query["code"], state: query["state"], error: query["error"])
    }
  }
}

private func waitForCallbackData(descriptor: Int32, deadline: TimeInterval) throws {
  let remaining = deadline - ProcessInfo.processInfo.systemUptime
  guard remaining > 0 else {
    throw GatewayAuthError("OAuth callback timed out", kind: .timeout)
  }
  var item = pollfd(fd: descriptor, events: Int16(POLLIN), revents: 0)
  let milliseconds = Int32(min(ceil(remaining * 1_000), Double(Int32.max)))
  guard poll(&item, 1, milliseconds) > 0 else {
    throw GatewayAuthError("OAuth callback timed out", kind: .timeout)
  }
}

private func readCallbackRequest(connection: Int32, deadline: TimeInterval) throws -> String {
  var request = Data()
  let maximumBytes = 16_384
  while request.count < maximumBytes {
    try waitForCallbackData(descriptor: connection, deadline: deadline)
    var buffer = [UInt8](repeating: 0, count: min(4_096, maximumBytes - request.count))
    let count = recv(connection, &buffer, buffer.count, 0)
    guard count > 0 else {
      throw GatewayAuthError("OAuth callback request was incomplete", kind: .callback)
    }
    request.append(contentsOf: buffer[..<count])
    if request.range(of: Data("\r\n\r\n".utf8)) != nil {
      guard let text = String(data: request, encoding: .utf8) else {
        throw GatewayAuthError("OAuth callback request was malformed", kind: .callback)
      }
      return text
    }
  }
  throw GatewayAuthError("OAuth callback request was too large", kind: .callback)
}
