// swift-tools-version: 6.0
import PackageDescription

let package = Package(
  name: "google-gateway-auth",
  platforms: [.macOS(.v14)],
  products: [.library(name: "GoogleGatewayAuth", targets: ["GoogleGatewayAuth"])],
  targets: [
    .target(name: "GoogleGatewayAuth"),
    .testTarget(name: "GoogleGatewayAuthTests", dependencies: ["GoogleGatewayAuth"])
  ],
  swiftLanguageModes: [.v6]
)
