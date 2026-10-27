// swift-tools-version:6.4

import PackageDescription

let package = Package(
    name: "Citadel",
    platforms: [
        .macOS(.v14),
        .iOS(.v17)
    ],
    products: [
        .library(name: "Citadel", targets: ["Citadel"])
    ],
    dependencies: [
        // https://github.com/apple/swift-nio-ssh
        .package(url: "https://github.com/Wellz26/swift-nio-ssh.git", from: "0.15.1"),
        
        // https://github.com/apple/swift-nio.git
        .package(url: "https://github.com/apple/swift-nio", from: "2.81.0"),
        
        // https://github.com/apple/swift-log.git
        .package(url: "https://github.com/apple/swift-log", from: "1.0.0"),
        
        // https://github.com/TopScrech/BigInt
        .package(url: "https://github.com/TopScrech/BigInt", branch: "master"),
        
        // https://github.com/apple/swift-crypto.git
        .package(url: "https://github.com/apple/swift-crypto", from: "3.12.3"),
        
        // https://github.com/mtynior/ColorizeSwift
        .package(url: "https://github.com/mtynior/ColorizeSwift", from: "1.5.0")
    ],
    targets: [
        .target(name: "CCitadelBcrypt"),
        .target(
            name: "Citadel",
            dependencies: [
                .target(name: "CCitadelBcrypt"),
                .product(name: "NIOSSH", package: "swift-nio-ssh"),
                .product(name: "NIO", package: "swift-nio"),
                .product(name: "Crypto", package: "swift-crypto"),
                .product(name: "_CryptoExtras", package: "swift-crypto"),
                .product(name: "BigInt", package: "BigInt"),
                .product(name: "Logging", package: "swift-log")
            ]
        ),
        .executableTarget(
            name: "CitadelServerExample",
            dependencies: [
                "Citadel",
                .product(name: "ColorizeSwift", package: "ColorizeSwift")
            ]
        ),
        .testTarget(
            name: "CitadelTests",
            dependencies: [
                "Citadel",
                .product(name: "NIOSSH", package: "swift-nio-ssh"),
                .product(name: "BigInt", package: "BigInt"),
                .product(name: "Logging", package: "swift-log")
            ]
        )
    ]
)
