import NIOSSH

// Configuration stores immutable algorithm metatypes, not cipher instances
public struct SSHAlgorithms: @unchecked Sendable {
    public var transportProtectionSchemes: Modification<NIOSSHTransportProtection.Type>?

    public init() {}

    public static let all: SSHAlgorithms = {
        var algorithms = SSHAlgorithms()
        algorithms.transportProtectionSchemes = .add([
            AES128CTR.self, AES128CTRSHA512.self, AES128CTRSHA1.self
        ])
        return algorithms
    }()

    func apply(to configuration: inout SSHClientConfiguration) {
        transportProtectionSchemes?.apply(to: &configuration.transportProtectionSchemes)
    }

    func apply(to configuration: inout SSHServerConfiguration) {
        transportProtectionSchemes?.apply(to: &configuration.transportProtectionSchemes)
    }
}
