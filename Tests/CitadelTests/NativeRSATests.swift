import Crypto
import NIO
import NIOSSH
import Testing
@testable import Citadel

struct NativeRSATests {
    @Test(arguments: [RSASignatureAlgorithm.sha512, .sha256, .sha1])
    func rsaAuthenticationAndCTR(signatureAlgorithm: RSASignatureAlgorithm) async throws {
        let privateKey = try Insecure.RSA.PrivateKey(sshRsa: TestRSAKey.openSSH)
        let hostKey = NIOSSHPrivateKey(rsaKey: privateKey)
        let expectedKey = hostKey.publicKey
        let auth = AuthDelegate(supportedAuthenticationMethods: .publicKey) { request, promise in
            if case .publicKey(let key) = request.request, key.publicKey == expectedKey, request.username == "rsa-test" {
                promise.assumeIsolated().succeed(.success)
            } else {
                promise.assumeIsolated().succeed(.failure)
            }
        }
        var algorithms = SSHAlgorithms()
        switch signatureAlgorithm {
        case .sha512: algorithms.transportProtectionSchemes = .replace(with: [AES128CTRSHA512.self])
        case .sha256: algorithms.transportProtectionSchemes = .replace(with: [AES128CTR.self])
        case .sha1: algorithms.transportProtectionSchemes = .replace(with: [AES128CTRSHA1.self])
        }
        let group = MultiThreadedEventLoopGroup(numberOfThreads: 1)
        let server = try await SSHServer.host(host: "127.0.0.1", port: 0, hostKeys: [hostKey], algorithms: algorithms, authenticationDelegate: auth, group: group)
        do {
            let port = try #require(server.channel.localAddress?.port)
            let client = try await SSHClient.connect(host: "127.0.0.1", port: port, authenticationMethod: .rsa(username: "rsa-test", privateKey: privateKey, signatureAlgorithm: signatureAlgorithm), hostKeyValidator: .trustedKeys([expectedKey]), reconnect: .never, algorithms: algorithms)
            #expect(client.isConnected)
            try await client.close()
            try await server.close()
            try await group.shutdownGracefully()
        } catch {
            try? await server.close()
            try? await group.shutdownGracefully()
            throw error
        }
    }
}
