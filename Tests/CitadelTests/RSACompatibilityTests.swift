@testable import Citadel
import NIO
import NIOSSH
import Crypto
import XCTest

final class RSACompatibilityTests: XCTestCase {
    func testRSAHostKeyWithAES128CTR() async throws {
        let key = try Insecure.RSA.PrivateKey(sshRsa: TestRSAKey.openSSH)
        let hostKey = NIOSSHPrivateKey(rsaKey: key)
        var algorithms = SSHAlgorithms.all
        algorithms.transportProtectionSchemes = .replace(with: [AES128CTR.self])
        let auth = AuthDelegate(supportedAuthenticationMethods: .password) { request, promise in
            if case .password(let password) = request.request,
               request.username == "citadel", password.password == "test" {
                promise.assumeIsolated().succeed(.success)
            } else {
                promise.assumeIsolated().succeed(.failure)
            }
        }
        let group = MultiThreadedEventLoopGroup(numberOfThreads: 1)
        let server = try await SSHServer.host(
            host: "127.0.0.1", port: 0, hostKeys: [hostKey],
            algorithms: algorithms, authenticationDelegate: auth, group: group
        )
        do {
            let port = try XCTUnwrap(server.channel.localAddress?.port)
            let client = try await SSHClient.connect(
                host: "127.0.0.1", port: port,
                authenticationMethod: .passwordBased(username: "citadel", password: "test"),
                hostKeyValidator: .trustedKeys([hostKey.publicKey]),
                reconnect: .never, algorithms: algorithms
            )
            XCTAssertTrue(client.isConnected)
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
