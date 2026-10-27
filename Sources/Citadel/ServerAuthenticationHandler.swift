import NIO
import NIOConcurrencyHelpers
import NIOSSH

final class ServerAuthenticationHandler: ChannelInboundHandler, NIOSSHServerUserAuthenticationDelegate, GlobalRequestDelegate {
    typealias InboundIn = ByteBuffer

    private let delegate: NIOSSHServerUserAuthenticationDelegate
    private let serverDelegate: CitadelServerDelegate
    private let authenticatedUsername = NIOLockedValueBox<String?>(nil)

    var username: String? { authenticatedUsername.withLockedValue { $0 } }
    var supportedAuthenticationMethods: NIOSSHAvailableUserAuthenticationMethods {
        delegate.supportedAuthenticationMethods
    }

    init(delegate: NIOSSHServerUserAuthenticationDelegate, serverDelegate: CitadelServerDelegate) {
        self.delegate = delegate
        self.serverDelegate = serverDelegate
    }

    func requestReceived(request: NIOSSHUserAuthenticationRequest, responsePromise: EventLoopPromise<NIOSSHUserAuthenticationOutcome>) {
        let validation = responsePromise.futureResult.eventLoop.makePromise(of: NIOSSHUserAuthenticationOutcome.self)
        let username = request.username
        let state = authenticatedUsername
        validation.futureResult.whenComplete { result in
            if case .success(.success) = result {
                state.withLockedValue { $0 = username }
            }
            responsePromise.completeWith(result)
        }
        delegate.requestReceived(request: request, responsePromise: validation)
    }

    func tcpForwardingRequest(_ request: GlobalRequest.TCPForwardingRequest, handler: NIOSSHHandler, promise: EventLoopPromise<GlobalRequest.TCPForwardingResponse>) {
        serverDelegate.tcpForwardingRequest(request, handler: handler, promise: promise, username: username)
    }
}
