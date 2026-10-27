struct SSHClientState {
    var session: SSHClientSession
    var userInitiatedClose = false
    var connectionSettings = SSHConnectionPoolSettings()
    var onDisconnect: (@Sendable () -> Void)?
}
