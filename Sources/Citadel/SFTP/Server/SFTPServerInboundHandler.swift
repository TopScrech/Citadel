import Foundation
import NIO
import NIOSSH
import Logging

struct SFTPDirectoryHandleIterator: Sendable {
    var listing = [SFTPFileListing]()
}

final class SFTPServerInboundHandler: ChannelInboundHandler {
    typealias InboundIn = SFTPMessage
    
    let logger: Logger
    let delegate: SFTPDelegate
    let initialized: EventLoopPromise<Void>
    var currentHandleID: UInt32 = 0
    var files = [UInt32: SFTPFileHandle]()
    var directories = [UInt32: SFTPDirectoryHandle]()
    var directoryListing = [UInt32: SFTPDirectoryHandleIterator]()
    var previousTask: EventLoopFuture<Void>
    let username: String?
    
    init(logger: Logger, delegate: SFTPDelegate, eventLoop: EventLoop, username: String?) {
        self.logger = logger
        self.delegate = delegate
        self.initialized = eventLoop.makePromise()
        self.previousTask = eventLoop.makeSucceededVoidFuture()
        self.username = username
    }
    
    func initialize(command: SFTPMessage.Initialize, context: ChannelHandlerContext) {
        let boundContext = NIOLoopBound(context, eventLoop: context.eventLoop)
        guard command.version >= .v3 else {
            return boundContext.value.channel.triggerUserOutboundEvent(ChannelFailureEvent()).whenComplete { _ in
                boundContext.value.channel.close(promise: nil)
            }
        }
        
        boundContext.value.writeAndFlush(
            NIOAny(SFTPMessage.version(
                .init(
                    version: .v3,
                    extensionData: []
                )
            )),
            promise: nil
        )
    }
    
    func makeContext() -> SSHContext {
        SSHContext(username: self.username)
    }
    
    func openFile(command: SFTPMessage.OpenFile, context: ChannelHandlerContext) {
        let boundContext = NIOLoopBound(context, eventLoop: context.eventLoop)
        let boundSelf = NIOLoopBound(self, eventLoop: context.eventLoop)
        let promise = boundContext.value.eventLoop.makePromise(of: SFTPFileHandle.self)
        promise.completeWithTask { [delegate, sshContext = makeContext()] in
            try await delegate.openFile(
                command.filePath,
                withAttributes: command.attributes,
                flags: command.pFlags,
                context: sshContext
            )
        }
        
        _ = promise.futureResult.map { file -> SFTPMessage in
            let handle = boundSelf.value.currentHandleID
            boundSelf.value.files[handle] = file
            boundSelf.value.currentHandleID &+= 1
            
            return SFTPMessage.handle(
                SFTPMessage.Handle(
                    requestId: command.requestId,
                    handle: ByteBuffer(integer: handle, endianness: .big)
                )
            )
        }.flatMap { handle in
            boundContext.value.writeAndFlush(NIOAny(handle))
        }
    }
    
    func closeFile(command: SFTPMessage.CloseFile, context: ChannelHandlerContext) {
        let boundContext = NIOLoopBound(context, eventLoop: context.eventLoop)
        let boundSelf = NIOLoopBound(self, eventLoop: context.eventLoop)
        guard let id: UInt32 = command.handle.getInteger(at: 0) else {
            logger.error("bad SFTP file handle")
            return
        }
        
        if let file = files[id] {
            previousTask = previousTask.flatMap {
                let promise = boundContext.value.eventLoop.makePromise(of: SFTPStatusCode.self)
                promise.completeWithTask {
                    try await file.close()
                }
                boundSelf.value.files[id] = nil
                return promise.futureResult.flatMap { status in
                    boundContext.value.channel.writeAndFlush(
                        SFTPMessage.status(
                            SFTPMessage.Status(
                                requestId: command.requestId,
                                errorCode: status,
                                message: "uploaded",
                                languageTag: "EN"
                            )
                        )
                    )
                }.flatMapError { _ in
                    boundContext.value.channel.triggerUserOutboundEvent(ChannelFailureEvent()).flatMap {
                        boundContext.value.channel.close()
                    }
                }
            }
        } else if directories[id] != nil {
            directories[id] = nil
            directoryListing[id] = nil
            
            previousTask = previousTask.flatMap {
                boundContext.value.channel.writeAndFlush(
                    SFTPMessage.status(
                        SFTPMessage.Status(
                            requestId: command.requestId,
                            errorCode: .ok,
                            message: "closed",
                            languageTag: "EN"
                        )
                    )
                )
            }
        } else {
            logger.error("unknown SFTP handle")
        }
    }
    
    func readFile(command: SFTPMessage.ReadFile, context: ChannelHandlerContext) {
        let boundContext = NIOLoopBound(context, eventLoop: context.eventLoop)
        let boundSelf = NIOLoopBound(self, eventLoop: context.eventLoop)
        previousTask = previousTask.flatMap {
            boundSelf.value.withFileHandle(command.handle, context: boundContext.value) { file -> ByteBuffer in
                try await file.read(at: command.offset, length: command.length)
            }.flatMap { data -> EventLoopFuture<Void> in
                if data.readableBytes == 0 {
                    return boundContext.value.channel.writeAndFlush(
                        SFTPMessage.status(
                            .init(
                                requestId: command.requestId,
                                errorCode: .eof,
                                message: "EOF",
                                languageTag: "EN"
                            )
                        )
                    )
                } else {
                    return boundContext.value.channel.writeAndFlush(
                        SFTPMessage.data(
                            SFTPMessage.FileData(
                                requestId: command.requestId,
                                data: data
                            )
                        )
                    )
                }
            }.flatMapError { _ in
                boundContext.value.channel.triggerUserOutboundEvent(ChannelFailureEvent()).flatMap {
                    boundContext.value.channel.close()
                }
            }
        }
    }
    
    func writeFile(command: SFTPMessage.WriteFile, context: ChannelHandlerContext) {
        let boundContext = NIOLoopBound(context, eventLoop: context.eventLoop)
        let boundSelf = NIOLoopBound(self, eventLoop: context.eventLoop)
        previousTask = previousTask.flatMap {
            boundSelf.value.withFileHandle(command.handle, context: boundContext.value) { file -> SFTPStatusCode in
                try await file.write(command.data, atOffset: command.offset)
            }.flatMap { status -> EventLoopFuture<Void> in
                boundContext.value.channel.writeAndFlush(
                    SFTPMessage.status(
                        SFTPMessage.Status(
                            requestId: command.requestId,
                            errorCode: status,
                            message: "",
                            languageTag: "EN"
                        )
                    )
                )
            }.flatMapError { _ in
                boundContext.value.channel.triggerUserOutboundEvent(ChannelFailureEvent()).flatMap {
                    boundContext.value.channel.close()
                }
            }
        }
    }
    
    func createDir(command: SFTPMessage.MkDir, context: ChannelHandlerContext) {
        let boundContext = NIOLoopBound(context, eventLoop: context.eventLoop)
        let promise = boundContext.value.eventLoop.makePromise(of: SFTPStatusCode.self)
        promise.completeWithTask { [delegate, sshContext = makeContext()] in
            try await delegate.createDirectory(
                command.filePath,
                withAttributes: command.attributes,
                context: sshContext
            )
        }
        
        _ = promise.futureResult.flatMap { status -> EventLoopFuture<Void> in
            boundContext.value.channel.writeAndFlush(
                SFTPMessage.status(
                    SFTPMessage.Status(
                        requestId: command.requestId,
                        errorCode: status,
                        message: "",
                        languageTag: "EN"
                    )
                )
            )
        }.flatMapError { _ in
            boundContext.value.channel.triggerUserOutboundEvent(ChannelFailureEvent()).flatMap {
                boundContext.value.channel.close()
            }
        }
    }
    
    func removeDir(command: SFTPMessage.RmDir, context: ChannelHandlerContext) {
        let boundContext = NIOLoopBound(context, eventLoop: context.eventLoop)
        let promise = boundContext.value.eventLoop.makePromise(of: SFTPStatusCode.self)
        promise.completeWithTask { [delegate, sshContext = makeContext()] in
            try await delegate.removeDirectory(
                command.filePath,
                context: sshContext
            )
        }
        
        _ =  promise.futureResult.flatMap { status -> EventLoopFuture<Void> in
            boundContext.value.channel.writeAndFlush(
                SFTPMessage.status(
                    SFTPMessage.Status(
                        requestId: command.requestId,
                        errorCode: status,
                        message: "",
                        languageTag: "EN"
                    )
                )
            )
        }.flatMapError { _ in
            boundContext.value.channel.triggerUserOutboundEvent(ChannelFailureEvent()).flatMap {
                boundContext.value.channel.close()
            }
        }
    }
    
    func stat(command: SFTPMessage.Stat, context: ChannelHandlerContext) {
        let boundContext = NIOLoopBound(context, eventLoop: context.eventLoop)
        let promise = boundContext.value.eventLoop.makePromise(of: SFTPFileAttributes.self)
        promise.completeWithTask { [delegate, sshContext = makeContext()] in
            try await delegate.fileAttributes(atPath: command.path, context: sshContext)
        }
        
        _ = promise.futureResult.flatMap { attributes -> EventLoopFuture<Void> in
            boundContext.value.writeAndFlush(
                NIOAny(SFTPMessage.attributes(
                    .init(
                        requestId: command.requestId,
                        attributes: attributes
                    )
                ))
            )
        }.flatMapErrorThrowing { _ in }
    }
    
    func lstat(command: SFTPMessage.LStat, context: ChannelHandlerContext) {
        let boundContext = NIOLoopBound(context, eventLoop: context.eventLoop)
        let promise = boundContext.value.eventLoop.makePromise(of: SFTPFileAttributes.self)
        promise.completeWithTask { [delegate, sshContext = makeContext()] in
            try await delegate.fileAttributes(atPath: command.path, context: sshContext)
        }
        
        _ = promise.futureResult.flatMap { attributes -> EventLoopFuture<Void> in
            boundContext.value.writeAndFlush(
                NIOAny(SFTPMessage.attributes(
                    .init(
                        requestId: command.requestId,
                        attributes: attributes
                    )
                ))
            )
        }.flatMapErrorThrowing { _ in }
    }
    
    func realPath(command: SFTPMessage.RealPath, context: ChannelHandlerContext) {
        let boundContext = NIOLoopBound(context, eventLoop: context.eventLoop)
        let promise = boundContext.value.eventLoop.makePromise(of: [SFTPPathComponent].self)
        promise.completeWithTask { [delegate, sshContext = makeContext()] in
            try await delegate.realPath(for: command.path, context: sshContext)
        }
        
        _ = promise.futureResult.flatMap { components -> EventLoopFuture<Void> in
            boundContext.value.writeAndFlush(
                NIOAny(SFTPMessage.name(
                    .init(
                        requestId: command.requestId,
                        components: components
                    )
                ))
            )
        }.flatMapErrorThrowing { _ in }
    }
    
    func openDir(command: SFTPMessage.OpenDir, context: ChannelHandlerContext) {
        let boundContext = NIOLoopBound(context, eventLoop: context.eventLoop)
        let boundSelf = NIOLoopBound(self, eventLoop: context.eventLoop)
        let promise = boundContext.value.eventLoop.makePromise(of: (SFTPDirectoryHandle, SFTPDirectoryHandleIterator).self)
        promise.completeWithTask { [delegate, sshContext = makeContext()] in
            let handle = try await delegate.openDirectory(atPath: command.handle, context: sshContext)
            let files = try await handle.listFiles(context: sshContext)
            let iterator = SFTPDirectoryHandleIterator(listing: files)
            return (handle, iterator)
        }
        
        _ = promise.futureResult.map { (directory, listing) -> SFTPMessage in
            let handle = boundSelf.value.currentHandleID
            boundSelf.value.directories[handle] = directory
            boundSelf.value.directoryListing[handle] = listing
            boundSelf.value.currentHandleID &+= 1
            
            return SFTPMessage.handle(
                SFTPMessage.Handle(
                    requestId: command.requestId,
                    handle: ByteBuffer(integer: handle, endianness: .big)
                )
            )
        }.flatMap { handle in
            boundContext.value.writeAndFlush(NIOAny(handle))
        }.flatMapErrorThrowing { _ in }
    }
    
    func readDir(command: SFTPMessage.ReadDir, context: ChannelHandlerContext) {
        let boundContext = NIOLoopBound(context, eventLoop: context.eventLoop)
        let boundSelf = NIOLoopBound(self, eventLoop: context.eventLoop)
        guard
            let id: UInt32 = command.handle.getInteger(at: 0),
            var listing = directoryListing[id]
        else {
            logger.error("bad SFTP directory handle")
            return
        }
        
        let result: EventLoopFuture<Void>
        if listing.listing.isEmpty {
            boundSelf.value.directoryListing[id] = nil
            result = boundContext.value.channel.writeAndFlush(SFTPMessage.status(
                SFTPMessage.Status(
                    requestId: command.requestId,
                    errorCode: .eof,
                    message: "",
                    languageTag: "EN"
                )
            ))
        } else {
            let file = listing.listing.removeFirst()
            result = boundContext.value.channel.writeAndFlush(SFTPMessage.name(
                .init(
                    requestId: command.requestId,
                    components: file.path
                )
            ))
        }
        
        boundSelf.value.directoryListing[id] = listing
        _ = result.flatMapError { error -> EventLoopFuture<Void> in
            boundSelf.value.logger.error("\(error)")
            return boundContext.value.channel.writeAndFlush(
                SFTPMessage.status(
                    SFTPMessage.Status(
                        requestId: command.requestId,
                        errorCode: .failure,
                        message: "",
                        languageTag: "EN"
                    )
                )
            )
        }
    }
    
    func fileStat(command: SFTPMessage.FileStat, context: ChannelHandlerContext) {
        let boundContext = NIOLoopBound(context, eventLoop: context.eventLoop)
        let boundSelf = NIOLoopBound(self, eventLoop: context.eventLoop)
        _ = boundSelf.value.withFileHandle(command.handle, context: boundContext.value) { file in
            try await file.readFileAttributes()
        }.flatMap { attributes -> EventLoopFuture<Void> in
            boundContext.value.channel.writeAndFlush(
                SFTPMessage.attributes(
                    .init(
                        requestId: command.requestId,
                        attributes: attributes
                    )
                )
            )
        }.flatMapError { _ -> EventLoopFuture<Void> in
            boundContext.value.channel.writeAndFlush(
                SFTPMessage.status(
                    SFTPMessage.Status(
                        requestId: command.requestId,
                        errorCode: .failure,
                        message: "",
                        languageTag: "EN"
                    )
                )
            )
        }
    }
    
    func removeFile(command: SFTPMessage.Remove, context: ChannelHandlerContext) {
        let boundContext = NIOLoopBound(context, eventLoop: context.eventLoop)
        let promise = boundContext.value.eventLoop.makePromise(of: SFTPStatusCode.self)
        promise.completeWithTask { [delegate, sshContext = makeContext()] in
            try await delegate.removeFile(command.filename, context: sshContext)
        }
        _ = promise.futureResult.flatMap { status -> EventLoopFuture<Void> in
            boundContext.value.channel.writeAndFlush(
                SFTPMessage.status(
                    SFTPMessage.Status(
                        requestId: command.requestId,
                        errorCode: status,
                        message: "",
                        languageTag: "EN"
                    )
                )
            )
        }.flatMapErrorThrowing { _ in }
    }
    
    func fileSetStat(command: SFTPMessage.FileSetStat, context: ChannelHandlerContext) {
        let boundContext = NIOLoopBound(context, eventLoop: context.eventLoop)
        let boundSelf = NIOLoopBound(self, eventLoop: context.eventLoop)
        _ = boundSelf.value.withFileHandle(command.handle, context: boundContext.value) { handle in
            try await handle.setFileAttributes(to: command.attributes)
        }.flatMap { () -> EventLoopFuture<Void> in
            boundContext.value.channel.writeAndFlush(
                SFTPMessage.status(
                    SFTPMessage.Status(
                        requestId: command.requestId,
                        errorCode: .ok,
                        message: "",
                        languageTag: "EN"
                    )
                )
            )
        }.flatMapError { _ -> EventLoopFuture<Void> in
            boundContext.value.channel.writeAndFlush(
                SFTPMessage.status(
                    SFTPMessage.Status(
                        requestId: command.requestId,
                        errorCode: .failure,
                        message: "",
                        languageTag: "EN"
                    )
                )
            )
        }
    }
    
    func setStat(command: SFTPMessage.SetStat, context: ChannelHandlerContext) {
        let boundContext = NIOLoopBound(context, eventLoop: context.eventLoop)
        let promise = boundContext.value.eventLoop.makePromise(of: SFTPStatusCode.self)
        promise.completeWithTask { [delegate, sshContext = makeContext()] in
            try await delegate.setFileAttributes(
                to: command.attributes,
                atPath: command.path,
                context: sshContext
            )
        }
        _ = promise.futureResult.flatMap { status -> EventLoopFuture<Void> in
            boundContext.value.channel.writeAndFlush(
                SFTPMessage.status(
                    SFTPMessage.Status(
                        requestId: command.requestId,
                        errorCode: status,
                        message: "",
                        languageTag: "EN"
                    )
                )
            )
        }.flatMapErrorThrowing { _ in }
    }
    
    func symlink(command: SFTPMessage.Symlink, context:ChannelHandlerContext) {
        let boundContext = NIOLoopBound(context, eventLoop: context.eventLoop)
        let promise = boundContext.value.eventLoop.makePromise(of: SFTPStatusCode.self)
        promise.completeWithTask { [delegate, sshContext = makeContext()] in
            try await delegate.addSymlink(
                linkPath: command.linkPath,
                targetPath: command.targetPath,
                context: sshContext
            )
        }
        _ = promise.futureResult.flatMap { status -> EventLoopFuture<Void> in
            boundContext.value.channel.writeAndFlush(
                SFTPMessage.status(
                    SFTPMessage.Status(
                        requestId: command.requestId,
                        errorCode: status,
                        message: "",
                        languageTag: "EN"
                    )
                )
            )
        }.flatMapErrorThrowing { _ in }
    }

    func rename(command: SFTPMessage.Rename, context:ChannelHandlerContext) {
        let boundContext = NIOLoopBound(context, eventLoop: context.eventLoop)
        let promise = boundContext.value.eventLoop.makePromise(of: SFTPStatusCode.self)
        promise.completeWithTask { [delegate, sshContext = makeContext()] in
            try await delegate.rename(
                oldPath: command.oldPath,
                newPath: command.newPath,
                flags: command.flags,
                context: sshContext
            )
        }
        _ = promise.futureResult.flatMap { status -> EventLoopFuture<Void> in
            boundContext.value.channel.writeAndFlush(
                SFTPMessage.status(
                    SFTPMessage.Status(
                        requestId: command.requestId,
                        errorCode: status,
                        message: "",
                        languageTag: "EN"
                    )
                )
            )
        }.flatMapErrorThrowing { _ in }
    }

    func readlink(command: SFTPMessage.Readlink, context:ChannelHandlerContext) {
        let boundContext = NIOLoopBound(context, eventLoop: context.eventLoop)
        let promise = boundContext.value.eventLoop.makePromise(of: [SFTPPathComponent].self)
        promise.completeWithTask { [delegate, sshContext = makeContext()] in
            try await delegate.readSymlink(
                atPath: command.path,
                context: sshContext
            )
        }
        _ = promise.futureResult.flatMap { components -> EventLoopFuture<Void> in
            boundContext.value.channel.writeAndFlush(
                SFTPMessage.name(
                    SFTPMessage.Name(
                        requestId: command.requestId,
                        components: components
                    )
                )
            )
        }.flatMapError { _ -> EventLoopFuture<Void> in
            boundContext.value.channel.writeAndFlush(
                SFTPMessage.status(
                    SFTPMessage.Status(
                        requestId: command.requestId,
                        errorCode: .failure,
                        message: "",
                        languageTag: "EN"
                    )
                )
            )
        }
    }
    
    func channelRead(context: ChannelHandlerContext, data: NIOAny) {
        let boundContext = NIOLoopBound(context, eventLoop: context.eventLoop)
        switch unwrapInboundIn(data) {
        case .initialize(let command):
            initialize(command: command, context: boundContext.value)
        case .openFile(let command):
            openFile(command: command, context: boundContext.value)
        case .closeFile(let command):
            closeFile(command: command, context: boundContext.value)
        case .read(let command):
            readFile(command: command, context: boundContext.value)
        case .write(let command):
            writeFile(command: command, context: boundContext.value)
        case .mkdir(let command):
            createDir(command: command, context: boundContext.value)
        case .opendir(let command):
            openDir(command: command, context: boundContext.value)
        case .rmdir(let command):
            removeDir(command: command, context: boundContext.value)
        case .stat(let command):
            stat(command: command, context: boundContext.value)
        case .lstat(let command):
            lstat(command: command, context: boundContext.value)
        case .realpath(let command):
            realPath(command: command, context: boundContext.value)
        case .readdir(let command):
            readDir(command: command, context: boundContext.value)
        case .fstat(let command):
            fileStat(command: command, context: boundContext.value)
        case .remove(let command):
            removeFile(command: command, context: boundContext.value)
        case .fsetstat(let command):
            fileSetStat(command: command, context: boundContext.value)
        case .setstat(let command):
            setStat(command: command, context: boundContext.value)
        case .symlink(let command):
            symlink(command: command, context: boundContext.value)
        case .readlink(let command):
            readlink(command: command, context: boundContext.value)
        case .rename(let command):
            rename(command: command, context: boundContext.value)
        case .version, .handle, .status, .data, .attributes, .name:
            // Client cannot send these messages
            boundContext.value.channel.triggerUserOutboundEvent(ChannelFailureEvent()).whenComplete { _ in
                boundContext.value.channel.close(promise: nil)
            }
        }
    }
    
    func withFileHandle<T: Sendable>(_ handle: ByteBuffer, context: ChannelHandlerContext, perform: @Sendable @escaping (SFTPFileHandle) async throws -> T) -> EventLoopFuture<T> {
        let boundContext = NIOLoopBound(context, eventLoop: context.eventLoop)
        guard
            let id: UInt32 = handle.getInteger(at: 0),
            let file = files[id]
        else {
            logger.error("bad SFTP file handle")
            return boundContext.value.eventLoop.makeFailedFuture(SFTPError.fileHandleInvalid)
        }
        
        let promise = boundContext.value.eventLoop.makePromise(of: T.self)
        promise.completeWithTask {
            try await perform(file)
        }
        return promise.futureResult
    }
    
    func userInboundEventTriggered(context: ChannelHandlerContext, event: Any) {
        let boundContext = NIOLoopBound(context, eventLoop: context.eventLoop)
        switch event {
        case ChannelEvent.inputClosed:
            boundContext.value.channel.close(promise: nil)
        default:
            boundContext.value.fireUserInboundEventTriggered(event)
        }
    }
    
    deinit {
        initialized.fail(SFTPError.connectionClosed)
    }
}
