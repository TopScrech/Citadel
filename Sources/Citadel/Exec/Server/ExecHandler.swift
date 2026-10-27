//===----------------------------------------------------------------------===//
//
// This source file is part of the SwiftNIO open source project
//
// Copyright (c) 2020 Apple Inc. and the SwiftNIO project authors
// Licensed under Apache License v2.0
//
// See LICENSE.txt for license information
// See CONTRIBUTORS.txt for the list of SwiftNIO project authors
//
// SPDX-License-Identifier: Apache-2.0
//
//===----------------------------------------------------------------------===//

import Foundation
import NIOCore
import NIOFoundationCompat
import NIOPosix
import NIOSSH

#if canImport(Darwin)
import Darwin
#elseif canImport(Glibc)
import Glibc
#elseif canImport(Musl)
import Musl
#elseif canImport(Bionic)
import Bionic
#endif

enum SSHServerError: Error {
    case invalidCommand
    case invalidDataType
    case invalidChannelType
    case alreadyListening
    case notListening
}

final class ExecHandler: ChannelDuplexHandler {
    typealias InboundIn = SSHChannelData
    typealias InboundOut = SSHChannelData
    typealias OutboundIn = SSHChannelData
    typealias OutboundOut = SSHChannelData
    
    let delegate: ExecDelegate?
    
    init(delegate: ExecDelegate?, username: String?) {
        self.delegate = delegate
        self.username = username
    }
    
    var context: ExecCommandContext?
    var pipeChannel: Channel?
    var environment: [String: String] = [:]
    let username: String?
    
    func handlerAdded(context: ChannelHandlerContext) {
        let boundContext = NIOLoopBound(context, eventLoop: context.eventLoop)
        context.channel.setOption(ChannelOptions.allowRemoteHalfClosure, value: true).whenFailure { error in
            boundContext.value.fireErrorCaught(error)
        }
    }
    
    func channelInactive(context: ChannelHandlerContext) {
        let commandContext = self.context
        self.context = nil
        self.pipeChannel = nil
        let termination = context.eventLoop.makePromise(of: Void.self)
        termination.completeWithTask { try await commandContext?.terminate() }
        termination.futureResult.whenFailure { _ in }
        context.fireChannelInactive()
    }
    
    func userInboundEventTriggered(context: ChannelHandlerContext, event: Any) {
        let channel = context.channel
        let boundContext = NIOLoopBound(context, eventLoop: context.eventLoop)
        switch event {
        case let event as SSHChannelRequestEvent.ExecRequest:
            if let delegate = delegate {
                self.exec(event, delegate: delegate, channel: context.channel)
            } else if event.wantReply {
                context.channel.triggerUserOutboundEvent(ChannelFailureEvent()).whenComplete { _ in
                    channel.close(promise: nil)
                }
            }
        case let event as SSHChannelRequestEvent.EnvironmentRequest:
            if let delegate = delegate {
                let value = event.value
                let name = event.name
                let update = context.eventLoop.makePromise(of: Void.self)
                update.completeWithTask { try await delegate.setEnvironmentValue(value, forKey: name) }
                update.futureResult.whenFailure { boundContext.value.fireErrorCaught($0) }
            }
        case ChannelEvent.inputClosed:
            let commandContext = self.context
            let close = context.eventLoop.makePromise(of: Void.self)
            close.completeWithTask { try await commandContext?.inputClosed() }
            close.futureResult.whenFailure { boundContext.value.fireErrorCaught($0) }
        default:
            context.fireUserInboundEventTriggered(event)
        }
    }
    
    func channelRead(context: ChannelHandlerContext, data: NIOAny) {
        context.fireChannelRead(data)
    }
    
    func write(context: ChannelHandlerContext, data: NIOAny, promise: EventLoopPromise<Void>?) {
        context.write(data, promise: promise)
    }
    
    private func exec(_ event: SSHChannelRequestEvent.ExecRequest, delegate: ExecDelegate, channel: Channel) {
        let boundSelf = NIOLoopBound(self, eventLoop: channel.eventLoop)
        let command = event.command
        let wantReply = event.wantReply
        let successPromise = channel.eventLoop.makePromise(of: Int.self)
        let handler = ExecOutputHandler(username: username) { code in
            successPromise.succeed(code)
        } onFailure: { _ in
            if wantReply {
                channel.triggerUserOutboundEvent(ChannelFailureEvent()).whenComplete { _ in
                    channel.close(promise: nil)
                }
            } else {
                channel.close(promise: nil)
            }
        }
        
        let (ours, theirs) = GlueHandler.matchedPair()
        let boundTheirs = NIOLoopBound(theirs, eventLoop: channel.eventLoop)
        
        // Ok, great, we've sorted stdout and stdin. For stderr we need a different strategy: we just park a thread for this.
        let stderrHandle = handler.stderrPipe.fileHandleForReading
        stderrHandle.readabilityHandler = { stderrHandle in
            do {
                guard let data = try stderrHandle.readToEnd() else {
                    stderrHandle.readabilityHandler = nil
                    return
                }
                var buffer = channel.allocator.buffer(capacity: data.count)
                buffer.writeContiguousBytes(data)
                channel.writeAndFlush(SSHChannelData(type: .stdErr, data: .byteBuffer(buffer)), promise: nil)
            } catch {
                channel.close(promise: nil)
            }
        }
        
        channel.eventLoop.makeCompletedFuture {
            try channel.pipeline.syncOperations.addHandler(ours)
        }.flatMap {
            NIOPipeBootstrap(group: channel.eventLoop)
                .channelOption(ChannelOptions.allowRemoteHalfClosure, value: true)
                .channelInitializer { pipeChannel in
                    pipeChannel.eventLoop.makeCompletedFuture {
                        try pipeChannel.pipeline.syncOperations.addHandlers(SSHInboundChannelDataWrapper(), SSHOutboundChannelDataUnwrapper(), boundTheirs.value)
                    }
                }.takingOwnershipOfDescriptors(
                    input: dup(handler.stdoutPipe.fileHandleForReading.fileDescriptor),
                    output: dup(handler.stdinPipe.fileHandleForWriting.fileDescriptor)
                )
        }.flatMap { pipeChannel -> EventLoopFuture<Channel> in
            boundSelf.value.pipeChannel = pipeChannel
            let start = channel.eventLoop.makePromise(of: ExecCommandContext.self)
            start.completeWithTask {
                do {
                    return try await delegate.start(command: command, outputHandler: handler)
                } catch {
                    try? await pipeChannel.close(mode: .all)
                    throw error
                }
            }

            return start.futureResult.flatMap { commandContext in
                boundSelf.value.context = commandContext
                if wantReply {
                    return channel.triggerUserOutboundEvent(ChannelSuccessEvent()).map {
                        pipeChannel
                    }
                } else {
                    return channel.eventLoop.makeSucceededFuture(pipeChannel)
                }
            }
        }.flatMap { pipeChannel in
            successPromise.futureResult.flatMap { code in
                pipeChannel.close(mode: .all).map { code }
            }
        }.flatMap { code in
            channel.triggerUserOutboundEvent(SSHChannelRequestEvent.ExitStatus(exitStatus: code))
        }.whenComplete { result in
            switch result {
            case .success:
                channel.close(promise: nil)
            case .failure:
                if wantReply {
                    channel.triggerUserOutboundEvent(ChannelFailureEvent()).whenComplete { _ in
                        channel.close(promise: nil)
                    }
                } else {
                    channel.close(promise: nil)
                }
            }
        }
    }
}
