//
// Part of SwiftSMB
// CancelTests.swift
//
// Licensed under Apache License v2.0
// Copyright its respective authors
//

@testable import SwiftSMB
import Testing

@Suite(.tags(.integration))
struct CancelTests {
    @Test("cancelling a notify request withdraws it before its directory is closed")
    func cancellingNotifyRequestWithdrawsItBeforeItsDirectoryIsClosed() async throws {
        try await withPublicShare { ctx in
            // Other tests change the share root, which would complete the request; nothing changes this directory.
            let path = uniquePath("notify-cancel")
            try await Bridge.makeDir(context: ctx, path: path)
            defer { try? await Bridge.removeDir(context: ctx, path: path) }
            let directory = try await Bridge.open(
                context: ctx,
                path: path,
                flags: Bridge.OpenFlags(.readOnly, options: [.directory])
            )
            defer { try? await Bridge.close(context: ctx, file: directory) }

            let request = try await Bridge.notifyChange(context: ctx, directory: directory) { _ in }
            // Requests on a connection are processed in order, so once the echo returns the notify request is pending.
            try await Bridge.echo(context: ctx)
            #expect(try await hasPendingRequests(ctx))

            try await Bridge.cancel(context: ctx, request: request)
            // The next servicing sends the queued CANCEL, and the server then answers the notify request.
            try await waitForReplies(ctx)
            #expect(try await !hasPendingRequests(ctx))
        }
    }

    @Test("cancelling a completed notify request sends nothing")
    func cancellingCompletedNotifyRequestSendsNothing() async throws {
        try await withPublicShare { ctx in
            // Other tests change the share root, which would complete the request; nothing changes this directory.
            let path = uniquePath("notify-cancel")
            try await Bridge.makeDir(context: ctx, path: path)
            defer { try? await Bridge.removeDir(context: ctx, path: path) }
            let directory = try await Bridge.open(
                context: ctx,
                path: path,
                flags: Bridge.OpenFlags(.readOnly, options: [.directory])
            )
            let request = try await Bridge.notifyChange(context: ctx, directory: directory) { _ in }
            try await Bridge.echo(context: ctx)
            // Closing the directory completes the request with STATUS_NOTIFY_CLEANUP.
            try await Bridge.close(context: ctx, file: directory)
            try await waitForReplies(ctx)
            #expect(try await !hasPendingRequests(ctx))

            try await Bridge.cancel(context: ctx, request: request)
            #expect(try await !hasQueuedRequests(ctx))
            try await Bridge.echo(context: ctx)
        }
    }
}

/// Services the context with echo requests until libsmb2 has no request waiting for a reply, or gives up.
private func waitForReplies(_ context: Bridge.Context) async throws {
    var attempts = 0
    while try await hasPendingRequests(context), attempts < 50 {
        try await Bridge.echo(context: context)
        attempts += 1
    }
}

/// Whether libsmb2 is waiting for replies to requests it has sent.
private func hasPendingRequests(_ context: Bridge.Context) async throws -> Bool {
    try await Bridge.perform(on: context) {
        context.raw.pointee.waitqueue != nil
    }
}

/// Whether libsmb2 has requests it has not sent yet.
private func hasQueuedRequests(_ context: Bridge.Context) async throws -> Bool {
    try await Bridge.perform(on: context) {
        context.raw.pointee.outqueue != nil
    }
}
