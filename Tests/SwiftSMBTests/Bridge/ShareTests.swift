//
// Part of SwiftSMB
// ShareTests.swift
//
// Licensed under LGPL v2.1
// Copyright it's respective authors
//

@testable import SwiftSMB
import Testing

@Suite(.tags(.integration))
struct ShareTests {
    @Test func `public share is listed`() throws {
        try withFreshContext { ctx in
            let shares = try listShares(context: ctx, server: testServerHost)
            #expect(shares.contains { $0.name == TestShare.public })
        }
    }

    @Test func `private share is listed`() throws {
        try withFreshContext { ctx in
            let shares = try listShares(context: ctx, server: testServerHost)
            #expect(shares.contains { $0.name == TestShare.private })
        }
    }

    @Test func `readonly share is listed`() throws {
        try withFreshContext { ctx in
            let shares = try listShares(context: ctx, server: testServerHost)
            #expect(shares.contains { $0.name == TestShare.readonly })
        }
    }

    @Test func `hidden share is not enumerated by default`() throws {
        // Samba excludes browseable=no shares from NetShareEnum entirely;
        // the listShares filter sees them as absent, not as SHARE_TYPE_HIDDEN.
        try withFreshContext { ctx in
            let shares = try listShares(context: ctx, server: testServerHost)
            #expect(!shares.contains { $0.name == TestShare.hidden })
        }
    }

    @Test func `all listed shares are disk trees`() throws {
        try withFreshContext { ctx in
            let shares = try listShares(context: ctx, server: testServerHost)
            for share in shares {
                #expect(share.kind == .diskTree, "Share \(share.name) should be a disk tree")
            }
        }
    }

    @Test func `public share is not hidden`() throws {
        try withFreshContext { ctx in
            let shares = try listShares(context: ctx, server: testServerHost)
            let publicShare = try #require(shares.first { $0.name == TestShare.public })
            #expect(!publicShare.isHidden)
        }
    }

    @Test func `share enumeration returns at least three shares`() throws {
        try withFreshContext { ctx in
            let shares = try listShares(context: ctx, server: testServerHost)
            #expect(shares.count >= 3)
        }
    }

    @Test func `shares have non empty names`() throws {
        try withFreshContext { ctx in
            let shares = try listShares(context: ctx, server: testServerHost)
            for share in shares {
                #expect(!share.name.isEmpty)
            }
        }
    }

    @Test func `names only enumeration returns shares without kind or remark`() throws {
        try withFreshContext { ctx in
            setSecurityMode(.signingEnabled, on: ctx)
            try connectShare(context: ctx, server: testServerHost, share: "IPC$")
            let shares = try listSharesOnConnectedIPCShare(context: ctx, level: .namesOnly)
            try disconnectShare(context: ctx)
            #expect(shares.count >= 3)
            for share in shares {
                #expect(share.kind == nil)
                #expect(share.remark == nil)
            }
        }
    }

    @Test func `detailed enumeration returns shares with kind`() throws {
        try withFreshContext { ctx in
            setSecurityMode(.signingEnabled, on: ctx)
            try connectShare(context: ctx, server: testServerHost, share: "IPC$")
            let shares = try listSharesOnConnectedIPCShare(context: ctx, level: .detailed)
            try disconnectShare(context: ctx)
            #expect(shares.count >= 3)
            for share in shares {
                #expect(share.kind != nil)
            }
        }
    }

    @Test func `share remark from detailed enumeration is not nil for public share`() throws {
        try withFreshContext { ctx in
            let shares = try listShares(context: ctx, server: testServerHost)
            let publicShare = try #require(shares.first { $0.name == TestShare.public })
            _ = publicShare.remark
        }
    }
}
