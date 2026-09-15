//
// Part of SwiftSMB
// ShareTests.swift
//
// Licensed under Apache License v2.0
// Copyright its respective authors
//

@testable import SwiftSMB
import Testing

@Suite(.tags(.integration))
struct ShareTests {
    @Test("public share is listed") func publicShareIsListed() async throws {
        try await withFreshContext { ctx in
            let shares = try await Bridge.listShares(context: ctx, server: testServerHost)
            #expect(shares.contains { $0.name == TestShare.public })
        }
    }

    @Test("private share is listed") func privateShareIsListed() async throws {
        try await withFreshContext { ctx in
            let shares = try await Bridge.listShares(context: ctx, server: testServerHost)
            #expect(shares.contains { $0.name == TestShare.private })
        }
    }

    @Test("readonly share is listed") func readonlyShareIsListed() async throws {
        try await withFreshContext { ctx in
            let shares = try await Bridge.listShares(context: ctx, server: testServerHost)
            #expect(shares.contains { $0.name == TestShare.readonly })
        }
    }

    @Test("hidden share is not enumerated by default") func hiddenShareIsNotEnumeratedByDefault() async throws {
        // Samba excludes browseable=no shares from NetShareEnum entirely; the listShares filter sees them as absent,
        // not as SHARE_TYPE_HIDDEN.
        try await withFreshContext { ctx in
            let shares = try await Bridge.listShares(context: ctx, server: testServerHost)
            #expect(!shares.contains { $0.name == TestShare.hidden })
        }
    }

    @Test("all listed shares are disk trees") func allListedSharesAreDiskTrees() async throws {
        try await withFreshContext { ctx in
            let shares = try await Bridge.listShares(context: ctx, server: testServerHost)
            for share in shares {
                #expect(share.kind == .diskTree, "Share \(share.name) should be a disk tree")
            }
        }
    }

    @Test("public share is not hidden") func publicShareIsNotHidden() async throws {
        try await withFreshContext { ctx in
            let shares = try await Bridge.listShares(context: ctx, server: testServerHost)
            let publicShare = try #require(shares.first { $0.name == TestShare.public })
            #expect(!publicShare.isHidden)
        }
    }

    @Test("share enumeration returns at least three shares") func shareEnumerationReturnsAtLeastThreeShares(
    ) async throws {
        try await withFreshContext { ctx in
            let shares = try await Bridge.listShares(context: ctx, server: testServerHost)
            #expect(shares.count >= 3)
        }
    }

    @Test("shares have non empty names") func sharesHaveNonEmptyNames() async throws {
        try await withFreshContext { ctx in
            let shares = try await Bridge.listShares(context: ctx, server: testServerHost)
            for share in shares {
                #expect(!share.name.isEmpty)
            }
        }
    }

    @Test(
        "names only enumeration returns shares without kind or remark"
    ) func namesOnlyEnumerationReturnsSharesWithoutKindOrRemark() async throws {
        try await withFreshContext { ctx in
            try await Bridge.setSecurityMode(.signingEnabled, on: ctx)
            try await Bridge.connectShare(context: ctx, server: testServerHost, share: "IPC$")
            let shares = try await Bridge.listSharesOnConnectedIPCShare(context: ctx, level: .namesOnly)
            try await Bridge.disconnectShare(context: ctx)
            #expect(shares.count >= 3)
            for share in shares {
                #expect(share.kind == nil)
                #expect(share.remark == nil)
            }
        }
    }

    @Test("detailed enumeration returns shares with kind") func detailedEnumerationReturnsSharesWithKind() async throws {
        try await withFreshContext { ctx in
            try await Bridge.setSecurityMode(.signingEnabled, on: ctx)
            try await Bridge.connectShare(context: ctx, server: testServerHost, share: "IPC$")
            let shares = try await Bridge.listSharesOnConnectedIPCShare(context: ctx, level: .detailed)
            try await Bridge.disconnectShare(context: ctx)
            #expect(shares.count >= 3)
            for share in shares {
                #expect(share.kind != nil)
            }
        }
    }

    @Test(
        "share remark from detailed enumeration is not nil for public share"
    ) func shareRemarkFromDetailedEnumerationIsNotNilForPublicShare() async throws {
        try await withFreshContext { ctx in
            let shares = try await Bridge.listShares(context: ctx, server: testServerHost)
            let publicShare = try #require(shares.first { $0.name == TestShare.public })
            _ = publicShare.remark
        }
    }
}
