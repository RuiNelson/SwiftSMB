//
// Part of SwiftSMB
// CookbookSupport.swift
//
// Licensed under LGPL v2.1
// Copyright its respective authors
//

import Foundation
import SwiftSMB

let cookbookServerHost = "localhost:44445"
let cookbookServer = SMB.Server(host: cookbookServerHost)
let cookbookCredentials = SMB.Credentials(user: "Anna", password: "1987")
let cookbookShare = "Documents"

func cookbookConnection() throws -> SMB.Connection {
    try SMB.connect(
        server: cookbookServer,
        credentials: cookbookCredentials,
        share: cookbookShare,
    )
}

func cookbookTemporaryFileURL() throws -> URL {
    let url = FileManager.default.temporaryDirectory.appendingPathComponent(UUID().uuidString)
    FileManager.default.createFile(atPath: url.path, contents: nil)
    return url
}
