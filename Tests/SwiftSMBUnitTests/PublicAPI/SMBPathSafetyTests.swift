//
// Part of SwiftSMB
// SMBPathSafetyTests.swift
//
// Licensed under Apache License v2.0
// Copyright its respective authors
//

@testable import SwiftSMB
import Testing

struct SMBPathSafetyTests {
    @Test("paths reject NUL and ASCII control characters", arguments: Array(UInt32(0) ... 31))
    func rejectsControlCharacters(_ scalar: UInt32) throws {
        let character = try String(#require(Unicode.Scalar(scalar)))
        let path = "dir/file\(character)suffix.txt"

        #expect(throws: SMB.Error.self) {
            try SMB.validatePath(path, operation: .smb2Unlink)
        }
    }

    @Test("safe Unicode filenames retain their spelling")
    func preservesUnicodePaths() throws {
        let path = "資料/cafe\u{301}.txt"
        #expect(try SMB.validatePath(path, operation: .smb2Open) == path)
    }

    @Test("paths enforce the NTFS UTF-16 filename limit", arguments: [
        String(repeating: "a", count: 256),
        String(repeating: "😀", count: 128),
    ])
    func rejectsOverlongComponents(_ filename: String) {
        #expect(throws: SMB.Error.invalidArgument(cause: .invalidPathComponent(filename), onOperation: .smb2Open)) {
            try SMB.validatePath("dir/" + filename, operation: .smb2Open)
        }
    }
}
