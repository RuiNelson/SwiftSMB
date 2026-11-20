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
    typealias Validation = SMB.Configuration.PathValidation

    static let allValidations = Validation.allCases

    static func validate(_ path: String, _ validation: Validation) throws -> String {
        try SMB.validatePath(path, operation: .smb2Open, validation: validation)
    }

    /// Whether the two strings have the same Unicode scalars. `String.==` treats canonically equivalent spellings, such
    /// as NFC and NFD, as equal, so it cannot show that a path kept its spelling.
    static func sameScalars(_ lhs: String, _ rhs: String) -> Bool {
        lhs.unicodeScalars.elementsEqual(rhs.unicodeScalars)
    }

    static func rejection(_ component: String) -> SMB.Error {
        .invalidArgument(cause: .invalidPathComponent(component), onOperation: .smb2Open)
    }

    @Test("paths reject NUL and ASCII control characters", arguments: Array(UInt32(0) ... 31), allValidations)
    func rejectsControlCharacters(_ scalar: UInt32, _ validation: Validation) throws {
        let character = try String(#require(Unicode.Scalar(scalar)))
        let path = "dir/file\(character)suffix.txt"

        #expect(throws: SMB.Error.self) {
            try SMB.validatePath(path, operation: .smb2Unlink, validation: validation)
        }
    }

    @Test(
        "paths reject the characters MS-FSCC forbids in filenames",
        arguments: [#"""#, #"\"#, ":", "|", "<", ">", "*", "?"],
        allValidations
    )
    func rejectsForbiddenCharacters(_ character: String, _ validation: Validation) {
        let component = "a\(character)b"
        #expect(throws: Self.rejection(component)) {
            try Self.validate("dir/" + component, validation)
        }
    }

    @Test(
        "paths that leave the share are rejected, with or without a leading slash",
        arguments: ["../dir", "/../dir", "..", "/..", "a/../../b", "/a/../../b", "a/b/../../..", "./../a"],
        allValidations
    )
    func rejectsParentOfRoot(_ path: String, _ validation: Validation) {
        #expect(throws: Self.rejection("..")) {
            try Self.validate(path, validation)
        }
        #expect(throws: Self.rejection("..")) {
            try SMB.validatePath(path, operation: .smb2Open, allowRoot: true, validation: validation)
        }
    }

    @Test("a path that resolves to the share root is the root", arguments: ["a/..", "/a/b/../..", ".", "/", "//./"])
    func resolvesToRoot(_ path: String) throws {
        #expect(try SMB.validatePath(path, operation: .smb2Open, allowRoot: true, validation: .smb) == "")
        #expect(throws: SMB.Error.invalidArgument(cause: .pathMustNotBeEmpty, onOperation: .smb2Open)) {
            try Self.validate(path, .smb)
        }
    }

    /// Scalars that join the `/` before them into one `Character`: a combining mark, a zero-width joiner, a variation
    /// selector, an emoji modifier and a spacing mark.
    @Test(
        "paths split at every slash, even one that forms a Character with the next scalar",
        arguments: ["\u{301}", "\u{200D}", "\u{FE0F}", "\u{1F3FB}", "\u{93F}"],
        allValidations
    )
    func splitsAtSlashBeforeExtendingScalar(_ scalar: String, _ validation: Validation) throws {
        let path = "dir/\(scalar)x"
        #expect(path.split(separator: "/").count == 1, "the test needs a slash that a Character split does not cut")

        let validated = try Self.validate(path, validation)
        #expect(Self.sameScalars(validated, path))
        #expect(validated.unicodeScalars.split(separator: "/").count == 2)
    }

    @Test("paths split at a slash that follows a prepended concatenation mark", arguments: allValidations)
    func splitsAtSlashAfterPrependScalar(_ validation: Validation) throws {
        let path = "a\u{600}/b"
        #expect(path.split(separator: "/").count == 1)
        #expect(try Self.sameScalars(Self.validate(path, validation), path))
    }

    @Test("dot components next to extending scalars are names, not dot directories")
    func dotWithCombiningMarkIsAName() throws {
        let path = "dir/.\u{301}/..\u{301}"
        #expect(try Self.sameScalars(Self.validate(path, .smb), path))
    }

    @Test("dot components are resolved", arguments: allValidations)
    func resolvesDotComponents(_ validation: Validation) throws {
        #expect(try Self.validate("./a/./b/../c/.", validation) == "a/c")
    }

    @Test("safe Unicode filenames retain their spelling", arguments: [
        "資料/cafe\u{301}.txt",
        "資料/caf\u{E9}.txt",
        "\u{1100}\u{1161}/\u{AC00}",
        "/leading/cafe\u{301}",
    ], allValidations)
    func preservesUnicodePaths(_ path: String, _ validation: Validation) throws {
        let expected = path.hasPrefix("/") ? String(path.dropFirst()) : path
        #expect(try Self.sameScalars(Self.validate(path, validation), expected))
    }

    @Test("paths enforce the 255 UTF-16 code unit filename limit", arguments: [
        String(repeating: "a", count: 256),
        String(repeating: "😀", count: 128),
    ], allValidations)
    func rejectsOverlongComponents(_ filename: String, _ validation: Validation) {
        #expect(throws: Self.rejection(filename)) {
            try Self.validate("dir/" + filename, validation)
        }
    }

    @Test("paths longer than 32,760 UTF-16 code units are rejected", arguments: allValidations)
    func rejectsOverlongPaths(_ validation: Validation) throws {
        let component = String(repeating: "a", count: 99)
        let fitting = Array(repeating: component, count: 327).joined(separator: "/") + "/" + String(
            repeating: "b",
            count: 60
        )
        #expect(fitting.utf16.count == 32760)
        #expect(try Self.validate(fitting, validation) == fitting)

        let overlong = fitting + "b"
        #expect(throws: SMB.Error.invalidArgument(cause: .pathTooLong(32761), onOperation: .smb2Open)) {
            try Self.validate(overlong, validation)
        }
    }

    /// A path component and whether each level accepts it.
    struct LevelCase: CustomTestStringConvertible, Sendable {
        let component: String
        let smb: Bool
        let ntfs: Bool
        let unix: Bool

        func accepts(_ validation: Validation) -> Bool {
            switch validation {
            case .smb: smb
            case .ntfsOverSMB: ntfs
            case .unixOverSMB: unix
            }
        }

        var testDescription: String {
            let shown = component
                .count > 24 ?
                "\(component.prefix(8))… (\(component.utf16.count) UTF-16, \(component.utf8.count) UTF-8)" : component
            return "'\(shown)' smb: \(smb) ntfs: \(ntfs) unix: \(unix)"
        }
    }

    static func both(_ component: String) -> LevelCase {
        LevelCase(component: component, smb: true, ntfs: true, unix: true)
    }

    static func ntfsRejects(_ component: String) -> LevelCase {
        LevelCase(component: component, smb: true, ntfs: false, unix: true)
    }

    static func unixRejects(_ component: String) -> LevelCase {
        LevelCase(component: component, smb: true, ntfs: true, unix: false)
    }

    static func allReject(_ component: String) -> LevelCase {
        LevelCase(component: component, smb: false, ntfs: false, unix: false)
    }

    static let levelCases: [LevelCase] = [
        // Trailing periods and spaces: NTFS strips them, Unix keeps them as part of the name.
        ntfsRejects("file."),
        ntfsRejects("file "),
        ntfsRejects("file..."),
        ntfsRejects("file. "),
        ntfsRejects("..."),
        ntfsRejects("dir.name."),
        // Reserved device names, in any case and with any extension (issue #12).
        ntfsRejects("CON"),
        ntfsRejects("con"),
        ntfsRejects("Con.txt"),
        ntfsRejects("PRN"),
        ntfsRejects("AUX"),
        ntfsRejects("NUL"),
        ntfsRejects("nul.txt"),
        ntfsRejects("COM1"),
        ntfsRejects("com9.log"),
        ntfsRejects("LPT1"),
        ntfsRejects("Lpt9.tar.gz"),
        ntfsRejects("COM\u{B9}"),
        ntfsRejects("lpt\u{B3}.log"),
        ntfsRejects("CONIN$"),
        ntfsRejects("conout$.txt"),
        ntfsRejects("NUL .txt"),
        // Names that only look reserved.
        both("CONSOLE"),
        both("xCON"),
        both("COM10"),
        both("COM0"),
        both("LPT"),
        both("CON_backup"),
        both("NULL.txt"),
        // Leading periods and spaces are fine everywhere.
        both(".hidden"),
        both(" leading space"),
        both("file.txt"),
        // UTF-16 vs UTF-8 length: NTFS counts UTF-16 code units, Unix counts UTF-8 bytes.
        both(String(repeating: "a", count: 255)),
        both(String(repeating: "音", count: 85)),
        unixRejects(String(repeating: "音", count: 86)),
        unixRejects(String(repeating: "é", count: 128)),
        both(String(repeating: "😀", count: 63)),
        unixRejects(String(repeating: "😀", count: 64)),
        allReject(String(repeating: "a", count: 256)),
        allReject(String(repeating: "e\u{301}", count: 128)),
        // Forbidden by the protocol itself.
        allReject("a:b"),
        allReject("a*b"),
        allReject("a?b"),
        allReject("a|b"),
    ]

    @Test("each level accepts or rejects a component", arguments: levelCases, allValidations)
    func levelAcceptsOrRejects(_ levelCase: LevelCase, _ validation: Validation) throws {
        let component = levelCase.component
        let path = "dir/\(component)/sample.mp3"

        if levelCase.accepts(validation) {
            #expect(try Self.sameScalars(Self.validate(path, validation), path))
        }
        else {
            #expect(throws: Self.rejection(component)) {
                try Self.validate(path, validation)
            }
        }
    }

    @Test("the last component is checked like any other", arguments: levelCases, allValidations)
    func levelChecksLastComponent(_ levelCase: LevelCase, _ validation: Validation) throws {
        let path = "dir/" + levelCase.component

        if levelCase.accepts(validation) {
            #expect(try Self.sameScalars(Self.validate(path, validation), path))
        }
        else {
            #expect(throws: Self.rejection(levelCase.component)) {
                try Self.validate(path, validation)
            }
        }
    }
}
