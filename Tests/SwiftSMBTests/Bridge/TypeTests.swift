//
// Part of SwiftSMB
// TypeTests.swift
//
// Licensed under LGPL v2.1
// Copyright its respective authors
//

@testable import SwiftSMB
import Darwin
import Foundation
import SMB2
import Testing

// MARK: - SMB.SMBStatus

struct SMBStatusTests {
    @Test("success severity is success") func successSeverityIsSuccess() {
        #expect(SMB.SMBStatus.success.severity == .success)
    }

    @Test("pending severity is success") func pendingSeverityIsSuccess() {
        // 0x0000_0103: bits 30-31 = 0b00 → success per NT status convention
        #expect(SMB.SMBStatus.pending.severity == .success)
    }

    @Test("no more files severity is warning") func noMoreFilesSeverityIsWarning() {
        // 0x8000_0006: bits 30-31 = 0b10 → warning
        #expect(SMB.SMBStatus.noMoreFiles.severity == .warning)
    }

    @Test("buffer overflow severity is warning") func bufferOverflowSeverityIsWarning() {
        // 0x8000_0005
        #expect(SMB.SMBStatus.bufferOverflow.severity == .warning)
    }

    @Test("unsuccessful severity is error") func unsuccessfulSeverityIsError() {
        // 0xC000_0001: bits 30-31 = 0b11 → error
        #expect(SMB.SMBStatus.unsuccessful.severity == .error)
    }

    @Test("no such file severity is error") func noSuchFileSeverityIsError() {
        #expect(SMB.SMBStatus.noSuchFile.severity == .error)
    }

    @Test("access denied severity is error") func accessDeniedSeverityIsError() {
        #expect(SMB.SMBStatus.accessDenied.severity == .error)
    }

    @Test("description contains hex") func descriptionContainsHex() {
        let desc = SMB.SMBStatus.success.description
        #expect(desc.contains("0x"))
        #expect(desc.contains("SMB2_STATUS_SUCCESS"))
    }

    @Test("name matches constant") func nameMatchesConstant() {
        #expect(SMB.SMBStatus.success.name == "SMB2_STATUS_SUCCESS")
        #expect(SMB.SMBStatus.noSuchFile.name == "SMB2_STATUS_NO_SUCH_FILE")
        #expect(SMB.SMBStatus.accessDenied.name == "SMB2_STATUS_ACCESS_DENIED")
        #expect(SMB.SMBStatus.logonFailure.name == "SMB2_STATUS_LOGON_FAILURE")
        #expect(SMB.SMBStatus.objectNameNotFound.name == "SMB2_STATUS_OBJECT_NAME_NOT_FOUND")
    }

    @Test("raw values are unique") func rawValuesAreUnique() {
        let values = SMB.SMBStatus.allCases.map(\.rawValue)
        let unique = Set(values)
        #expect(values.count == unique.count)
    }

    @Test("raw value round trips") func rawValueRoundTrips() {
        for status in SMB.SMBStatus.allCases {
            #expect(SMB.SMBStatus(rawValue: status.rawValue) == status)
        }
    }
}

// MARK: - SMB.SMBStatusSeverity

struct SMBStatusSeverityTests {
    @Test("raw values") func rawValues() {
        #expect(SMB.SMBStatusSeverity.success.rawValue == 0x0000_0000)
        #expect(SMB.SMBStatusSeverity.info.rawValue == 0x4000_0000)
        #expect(SMB.SMBStatusSeverity.warning.rawValue == 0x8000_0000)
        #expect(SMB.SMBStatusSeverity.error.rawValue == 0xC000_0000)
    }
}

// MARK: - SMB2NodeType

struct SMB2NodeTypeTests {
    // SMB2_TYPE_FILE = 0, SMB2_TYPE_DIRECTORY = 1, SMB2_TYPE_LINK = 2 (from libsmb2.h)

    @Test("file from raw value") func fileFromRawValue() {
        #expect(SMB2NodeType(rawValue: 0) == .file)
    }

    @Test("directory from raw value") func directoryFromRawValue() {
        #expect(SMB2NodeType(rawValue: 1) == .directory)
    }

    @Test("link from raw value") func linkFromRawValue() {
        #expect(SMB2NodeType(rawValue: 2) == .link)
    }

    @Test("unknown from unrecognized raw value") func unknownFromUnrecognizedRawValue() {
        let raw: UInt32 = 99
        if case let .unknown(value) = SMB2NodeType(rawValue: raw) {
            #expect(value == raw)
        }
        else {
            Issue.record("Expected .unknown for raw value \(raw)")
        }
    }
}

// MARK: - SMB2ShareKind

struct SMB2ShareKindTests {
    @Test("disk tree from raw value") func diskTreeFromRawValue() {
        #expect(SMB2ShareKind(rawValue: 0) == .diskTree)
    }

    @Test("print queue from raw value") func printQueueFromRawValue() {
        #expect(SMB2ShareKind(rawValue: 1) == .printQueue)
    }

    @Test("device from raw value") func deviceFromRawValue() {
        #expect(SMB2ShareKind(rawValue: 2) == .device)
    }

    @Test("ipc from raw value") func ipcFromRawValue() {
        #expect(SMB2ShareKind(rawValue: 3) == .ipc)
    }

    @Test("only lower two bits used for kind") func onlyLowerTwoBitsUsedForKind() {
        // rawValue=4 → 4&3=0 → diskTree
        #expect(SMB2ShareKind(rawValue: 4) == .diskTree)
        // rawValue=5 → 5&3=1 → printQueue
        #expect(SMB2ShareKind(rawValue: 5) == .printQueue)
        // rawValue=7 → 7&3=3 → ipc
        #expect(SMB2ShareKind(rawValue: 7) == .ipc)
    }
}

// MARK: - SMB2ShareAttributes

struct SMB2ShareAttributesTests {
    @Test("temporary flag") func temporaryFlag() {
        let attrs = SMB2ShareAttributes(rawShareType: 0x4000_0000)
        #expect(attrs.contains(.temporary))
        #expect(!attrs.contains(.hidden))
    }

    @Test("hidden flag") func hiddenFlag() {
        let attrs = SMB2ShareAttributes(rawShareType: 0x8000_0000)
        #expect(attrs.contains(.hidden))
        #expect(!attrs.contains(.temporary))
    }

    @Test("both flags") func bothFlags() {
        let attrs = SMB2ShareAttributes(rawShareType: 0xC000_0000)
        #expect(attrs.contains(.temporary))
        #expect(attrs.contains(.hidden))
    }

    @Test("no flags") func noFlags() {
        let attrs = SMB2ShareAttributes(rawShareType: 0x0000_0003)
        #expect(!attrs.contains(.temporary))
        #expect(!attrs.contains(.hidden))
    }

    @Test("share is hidden property") func shareIsHiddenProperty() {
        let hidden = SMB2Share(name: "test$", kind: .diskTree, attributes: [.hidden], remark: nil)
        #expect(hidden.isHidden)
        #expect(!hidden.isTemporary)
    }

    @Test("share is temporary property") func shareIsTemporaryProperty() {
        let temp = SMB2Share(name: "temp", kind: .diskTree, attributes: [.temporary], remark: nil)
        #expect(temp.isTemporary)
        #expect(!temp.isHidden)
    }
}

// MARK: - SMB2OpenFlags

struct SMB2OpenFlagsTests {
    @Test("read only raw value") func readOnlyRawValue() {
        let flags = SMB2OpenFlags(.readOnly)
        #expect(flags.rawValue == O_RDONLY)
    }

    @Test("write only raw value") func writeOnlyRawValue() {
        let flags = SMB2OpenFlags(.writeOnly)
        #expect(flags.rawValue == O_WRONLY)
    }

    @Test("read write raw value") func readWriteRawValue() {
        let flags = SMB2OpenFlags(.readWrite)
        #expect(flags.rawValue == O_RDWR)
    }

    @Test("create option") func createOption() {
        let flags = SMB2OpenFlags(.writeOnly, options: .create)
        #expect(flags.rawValue == (O_WRONLY | O_CREAT))
    }

    @Test("exclusive option") func exclusiveOption() {
        let flags = SMB2OpenFlags(.writeOnly, options: [.create, .exclusive])
        #expect(flags.rawValue == (O_WRONLY | O_CREAT | O_EXCL))
    }

    @Test("default is read only") func defaultIsReadOnly() {
        let flags = SMB2OpenFlags()
        #expect(flags.accessMode == .readOnly)
        #expect(flags.options == [])
    }
}

// MARK: - SMB2SecurityMode

struct SMB2SecurityModeTests {
    @Test("option set union") func optionSetUnion() {
        let mode: SMB2SecurityMode = [.signingEnabled, .signingRequired]
        #expect(mode.contains(.signingEnabled))
        #expect(mode.contains(.signingRequired))
    }

    @Test("signing enabled and required are distinct") func signingEnabledAndRequiredAreDistinct() {
        #expect(SMB2SecurityMode.signingEnabled != SMB2SecurityMode.signingRequired)
    }

    @Test("empty mode contains nothing") func emptyModeContainsNothing() {
        let mode = SMB2SecurityMode()
        #expect(!mode.contains(.signingEnabled))
        #expect(!mode.contains(.signingRequired))
    }
}

// MARK: - Int extension

struct IntExtensionTests {
    @Test func `zero converts`() throws {
        let result = try 0.asUInt32(operation: "test")
        #expect(result == 0)
    }

    @Test func `uint 32 max converts`() throws {
        let result = try Int(UInt32.max).asUInt32(operation: "test")
        #expect(result == UInt32.max)
    }

    @Test func `positive value converts`() throws {
        let result = try 1024.asUInt32(operation: "test")
        #expect(result == 1024)
    }

    @Test("negative throws") func negativeThrows() {
        #expect(throws: SMB.Error.self) {
            try (-1).asUInt32(operation: "test")
        }
    }

    @Test("int max throws on 64 bit") func intMaxThrowsOn64Bit() {
        // Int.max (9223372036854775807) exceeds UInt32.max on 64-bit platforms
        if Int.max > Int(UInt32.max) {
            #expect(throws: SMB.Error.self) {
                try Int.max.asUInt32(operation: "test")
            }
        }
    }

    @Test func `error message contains operation`() throws {
        do {
            _ = try (-5).asUInt32(operation: "my_operation")
            Issue.record("Expected error to be thrown")
        }
        catch let error as SMB.Error {
            #expect(error.operation == "my_operation")
        }
    }
}

// MARK: - Optional<String> extension

struct OptionalStringExtensionTests {
    @Test("nil calls body with nil pointer") func nilCallsBodyWithNilPointer() {
        let result: Bool = (nil as String?).withOptionalCString { ptr in
            ptr == nil
        }
        #expect(result)
    }

    @Test("non nil calls body with pointer") func nonNilCallsBodyWithPointer() {
        let result: Bool = ("hello" as String?).withOptionalCString { ptr in
            ptr != nil
        }
        #expect(result)
    }

    @Test("non nil passes correct string") func nonNilPassesCorrectString() {
        let result: String = ("hello" as String?).withOptionalCString { ptr in
            ptr.map(String.init(cString:)) ?? ""
        }
        #expect(result == "hello")
    }
}

// MARK: - SMB2AuthenticationMethod

struct SMB2AuthenticationMethodTests {
    @Test("cases are distinct") func casesAreDistinct() {
        #expect(SMB2AuthenticationMethod.automatic != .ntlmssp)
        #expect(SMB2AuthenticationMethod.automatic != .kerberos)
        #expect(SMB2AuthenticationMethod.ntlmssp != .kerberos)
    }

    @Test("automatic raw value is zero") func automaticRawValueIsZero() {
        #expect(SMB2AuthenticationMethod.automatic.rawValue == 0)
    }

    @Test("ntlmssp raw value is one") func ntlmsspRawValueIsOne() {
        #expect(SMB2AuthenticationMethod.ntlmssp.rawValue == 1)
    }

    @Test("kerberos raw value is two") func kerberosRawValueIsTwo() {
        #expect(SMB2AuthenticationMethod.kerberos.rawValue == 2)
    }
}

// MARK: - SMB2OpenAccessMode

struct SMB2OpenAccessModeTests {
    @Test("readOnly raw value is O_RDONLY") func readonlyRawValueIsO_rdonly() {
        #expect(SMB2OpenAccessMode.readOnly.rawValue == O_RDONLY)
    }

    @Test("writeOnly raw value is O_WRONLY") func writeonlyRawValueIsO_wronly() {
        #expect(SMB2OpenAccessMode.writeOnly.rawValue == O_WRONLY)
    }

    @Test("readWrite raw value is O_RDWR") func readwriteRawValueIsO_rdwr() {
        #expect(SMB2OpenAccessMode.readWrite.rawValue == O_RDWR)
    }
}

// MARK: - SMB2OpenOptions

struct SMB2OpenOptionsTests {
    @Test("synchronous raw value is O_SYNC") func synchronousRawValueIsO_sync() {
        #expect(SMB2OpenOptions.synchronous.rawValue == O_SYNC)
    }

    @Test("create raw value is O_CREAT") func createRawValueIsO_creat() {
        #expect(SMB2OpenOptions.create.rawValue == O_CREAT)
    }

    @Test("exclusive raw value is O_EXCL") func exclusiveRawValueIsO_excl() {
        #expect(SMB2OpenOptions.exclusive.rawValue == O_EXCL)
    }

    @Test("combined options raw value") func combinedOptionsRawValue() {
        let options: SMB2OpenOptions = [.create, .exclusive]
        #expect(options.rawValue == O_CREAT | O_EXCL)
    }
}

// MARK: - SMB2ShareEnumerationLevel

struct SMB2ShareEnumerationLevelTests {
    @Test("namesOnly raw value is SHARE_INFO_0") func namesonlyRawValueIsShare_info_0() {
        #expect(SMB2ShareEnumerationLevel.namesOnly.rawValue == SHARE_INFO_0)
    }

    @Test("detailed raw value is SHARE_INFO_1") func detailedRawValueIsShare_info_1() {
        #expect(SMB2ShareEnumerationLevel.detailed.rawValue == SHARE_INFO_1)
    }
}

// MARK: - SMB.Error

struct SMBErrorTests {
    @Test("contextCreationFailed has no operation") func contextcreationfailedHasNoOperation() {
        let error = SMB.Error.contextCreationFailed
        #expect(error.operation == nil)
        #expect(error.description == "Failed to create SMB context")
    }

    @Test("invalidArgument has operation and message") func invalidargumentHasOperationAndMessage() {
        let error = SMB.Error.invalidArgument(operation: "test_op", message: "bad input")
        #expect(error.operation == "test_op")
        #expect(error.message == "bad input")
        #expect(error.description.contains("Invalid argument"))
        #expect(error.description.contains("test_op"))
        #expect(error.description.contains("bad input"))
    }

    @Test("posix error has operation") func posixErrorHasOperation() {
        let error = SMB.Error.posix(code: POSIXErrorCode.EPERM.rawValue, operation: "smb2_open", message: "detail")
        #expect(error.operation == "smb2_open")
        #expect(error.posixErrorLocalizedDescription == POSIXError(.EPERM).localizedDescription)
        #expect(error.description.contains("POSIX error"))
        #expect(error.description.contains(POSIXError(.EPERM).localizedDescription))
        #expect(error.description.contains("smb2_open"))
    }

    @Test("unknown error has operation") func unknownErrorHasOperation() {
        let error = SMB.Error.unknown(operation: "smb2_connect", message: "")
        #expect(error.operation == "smb2_connect")
        #expect(error.description.contains("Unknown SMB error"))
    }

    @Test("ntStatus error has operation") func ntstatusErrorHasOperation() {
        let error = SMB.Error.ntStatus(.noSuchFile, posixCode: nil, operation: "smb2_stat", message: "")
        #expect(error.operation == "smb2_stat")
        #expect(error.description.contains("SMB2_STATUS_NO_SUCH_FILE"))
    }
}

// MARK: - Path validation

struct SMBPathValidationTests {
    @Test("validates share relative paths using PathWorks") func validatesShareRelativePathsUsingPathworks() throws {
        #expect(try SMB.validatePath("dir/file.txt", operation: "test") == "dir/file.txt")
        #expect(try SMB.validatePath("/dir/file.txt", operation: "test") == "dir/file.txt")
        #expect(try SMB.validatePath("//dir/file.txt", operation: "test") == "dir/file.txt")
        #expect(try SMB.validatePath("", operation: "test", allowRoot: true) == "")
        #expect(try SMB.validatePath("/", operation: "test", allowRoot: true) == "")

        #expect(throws: SMB.Error.self) {
            try SMB.validatePath("dir/bad:name.txt", operation: "test")
        }
        #expect(throws: SMB.Error.self) {
            try SMB.validatePath("dir/CON.txt", operation: "test")
        }
        #expect(throws: SMB.Error.self) {
            try SMB.validatePath("", operation: "test")
        }
    }

    @Test("validates share names using PathWorks") func validatesShareNamesUsingPathworks() throws {
        try SMB.validateShareName("public", operation: "test")
        try SMB.validateShareName("IPC$", operation: "test")

        #expect(throws: SMB.Error.self) {
            try SMB.validateShareName("", operation: "test")
        }
        #expect(throws: SMB.Error.self) {
            try SMB.validateShareName("public/private", operation: "test")
        }
        #expect(throws: SMB.Error.self) {
            try SMB.validateShareName("bad:name", operation: "test")
        }
    }

    @Test("String removes leading SMB path separators") func stringRemovesLeadingSMBPathSeparators() {
        #expect("dir/file.txt".smbShareRelativePath == "dir/file.txt")
        #expect("/dir/file.txt".smbShareRelativePath == "dir/file.txt")
        #expect("//dir/file.txt".smbShareRelativePath == "dir/file.txt")
        #expect("/".smbShareRelativePath == "")
    }
}
