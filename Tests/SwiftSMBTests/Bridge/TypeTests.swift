//
// Part of SwiftSMB
// TypeTests.swift
//
// Licensed under LGPL v2.1
// Copyright it's respective authors
//

@testable import SwiftSMB
import Darwin
import Foundation
import SMB2
import Testing

// MARK: - SMB2Status

struct SMB2StatusTests {
    @Test func `success severity is success`() {
        #expect(SMB2Status.success.severity == .success)
    }

    @Test func `pending severity is success`() {
        // 0x0000_0103: bits 30-31 = 0b00 → success per NT status convention
        #expect(SMB2Status.pending.severity == .success)
    }

    @Test func `no more files severity is warning`() {
        // 0x8000_0006: bits 30-31 = 0b10 → warning
        #expect(SMB2Status.noMoreFiles.severity == .warning)
    }

    @Test func `buffer overflow severity is warning`() {
        // 0x8000_0005
        #expect(SMB2Status.bufferOverflow.severity == .warning)
    }

    @Test func `unsuccessful severity is error`() {
        // 0xC000_0001: bits 30-31 = 0b11 → error
        #expect(SMB2Status.unsuccessful.severity == .error)
    }

    @Test func `no such file severity is error`() {
        #expect(SMB2Status.noSuchFile.severity == .error)
    }

    @Test func `access denied severity is error`() {
        #expect(SMB2Status.accessDenied.severity == .error)
    }

    @Test func `description contains hex`() {
        let desc = SMB2Status.success.description
        #expect(desc.contains("0x"))
        #expect(desc.contains("SMB2_STATUS_SUCCESS"))
    }

    @Test func `name matches constant`() {
        #expect(SMB2Status.success.name == "SMB2_STATUS_SUCCESS")
        #expect(SMB2Status.noSuchFile.name == "SMB2_STATUS_NO_SUCH_FILE")
        #expect(SMB2Status.accessDenied.name == "SMB2_STATUS_ACCESS_DENIED")
        #expect(SMB2Status.logonFailure.name == "SMB2_STATUS_LOGON_FAILURE")
        #expect(SMB2Status.objectNameNotFound.name == "SMB2_STATUS_OBJECT_NAME_NOT_FOUND")
    }

    @Test func `raw values are unique`() {
        let values = SMB2Status.allCases.map(\.rawValue)
        let unique = Set(values)
        #expect(values.count == unique.count)
    }

    @Test func `raw value round trips`() {
        for status in SMB2Status.allCases {
            #expect(SMB2Status(rawValue: status.rawValue) == status)
        }
    }
}

// MARK: - SMB2StatusSeverity

struct SMB2StatusSeverityTests {
    @Test func `raw values`() {
        #expect(SMB2StatusSeverity.success.rawValue == 0x0000_0000)
        #expect(SMB2StatusSeverity.info.rawValue == 0x4000_0000)
        #expect(SMB2StatusSeverity.warning.rawValue == 0x8000_0000)
        #expect(SMB2StatusSeverity.error.rawValue == 0xC000_0000)
    }
}

// MARK: - SMB2NodeType

struct SMB2NodeTypeTests {
    // SMB2_TYPE_FILE = 0, SMB2_TYPE_DIRECTORY = 1, SMB2_TYPE_LINK = 2 (from libsmb2.h)

    @Test func `file from raw value`() {
        #expect(SMB2NodeType(rawValue: 0) == .file)
    }

    @Test func `directory from raw value`() {
        #expect(SMB2NodeType(rawValue: 1) == .directory)
    }

    @Test func `link from raw value`() {
        #expect(SMB2NodeType(rawValue: 2) == .link)
    }

    @Test func `unknown from unrecognized raw value`() {
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
    @Test func `disk tree from raw value`() {
        #expect(SMB2ShareKind(rawValue: 0) == .diskTree)
    }

    @Test func `print queue from raw value`() {
        #expect(SMB2ShareKind(rawValue: 1) == .printQueue)
    }

    @Test func `device from raw value`() {
        #expect(SMB2ShareKind(rawValue: 2) == .device)
    }

    @Test func `ipc from raw value`() {
        #expect(SMB2ShareKind(rawValue: 3) == .ipc)
    }

    @Test func `only lower two bits used for kind`() {
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
    @Test func `temporary flag`() {
        let attrs = SMB2ShareAttributes(rawShareType: 0x4000_0000)
        #expect(attrs.contains(.temporary))
        #expect(!attrs.contains(.hidden))
    }

    @Test func `hidden flag`() {
        let attrs = SMB2ShareAttributes(rawShareType: 0x8000_0000)
        #expect(attrs.contains(.hidden))
        #expect(!attrs.contains(.temporary))
    }

    @Test func `both flags`() {
        let attrs = SMB2ShareAttributes(rawShareType: 0xC000_0000)
        #expect(attrs.contains(.temporary))
        #expect(attrs.contains(.hidden))
    }

    @Test func `no flags`() {
        let attrs = SMB2ShareAttributes(rawShareType: 0x0000_0003)
        #expect(!attrs.contains(.temporary))
        #expect(!attrs.contains(.hidden))
    }

    @Test func `share is hidden property`() {
        let hidden = SMB2Share(name: "test$", kind: .diskTree, attributes: [.hidden], remark: nil)
        #expect(hidden.isHidden)
        #expect(!hidden.isTemporary)
    }

    @Test func `share is temporary property`() {
        let temp = SMB2Share(name: "temp", kind: .diskTree, attributes: [.temporary], remark: nil)
        #expect(temp.isTemporary)
        #expect(!temp.isHidden)
    }
}

// MARK: - SMB2OpenFlags

struct SMB2OpenFlagsTests {
    @Test func `read only raw value`() {
        let flags = SMB2OpenFlags(.readOnly)
        #expect(flags.rawValue == O_RDONLY)
    }

    @Test func `write only raw value`() {
        let flags = SMB2OpenFlags(.writeOnly)
        #expect(flags.rawValue == O_WRONLY)
    }

    @Test func `read write raw value`() {
        let flags = SMB2OpenFlags(.readWrite)
        #expect(flags.rawValue == O_RDWR)
    }

    @Test func `create option`() {
        let flags = SMB2OpenFlags(.writeOnly, options: .create)
        #expect(flags.rawValue == (O_WRONLY | O_CREAT))
    }

    @Test func `exclusive option`() {
        let flags = SMB2OpenFlags(.writeOnly, options: [.create, .exclusive])
        #expect(flags.rawValue == (O_WRONLY | O_CREAT | O_EXCL))
    }

    @Test func `default is read only`() {
        let flags = SMB2OpenFlags()
        #expect(flags.accessMode == .readOnly)
        #expect(flags.options == [])
    }
}

// MARK: - SMB2SecurityMode

struct SMB2SecurityModeTests {
    @Test func `option set union`() {
        let mode: SMB2SecurityMode = [.signingEnabled, .signingRequired]
        #expect(mode.contains(.signingEnabled))
        #expect(mode.contains(.signingRequired))
    }

    @Test func `signing enabled and required are distinct`() {
        #expect(SMB2SecurityMode.signingEnabled != SMB2SecurityMode.signingRequired)
    }

    @Test func `empty mode contains nothing`() {
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

    @Test func `negative throws`() {
        #expect(throws: SMB2Error.self) {
            try (-1).asUInt32(operation: "test")
        }
    }

    @Test func `int max throws on 64 bit`() {
        // Int.max (9223372036854775807) exceeds UInt32.max on 64-bit platforms
        if Int.max > Int(UInt32.max) {
            #expect(throws: SMB2Error.self) {
                try Int.max.asUInt32(operation: "test")
            }
        }
    }

    @Test func `error message contains operation`() throws {
        do {
            _ = try (-5).asUInt32(operation: "my_operation")
            Issue.record("Expected error to be thrown")
        }
        catch let error as SMB2Error {
            #expect(error.context?.operation == "my_operation")
        }
    }
}

// MARK: - Optional<String> extension

struct OptionalStringExtensionTests {
    @Test func `nil calls body with nil pointer`() {
        let result: Bool = (nil as String?).withOptionalCString { ptr in
            ptr == nil
        }
        #expect(result)
    }

    @Test func `non nil calls body with pointer`() {
        let result: Bool = ("hello" as String?).withOptionalCString { ptr in
            ptr != nil
        }
        #expect(result)
    }

    @Test func `non nil passes correct string`() {
        let result: String = ("hello" as String?).withOptionalCString { ptr in
            ptr.map(String.init(cString:)) ?? ""
        }
        #expect(result == "hello")
    }
}

// MARK: - SMB2AuthenticationMethod

struct SMB2AuthenticationMethodTests {
    @Test func `cases are distinct`() {
        #expect(SMB2AuthenticationMethod.automatic != .ntlmssp)
        #expect(SMB2AuthenticationMethod.automatic != .kerberos)
        #expect(SMB2AuthenticationMethod.ntlmssp != .kerberos)
    }

    @Test func `automatic raw value is zero`() {
        #expect(SMB2AuthenticationMethod.automatic.rawValue == 0)
    }

    @Test func `ntlmssp raw value is one`() {
        #expect(SMB2AuthenticationMethod.ntlmssp.rawValue == 1)
    }

    @Test func `kerberos raw value is two`() {
        #expect(SMB2AuthenticationMethod.kerberos.rawValue == 2)
    }
}

// MARK: - SMB2OpenAccessMode

struct SMB2OpenAccessModeTests {
    @Test func `readOnly raw value is O_RDONLY`() {
        #expect(SMB2OpenAccessMode.readOnly.rawValue == O_RDONLY)
    }

    @Test func `writeOnly raw value is O_WRONLY`() {
        #expect(SMB2OpenAccessMode.writeOnly.rawValue == O_WRONLY)
    }

    @Test func `readWrite raw value is O_RDWR`() {
        #expect(SMB2OpenAccessMode.readWrite.rawValue == O_RDWR)
    }
}

// MARK: - SMB2OpenOptions

struct SMB2OpenOptionsTests {
    @Test func `synchronous raw value is O_SYNC`() {
        #expect(SMB2OpenOptions.synchronous.rawValue == O_SYNC)
    }

    @Test func `create raw value is O_CREAT`() {
        #expect(SMB2OpenOptions.create.rawValue == O_CREAT)
    }

    @Test func `exclusive raw value is O_EXCL`() {
        #expect(SMB2OpenOptions.exclusive.rawValue == O_EXCL)
    }

    @Test func `combined options raw value`() {
        let options: SMB2OpenOptions = [.create, .exclusive]
        #expect(options.rawValue == O_CREAT | O_EXCL)
    }
}

// MARK: - SMB2ShareEnumerationLevel

struct SMB2ShareEnumerationLevelTests {
    @Test func `namesOnly raw value is SHARE_INFO_0`() {
        #expect(SMB2ShareEnumerationLevel.namesOnly.rawValue == SHARE_INFO_0)
    }

    @Test func `detailed raw value is SHARE_INFO_1`() {
        #expect(SMB2ShareEnumerationLevel.detailed.rawValue == SHARE_INFO_1)
    }
}

// MARK: - SMB2Error

struct SMB2ErrorTests {
    @Test func `contextCreationFailed has no context`() {
        let error = SMB2Error.contextCreationFailed
        #expect(error.context == nil)
        #expect(error.description == "Failed to create SMB2 context")
    }

    @Test func `invalidArgument has context`() {
        let ctx = SMB2ErrorContext(operation: "test_op", message: "bad input")
        let error = SMB2Error.invalidArgument(ctx)
        #expect(error.context?.operation == "test_op")
        #expect(error.context?.message == "bad input")
        #expect(error.description.contains("Invalid argument"))
        #expect(error.description.contains("test_op"))
        #expect(error.description.contains("bad input"))
    }

    @Test func `posix error has context`() {
        let ctx = SMB2ErrorContext(operation: "smb2_open", message: "detail")
        let error = SMB2Error.posix(POSIXError(.EPERM), context: ctx)
        #expect(error.context?.operation == "smb2_open")
        #expect(error.description.contains("POSIX error"))
        #expect(error.description.contains("smb2_open"))
    }

    @Test func `unknown error has context`() {
        let ctx = SMB2ErrorContext(operation: "smb2_connect", message: "")
        let error = SMB2Error.unknown(ctx)
        #expect(error.context?.operation == "smb2_connect")
        #expect(error.description.contains("Unknown SMB2 error"))
    }

    @Test func `ntStatus error has context`() {
        let ctx = SMB2ErrorContext(operation: "smb2_stat", message: "")
        let error = SMB2Error.ntStatus(.noSuchFile, posixCode: nil, context: ctx)
        #expect(error.context?.operation == "smb2_stat")
        #expect(error.description.contains("SMB2_STATUS_NO_SUCH_FILE"))
    }
}
