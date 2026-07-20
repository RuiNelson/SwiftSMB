//
// Part of SwiftSMB
// Bridge-Security.swift
//
// Licensed under Apache License v2.0
// Copyright its respective authors
//

import Foundation
import SMB2
import SMB2.Raw

extension Bridge {
    private final class SecurityDescriptorState: PendingOperationState {
        var status: Int32 = SMB2_STATUS_SUCCESS
        var isFinished = false
    }

    private final class SIDStorage {
        let pointer: UnsafeMutablePointer<smb2_sid>

        init(_ sid: SecurityIdentifier) {
            let byteCount = MemoryLayout<smb2_sid>.size + sid.subauthorities.count * MemoryLayout<UInt32>.size
            let raw = UnsafeMutableRawPointer.allocate(
                byteCount: byteCount,
                alignment: MemoryLayout<smb2_sid>.alignment
            )
            raw.initializeMemory(as: UInt8.self, repeating: 0, count: byteCount)
            pointer = raw.bindMemory(to: smb2_sid.self, capacity: 1)
            pointer.pointee.revision = sid.revision
            pointer.pointee.sub_auth_count = UInt8(sid.subauthorities.count)

            withUnsafeMutableBytes(of: &pointer.pointee.id_auth) { authorityBytes in
                for index in 0 ..< 6 {
                    let shift = UInt64((5 - index) * 8)
                    authorityBytes[index] = UInt8(truncatingIfNeeded: sid.identifierAuthority >> shift)
                }
            }

            let subauthorities = raw
                .advanced(by: MemoryLayout<smb2_sid>.size)
                .bindMemory(to: UInt32.self, capacity: sid.subauthorities.count)
            for (index, subauthority) in sid.subauthorities.enumerated() {
                subauthorities[index] = subauthority
            }
        }

        deinit {
            UnsafeMutableRawPointer(pointer).deallocate()
        }
    }

    private final class SecurityDescriptorStorage {
        let descriptor: UnsafeMutablePointer<smb2_security_descriptor>

        private let owner: SIDStorage?
        private let group: SIDStorage?
        private let trustees: [SIDStorage]
        private let entries: UnsafeMutablePointer<smb2_ace>?
        private let dacl: UnsafeMutablePointer<smb2_acl>?

        init(_ value: SecurityDescriptor) {
            owner = value.owner.map(SIDStorage.init)
            group = value.group.map(SIDStorage.init)

            if let list = value.discretionaryAccessControlList {
                trustees = list.entries.map { SIDStorage($0.trustee) }
                if list.entries.isEmpty {
                    entries = nil
                }
                else {
                    let buffer = UnsafeMutablePointer<smb2_ace>.allocate(capacity: list.entries.count)
                    buffer.initialize(repeating: smb2_ace(), count: list.entries.count)
                    for (index, entry) in list.entries.enumerated() {
                        buffer[index].next = index + 1 < list.entries.count ? buffer.advanced(by: index + 1) : nil
                        buffer[index].ace_type = entry.kind
                        buffer[index].ace_flags = entry.flags
                        buffer[index].mask = entry.accessMask
                        buffer[index].sid = trustees[index].pointer
                    }
                    entries = buffer
                }

                let acl = UnsafeMutablePointer<smb2_acl>.allocate(capacity: 1)
                acl.initialize(to: smb2_acl(
                    revision: list.revision,
                    ace_count: UInt16(list.entries.count),
                    aces: entries
                ))
                dacl = acl
            }
            else {
                trustees = []
                entries = nil
                dacl = nil
            }

            descriptor = UnsafeMutablePointer<smb2_security_descriptor>.allocate(capacity: 1)
            descriptor.initialize(to: smb2_security_descriptor(
                revision: 1,
                control: dacl == nil ? 0 : UInt16(SMB2_SD_CONTROL_DP),
                owner: owner?.pointer,
                group: group?.pointer,
                dacl: dacl
            ))
        }

        deinit {
            descriptor.deinitialize(count: 1)
            descriptor.deallocate()
            dacl?.deinitialize(count: 1)
            dacl?.deallocate()
            if let entries {
                entries.deinitialize(count: trustees.count)
                entries.deallocate()
            }
        }
    }

    private static let setSecurityCreateCallback: smb2_command_cb = { _, status, _, callbackData in
        guard let callbackData else { return }
        Unmanaged<SecurityDescriptorState>.fromOpaque(callbackData).takeUnretainedValue().recordStatus(status)
    }

    private static let setSecurityInfoCallback: smb2_command_cb = { _, status, _, callbackData in
        guard let callbackData else { return }
        Unmanaged<SecurityDescriptorState>.fromOpaque(callbackData).takeUnretainedValue().recordStatus(status)
    }

    private static let setSecurityCloseCallback: smb2_command_cb = { _, status, _, callbackData in
        guard let callbackData else { return }
        Unmanaged<SecurityDescriptorState>.fromOpaque(callbackData).takeUnretainedValue().finish(status)
    }

    private static func validate(_ sid: SecurityIdentifier) throws {
        guard sid.identifierAuthority <= 0xFFFF_FFFF_FFFF else {
            throw SMB.Error.invalidArgument(
                cause: .securityIdentifierAuthorityOutOfRange,
                onOperation: .smbConnectionSetSecurityDescriptor
            )
        }
        guard sid.subauthorities.count <= 15 else {
            throw SMB.Error.invalidArgument(
                cause: .securityIdentifierHasTooManySubauthorities(sid.subauthorities.count),
                onOperation: .smbConnectionSetSecurityDescriptor
            )
        }
    }

    private static func validate(_ descriptor: SecurityDescriptor) throws {
        guard descriptor.owner != nil || descriptor.group != nil || descriptor.discretionaryAccessControlList != nil else {
            throw SMB.Error.invalidArgument(
                cause: .securityDescriptorHasNoComponents,
                onOperation: .smbConnectionSetSecurityDescriptor
            )
        }
        if let owner = descriptor.owner { try validate(owner) }
        if let group = descriptor.group { try validate(group) }
        if let entries = descriptor.discretionaryAccessControlList?.entries {
            guard entries.count <= Int(UInt16.max) else {
                throw SMB.Error.invalidArgument(
                    cause: .accessControlListHasTooManyEntries(entries.count),
                    onOperation: .smbConnectionSetSecurityDescriptor
                )
            }
            for entry in entries {
                try validate(entry.trustee)
            }
        }
    }

    private static func _setSecurityDescriptor(
        context: Context,
        path: String,
        descriptor value: SecurityDescriptor
    ) throws {
        try validate(value)
        let storage = SecurityDescriptorStorage(value)
        let state = SecurityDescriptorState()
        let callbackData = Unmanaged.passRetained(state).toOpaque()
        defer { Unmanaged<SecurityDescriptorState>.fromOpaque(callbackData).release() }

        var desiredAccess: UInt32 = 0
        var additionalInformation: UInt32 = 0
        if value.owner != nil {
            desiredAccess |= UInt32(SMB2_WRITE_OWNER)
            additionalInformation |= UInt32(SMB2_OWNER_SECURITY_INFORMATION)
        }
        if value.group != nil {
            desiredAccess |= UInt32(SMB2_WRITE_OWNER)
            additionalInformation |= UInt32(SMB2_GROUP_SECURITY_INFORMATION)
        }
        if value.discretionaryAccessControlList != nil {
            desiredAccess |= UInt32(SMB2_WRITE_DACL)
            additionalInformation |= UInt32(SMB2_DACL_SECURITY_INFORMATION)
        }

        var createRequest = smb2_create_request()
        createRequest.requested_oplock_level = UInt8(SMB2_OPLOCK_LEVEL_NONE)
        createRequest.impersonation_level = UInt32(SMB2_IMPERSONATION_IMPERSONATION)
        createRequest.desired_access = desiredAccess
        createRequest.share_access = UInt32(SMB2_FILE_SHARE_READ | SMB2_FILE_SHARE_WRITE | SMB2_FILE_SHARE_DELETE)
        createRequest.create_disposition = UInt32(SMB2_FILE_OPEN)

        try path.withCString { pathPointer in
            createRequest.name = pathPointer
            guard let pdu = smb2_cmd_create_async(
                context.raw,
                &createRequest,
                setSecurityCreateCallback,
                callbackData
            ) else {
                throw SMB.Error.fromBridge(context, operation: "smb2_cmd_create_async")
            }

            var setInfoRequest = smb2_set_info_request()
            setInfoRequest.info_type = UInt8(SMB2_0_INFO_SECURITY)
            setInfoRequest.additional_information = additionalInformation
            setInfoRequest.file_id = FileID.allOnes.raw
            setInfoRequest.input_data = UnsafeMutableRawPointer(storage.descriptor)

            guard let setInfoPDU = smb2_cmd_set_info_async(
                context.raw,
                &setInfoRequest,
                setSecurityInfoCallback,
                callbackData
            ) else {
                smb2_free_pdu(context.raw, pdu)
                throw SMB.Error.fromBridge(context, operation: "smb2_cmd_set_info_async")
            }
            smb2_add_compound_pdu(context.raw, pdu, setInfoPDU)

            var closeRequest = smb2_close_request(flags: 0, file_id: FileID.allOnes.raw)
            guard let closePDU = smb2_cmd_close_async(
                context.raw,
                &closeRequest,
                setSecurityCloseCallback,
                callbackData
            ) else {
                smb2_free_pdu(context.raw, pdu)
                throw SMB.Error.fromBridge(context, operation: "smb2_cmd_close_async")
            }
            smb2_add_compound_pdu(context.raw, pdu, closePDU)
            smb2_queue_pdu(context.raw, pdu)
            try serviceUntilFinished(context: context, state: state)
        }

        if state.status != SMB2_STATUS_SUCCESS {
            throw SMB.Error.fromBridge(context, operation: "SMB2_0_INFO_SECURITY", status: state.status)
        }
    }

    /// Sets selected owner, group, and DACL fields on an SMB item.
    static func setSecurityDescriptor(
        context: Context,
        path: String,
        descriptor: SecurityDescriptor
    ) throws {
        try sync {
            try _setSecurityDescriptor(context: context, path: path, descriptor: descriptor)
        }
    }
}
