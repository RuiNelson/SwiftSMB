//
// Part of SwiftSMB
// SMBFileHandleForEXIFKitError.swift
//
// Licensed under Apache License v2.0
// Copyright its respective authors
//

/// A failure reading or editing image metadata over SMB that neither SwiftSMB nor EXIFKit describes.
public enum SMBFileHandleForEXIFKitError: Error, Sendable, Equatable {
    /// An edit was given the same SMB file handle as its source and its destination. The new image would overwrite the
    /// source before it is read.
    case sameSourceAndDestination
}
