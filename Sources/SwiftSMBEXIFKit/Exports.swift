//
// Part of SwiftSMB
// Exports.swift
//
// Licensed under Apache License v2.0
// Copyright its respective authors
//

#if canImport(EXIFKit)
    // Every public API of this module takes or returns EXIFKit types, so importing it brings EXIFKit along, as in
    // SwiftSFTPEXIFKit.
    @_exported import EXIFKit
#endif
