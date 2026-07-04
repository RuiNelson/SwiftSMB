//
// Part of SwiftSMB
// ProtectedHandle.swift
//
// Licensed under Apache License v2.0
// Copyright its respective authors
//

/// Wraps an optional bridge handle that can be read, replaced, or taken (e.g. on close) from any thread.
final class ProtectedHandle<Handle>: @unchecked Sendable {
    private let protected: Protected<Handle?>

    init(label: String) {
        protected = Protected(nil, label: label)
    }

    /// The live handle, or `nil` if it has been taken.
    var current: Handle? {
        get {
            protected.current
        }
        set {
            protected.current = newValue
        }
    }

    /// Returns the live handle, or throws the error produced by `makeError` if it has already been taken.
    func require(orThrow makeError: () -> SMB.Error) throws -> Handle {
        guard let handle = current else {
            throw makeError()
        }
        return handle
    }

    /// Takes ownership of the handle, leaving `nil` in its place.
    func take() -> Handle? {
        protected.take(replacingWith: nil)
    }
}
