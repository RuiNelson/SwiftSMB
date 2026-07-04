//
// Part of SwiftSMB
// Protected.swift
//
// Licensed under Apache License v2.0
// Copyright its respective authors
//

import Foundation
import Synchronization

/// Type-erased locking backend shared by `Protected`'s storage strategies.
private protocol ProtectedBox<Value>: AnyObject, Sendable {
    associatedtype Value

    var debugValue: Value { get }
    func get() -> sending Value
    func set(_ newValue: Value)
    func take(replacingWith replacement: sending Value) -> sending Value
    func withLock<Result>(_ body: (inout Value) -> Result) -> Result
}

/// `NSLock`-backed storage, used where `Mutex` is unavailable.
private final class LockBox<Value>: ProtectedBox, @unchecked Sendable {
    private let lock = NSLock()
    private var value: Value

    init(_ value: sending Value) {
        self.value = value
    }

    var debugValue: Value {
        lock.lock()
        defer { lock.unlock() }
        return value
    }

    func get() -> sending Value {
        lock.lock()
        defer { lock.unlock() }
        return value
    }

    func set(_ newValue: Value) {
        lock.lock()
        defer { lock.unlock() }
        value = newValue
    }

    func take(replacingWith replacement: sending Value) -> sending Value {
        lock.lock()
        defer { lock.unlock() }
        let currentValue = value
        value = replacement
        return currentValue
    }

    func withLock<Result>(_ body: (inout Value) -> Result) -> Result {
        lock.lock()
        defer { lock.unlock() }
        return body(&value)
    }
}

/// Wraps a non-`Sendable` value so it can be stored in a `Mutex`, which requires its contents to cross isolation
/// regions freely.
private struct ValueBox<Value>: @unchecked Sendable {
    var value: Value
}

/// `Mutex`-backed storage, preferred when available.
@available(macOS 15, iOS 18, tvOS 18, watchOS 11, visionOS 2, *)
private final class MutexBox<Value>: ProtectedBox, @unchecked Sendable {
    private let mutex: Mutex<ValueBox<Value>>

    init(_ value: sending Value) {
        mutex = Mutex(ValueBox(value: value))
    }

    var debugValue: Value {
        mutex.withLock { $0.value }
    }

    func get() -> sending Value {
        mutex.withLock { $0.value }
    }

    func set(_ newValue: Value) {
        mutex.withLock { $0.value = newValue }
    }

    func take(replacingWith replacement: sending Value) -> sending Value {
        mutex.withLock { box in
            let currentValue = box.value
            box.value = replacement
            return currentValue
        }
    }

    func withLock<Result>(_ body: (inout Value) -> Result) -> Result {
        mutex.withLock { box in
            body(&box.value)
        }
    }
}

final class Protected<Value>: CustomDebugStringConvertible, @unchecked Sendable {
    private let label: String
    private let box: any ProtectedBox<Value>

    init(_ value: sending Value, label: String) {
        self.label = label
        if #available(macOS 15, iOS 18, tvOS 18, watchOS 11, visionOS 2, *) {
            box = MutexBox(value)
        }
        else {
            box = LockBox(value)
        }
    }

    var debugDescription: String {
        "Protected<\(Value.self)>(\(label), \(box.debugValue))"
    }

    var current: Value {
        get {
            box.get()
        }
        set {
            box.set(newValue)
        }
    }

    func take(replacingWith replacement: sending Value) -> sending Value {
        box.take(replacingWith: replacement)
    }

    /// Performs a read-modify-write of the protected value as a single atomic operation.
    func withLock<Result>(_ body: (inout Value) -> Result) -> Result {
        box.withLock(body)
    }
}
