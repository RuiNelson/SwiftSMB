//
// Part of SwiftSMB
// Protected.swift
//
// Licensed under LGPL v2.1
// Copyright its respective authors
//

import Dispatch

final class Protected<Value>: CustomDebugStringConvertible, @unchecked Sendable {
    private let label: String
    private let queue: DispatchQueue
    private var value: Value

    init(_ value: Value, label: String) {
        self.label = label
        queue = DispatchQueue(label: label)
        self.value = value
    }

    var debugDescription: String {
        queue.sync {
            "Protected<\(Value.self)>(\(label), \(value))"
        }
    }

    var current: Value {
        get {
            queue.sync {
                value
            }
        }
        set {
            queue.sync {
                value = newValue
            }
        }
    }

    func take(replacingWith replacement: Value) -> Value {
        queue.sync {
            let currentValue = value
            value = replacement
            return currentValue
        }
    }
}
