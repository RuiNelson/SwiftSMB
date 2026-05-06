//
// Part of SwiftSMB
// SMBProtected.swift
//
// Licensed under LGPL v2.1
// Copyright it's respective authors
//

import Dispatch

final class SMBProtected<Value>: @unchecked Sendable {
    private let queue: DispatchQueue
    private var value: Value

    init(_ value: Value, label: String) {
        queue = DispatchQueue(label: label)
        self.value = value
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
