//
// Part of SwiftSMB
// Date+.swift
//
// Licensed under Apache License v2.0
// Copyright its respective authors
//

import Foundation

extension Date {
    init(seconds: Int64, nanoseconds: UInt64) {
        let s = Double(seconds)
        let ns = Double(nanoseconds) / 1_000_000_000.0
        self.init(timeIntervalSince1970: s + ns)
    }
}
