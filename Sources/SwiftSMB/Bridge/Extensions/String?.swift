//
// Part of SwiftSMB
// String?.swift
//
// Licensed under LGPL v2.1
// Copyright it's respective authors
//

extension String? {
    /// Calls a closure with either a temporary C string pointer or nil.
    func withOptionalCString<Result>(
        _ body: (UnsafePointer<CChar>?) throws -> Result,
    ) rethrows -> Result {
        guard let string = self else {
            return try body(nil)
        }
        
        return try string.withCString(body)
    }
}
