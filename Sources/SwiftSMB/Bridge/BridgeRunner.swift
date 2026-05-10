//
//  BridgeRunner.swift
//  SwiftSMB
//
//  Created by Rui Nelson on 10/05/2026.
//

import Dispatch

class BridgeRunner {
    private static let bridgeQueue = DispatchQueue(label: "com.ruinelson.swiftsmb.bridge")
    
    static func bridgeExecution<T>(_ body: () throws -> T) throws -> T {
        try bridgeQueue.sync {
            try body()
        }
    }
}
