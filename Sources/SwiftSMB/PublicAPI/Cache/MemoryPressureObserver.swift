//
// Part of SwiftSMB
// MemoryPressureObserver.swift
//
// Licensed under Apache License v2.0
// Copyright its respective authors
//

#if canImport(Darwin)
    import Dispatch

    /// Reports the system's memory pressure warnings, for as long as it lives.
    final class MemoryPressureObserver: @unchecked Sendable {
        /// The queue the warnings arrive on: one of the observer's own, never a global one.
        private let queue = DispatchQueue(label: "com.ruinelson.SwiftSMB.MemoryPressureObserver")

        private let source: any DispatchSourceMemoryPressure

        init() {
            source = DispatchSource.makeMemoryPressureSource(eventMask: [.warning, .critical], queue: queue)
            // Active from the start: an inactive source must not be released.
            source.activate()
        }

        /// Calls `handler` on every warning, with whether memory is critical. Call it once.
        func start(_ handler: @escaping @Sendable (_ critical: Bool) -> Void) {
            source.setEventHandler { [weak self] in
                guard let self else {
                    return
                }
                handler(source.data.contains(.critical))
            }
        }

        deinit {
            source.cancel()
        }
    }
#endif
