//
// Part of SwiftSMB
// Bridge-Platform.swift
//
// Licensed under Apache License v2.0
// Copyright its respective authors
//

#if canImport(Android)
    import Android
#endif
import Foundation
import SMB2
#if os(Windows)
    import WinSDK
#endif

extension Bridge {
    /// Starts Winsock on Windows, which libsmb2 expects its host to have done (it only reports "Please call
    /// WSAStartup()" when a connection is attempted without it). Does nothing elsewhere.
    ///
    /// Runs once, before the first context is created.
    static let installNetworking: Void = {
        #if os(Windows)
            var data = WSADATA()
            // A failure surfaces as libsmb2's own connection error, with Winsock's message.
            _ = WSAStartup(WORD(0x0202), &data)
        #endif
    }()

    /// Waits until the context's socket is ready for what libsmb2 wants to do next, or `timeoutMilliseconds` pass, and
    /// returns the events to hand to `smb2_service`.
    ///
    /// Without a connection, polling ignores the descriptor, so a loop that waits on it would never finish; this throws
    /// ``noConnectionError(operation:)`` instead, as libsmb2's own synchronous wait loop fails in this case too. An
    /// interrupted wait is retried.
    ///
    /// - Parameter failureMessage: The message of the error thrown when the wait itself fails.
    static func waitForConnectionEvents(
        context: Context,
        timeoutMilliseconds: Int32,
        failureMessage: String
    ) throws -> Int32 {
        #if os(Windows)
            var pfd = WSAPOLLFD()
            pfd.fd = smb2_get_fd(context.raw)
            guard pfd.fd != INVALID_SOCKET else {
                throw noConnectionError(operation: "smb2_service")
            }
            pfd.events = SHORT(truncatingIfNeeded: smb2_which_events(context.raw))
            let rc = withUnsafeMutablePointer(to: &pfd) { WSAPoll($0, 1, timeoutMilliseconds) }
            if rc == SOCKET_ERROR {
                throw SMB.Error.posix(code: WSAGetLastError(), operation: "poll", message: failureMessage)
            }
            return Int32(pfd.revents)
        #else
            var pfd = pollfd()
            pfd.fd = smb2_get_fd(context.raw)
            guard pfd.fd >= 0 else {
                throw noConnectionError(operation: "smb2_service")
            }
            pfd.events = Int16(smb2_which_events(context.raw))

            var rc: Int32 = 0
            repeat {
                rc = withUnsafeMutablePointer(to: &pfd) { poll($0, 1, timeoutMilliseconds) }
            }
            while rc < 0 && errno == EINTR

            if rc < 0 {
                throw SMB.Error.posix(code: errno, operation: "poll", message: failureMessage)
            }
            return Int32(pfd.revents)
        #endif
    }
}

extension Bridge {
    /// The values of the `O_*` flags `smb2_open` understands, as libsmb2 itself sees them.
    enum OpenFlagValues {
        #if os(Windows)
            // The CRT's own names: `O_RDONLY` and the like exist only when its non-standard names are enabled. The CRT
            // has no `O_SYNC` or `O_DIRECTORY`, so the configuration header
            // (`Sources/libsmb2/include/windows-config.h`) defines them, and libsmb2 and this module read the same
            // values.
            static let readOnly = Int32(_O_RDONLY)
            static let writeOnly = Int32(_O_WRONLY)
            static let readWrite = Int32(_O_RDWR)
            static let create = Int32(_O_CREAT)
            static let exclusive = Int32(_O_EXCL)
            static let truncate = Int32(_O_TRUNC)
            static let append = Int32(_O_APPEND)
            static let synchronous = Int32(O_SYNC)
            static let directory = Int32(O_DIRECTORY)
        #else
            static let readOnly = Int32(O_RDONLY)
            static let writeOnly = Int32(O_WRONLY)
            static let readWrite = Int32(O_RDWR)
            static let create = Int32(O_CREAT)
            static let exclusive = Int32(O_EXCL)
            static let truncate = Int32(O_TRUNC)
            static let append = Int32(O_APPEND)
            static let synchronous = Int32(O_SYNC)
            static let directory = Int32(O_DIRECTORY)
        #endif
    }
}
