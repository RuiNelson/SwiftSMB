//
// Part of SwiftSMB
// Connection+AVFoundation.swift
//
// Licensed under Apache License v2.0
// Copyright its respective authors
//

#if canImport(AVFoundation) && !os(watchOS)
    import AVFoundation
    import Foundation
    import PathWorks
    import SwiftSMB
    import UniformTypeIdentifiers

    @available(macOS 11, iOS 14, tvOS 14, macCatalyst 14, visionOS 1, *)
    public extension SMB.Connection {
        /// Creates an AVFoundation asset that streams a media file from the SMB share.
        ///
        /// The asset reads the file on demand through this connection, so playback can start before the whole file has
        /// been transferred and seeking only fetches the byte ranges AVFoundation asks for. Nothing reaches the server
        /// until AVFoundation loads the asset; failures, such as a missing file or a closed connection, surface as the
        /// asset's loading errors or as ``AVPlayerItem/status`` `.failed`.
        ///
        /// The asset keeps this connection alive while it exists. Disconnecting the connection makes further reads
        /// fail. All reads share the connection with any other operations it performs.
        ///
        /// ```swift
        /// let asset = connection.makeAsset(at: "Videos/holiday.mp4")
        /// let duration = try await asset.load(.duration)
        /// ```
        ///
        /// - Parameters:
        ///   - path: The path to the media file, relative to the share root.
        ///   - contentType: The file's media type, or `nil` to infer it from the path's extension. Pass it for files
        /// without an extension; `.movie` is used when the extension is missing or has no registered type.
        ///   - options: Options passed to ``AVURLAsset/init(url:options:)``.
        /// - Returns: An asset backed by the SMB file.
        func makeAsset(at path: String, contentType: UTType? = nil, options: [String: Any]? = nil) -> AVURLAsset {
            let fileName = path.lastPathComponent ?? ""
            // `UTType(filenameExtension:)` returns a dynamic type, not `nil`, for an extension it doesn't know.
            let registeredType = fileName.separateExtension.ext
                .flatMap { UTType(filenameExtension: $0) }
                .flatMap { $0.isDynamic ? nil : $0 }
            let resolvedType = contentType ?? registeredType ?? .movie
            let loader = MediaResourceLoader(connection: self, path: path, contentType: resolvedType)
            return SMBMediaAsset(url: SMBMediaAsset.makeURL(fileName: fileName), loader: loader, options: options)
        }

        /// Creates a player item that streams a media file from the SMB share.
        ///
        /// This is a shorthand for `AVPlayerItem(asset: makeAsset(at:contentType:))`. See
        /// ``SMB/Connection/makeAsset(at:contentType:options:)`` for how the file is read and how errors are reported.
        ///
        /// ```swift
        /// let player = AVPlayer(playerItem: connection.makePlayerItem(at: "Videos/holiday.mp4"))
        /// player.play()
        /// ```
        ///
        /// - Parameters:
        ///   - path: The path to the media file, relative to the share root.
        ///   - contentType: The file's media type, or `nil` to infer it from the path's extension.
        /// - Returns: A player item backed by the SMB file.
        func makePlayerItem(at path: String, contentType: UTType? = nil) -> AVPlayerItem {
            AVPlayerItem(asset: makeAsset(at: path, contentType: contentType))
        }
    }
#endif
