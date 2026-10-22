//
// Part of SwiftSMB
// SMBMediaAsset.swift
//
// Licensed under Apache License v2.0
// Copyright its respective authors
//

#if canImport(AVFoundation) && !os(watchOS)
    import AVFoundation
    import Foundation

    /// A URL asset that owns the resource loader serving its SMB file.
    ///
    /// ``AVAssetResourceLoader`` holds its delegate weakly, so the asset keeps the loader alive for its own lifetime.
    @available(macOS 11, iOS 14, tvOS 14, macCatalyst 14, visionOS 1, *)
    final class SMBMediaAsset: AVURLAsset, @unchecked Sendable {
        /// The custom scheme that routes every request through the resource loader.
        static let scheme = "swiftsmb-media"

        let loader: MediaResourceLoader

        init(url: URL, loader: MediaResourceLoader, options: [String: Any]?) {
            self.loader = loader
            super.init(url: url, options: options)
            resourceLoader.setDelegate(loader, queue: loader.queue)
        }

        /// Builds a unique URL that AVFoundation cannot load by itself, ending in the file name to help format
        /// detection.
        static func makeURL(fileName: String) -> URL {
            var components = URLComponents()
            components.scheme = scheme
            components.host = UUID().uuidString
            components.path = "/" + (fileName.isEmpty ? "media" : fileName)
            return components.url ?? URL(string: "\(scheme)://\(UUID().uuidString)/media")!
        }
    }
#endif
