//
// Part of SwiftSMB
// TestMovie.swift
//
// Licensed under Apache License v2.0
// Copyright its respective authors
//

#if canImport(AVFoundation) && !os(watchOS)
    import AVFoundation
    import Foundation
    import SwiftSMB
    import Testing

    /// A small H.264 movie generated at test time, so no media fixtures live in the repository.
    enum TestMovie {
        static let frameCount = 30
        static let framesPerSecond: Int32 = 10

        /// Writes the movie to a temporary local file and returns its URL.
        @available(macOS 13, iOS 16, tvOS 16, macCatalyst 16, visionOS 1, *)
        static func make() async throws -> URL {
            let url = FileManager.default.temporaryDirectory.appendingPathComponent(UUID().uuidString + ".mp4")
            let width = 160
            let height = 120
            let writer = try AVAssetWriter(outputURL: url, fileType: .mp4)
            let input = AVAssetWriterInput(
                mediaType: .video,
                outputSettings: [
                    AVVideoCodecKey: AVVideoCodecType.h264,
                    AVVideoWidthKey: width,
                    AVVideoHeightKey: height,
                ]
            )
            input.expectsMediaDataInRealTime = false
            let adaptor = AVAssetWriterInputPixelBufferAdaptor(
                assetWriterInput: input,
                sourcePixelBufferAttributes: nil
            )
            writer.add(input)
            #expect(writer.startWriting())
            writer.startSession(atSourceTime: .zero)

            for frame in 0 ..< frameCount {
                while !input.isReadyForMoreMediaData {
                    try await Task.sleep(nanoseconds: 1_000_000)
                }
                var buffer: CVPixelBuffer?
                CVPixelBufferCreate(nil, width, height, kCVPixelFormatType_32BGRA, nil, &buffer)
                let pixels = try #require(buffer)
                CVPixelBufferLockBaseAddress(pixels, [])
                // Noise keeps the encoded frames large enough to need several read blocks.
                let base = try #require(CVPixelBufferGetBaseAddress(pixels)).assumingMemoryBound(to: UInt8.self)
                for index in 0 ..< CVPixelBufferGetBytesPerRow(pixels) * height {
                    base[index] = UInt8.random(in: .min ... .max)
                }
                CVPixelBufferUnlockBaseAddress(pixels, [])
                #expect(adaptor.append(pixels, withPresentationTime: CMTime(
                    value: CMTimeValue(frame),
                    timescale: framesPerSecond
                )))
            }

            input.markAsFinished()
            await writer.finishWriting()
            if let error = writer.error {
                throw error
            }
            return url
        }

        /// Uploads a freshly generated movie to `path` on the connection's share.
        @available(macOS 13, iOS 16, tvOS 16, macCatalyst 16, visionOS 1, *)
        static func upload(to path: String, on connection: SMB.Connection) async throws {
            let local = try await make()
            defer { try? FileManager.default.removeItem(at: local) }
            try await connection.dumpToFile(Data(contentsOf: local), to: path)
        }
    }
#endif
