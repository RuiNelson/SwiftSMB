//
// Part of SwiftSMB
// CookbookVideoPlaybackTests.swift
//
// Licensed under Apache License v2.0
// Copyright its respective authors
//

#if canImport(AVFoundation) && !os(watchOS)
    import AVFoundation
    import Foundation
    import SwiftSMB
    import SwiftSMBAVFoundation
    import Testing

    @Suite(.tags(.integration))
    struct CookbookVideoPlaybackTests {
        @available(macOS 13, iOS 16, tvOS 16, macCatalyst 16, visionOS 1, *)
        @Test("play a file compiles and runs")
        func playFile() async throws {
            try await withCookbookMovie { connection, path in
                let player = AVPlayer(playerItem: connection.makePlayerItem(at: path))
                player.play()
                player.pause()
            }
        }

        @available(macOS 13, iOS 16, tvOS 16, macCatalyst 16, visionOS 1, *)
        @Test("work with the asset compiles and runs")
        func workWithAsset() async throws {
            try await withCookbookMovie { connection, path in
                let asset = connection.makeAsset(at: path)
                let duration = try await asset.load(.duration)
                #expect(duration.seconds > 0)

                let generator = AVAssetImageGenerator(asset: asset)
                let (thumbnail, _) = try await generator.image(at: .zero)
                #expect(thumbnail.width > 0)

                let preciseAsset = connection.makeAsset(
                    at: path,
                    options: [AVURLAssetPreferPreciseDurationAndTimingKey: true]
                )
                _ = try await preciseAsset.load(.duration)
            }
        }

        @available(macOS 13, iOS 16, tvOS 16, macCatalyst 16, visionOS 1, *)
        @Test("explicit content type compiles and runs")
        func explicitContentType() async throws {
            try await withCookbookMovie(fileExtension: nil) { connection, path in
                let item = connection.makePlayerItem(at: path, contentType: .mpeg4Movie)
                _ = item
                let asset = connection.makeAsset(at: path, contentType: .mpeg4Movie)
                let tracks = try await asset.loadTracks(withMediaType: .video)
                #expect(tracks.count == 1)
            }
        }

        @available(macOS 13, iOS 16, tvOS 16, macCatalyst 16, visionOS 1, *)
        @Test("observe playback failures compiles and runs")
        func observePlaybackFailures() async throws {
            let connection = try await cookbookConnection()
            defer { try? await connection.disconnect() }

            let item = connection.makePlayerItem(at: uniquePath("cookbook-missing") + ".mp4")
            let observation = item.observe(\.status) { item, _ in
                if item.status == .failed {
                    _ = String(describing: item.error)
                }
            }
            defer { observation.invalidate() }

            let player = AVPlayer(playerItem: item)
            defer { player.replaceCurrentItem(with: nil) }
            let deadline = Date().addingTimeInterval(15)
            while item.status == .unknown, Date() < deadline {
                try await Task.sleep(nanoseconds: 20_000_000)
            }
            #expect(item.status == .failed)
            #expect(item.error != nil)
        }

        @available(macOS 13, iOS 16, tvOS 16, macCatalyst 16, visionOS 1, *)
        private func withCookbookMovie(
            fileExtension: String? = "mp4",
            _ body: (SMB.Connection, String) async throws -> Void
        ) async throws {
            let connection = try await cookbookConnection()
            defer { try? await connection.disconnect() }

            let path = uniquePath("cookbook-video") + (fileExtension.map { "." + $0 } ?? "")
            try await TestMovie.upload(to: path, on: connection)
            defer { try? await connection.removeFile(at: path) }

            try await body(connection, path)
        }
    }
#endif
