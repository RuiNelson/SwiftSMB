import AVKit
import SwiftSMB
import SwiftSMBAVFoundation
import SwiftUI

/// Connects to an SMB share and plays one of its audio or video files with `AVPlayer`.
///
/// The interesting part is `PlayerModel.play()`: once connected, `SMB.Connection.makePlayerItem(at:)` returns an
/// `AVPlayerItem` that streams the file from the share, so playback starts without downloading it first.
struct ContentView: View {
    @State private var model = PlayerModel()

    var body: some View {
        NavigationStack {
            Form {
                Section("Server") {
                    TextField("Host (e.g. nas.local)", text: $model.host)
                    TextField("Share", text: $model.share)
                    TextField("User (empty for guest)", text: $model.user)
                    SecureField("Password", text: $model.password)
                }

                Section("File") {
                    TextField("Path in the share (e.g. Movies/trailer.mp4)", text: $model.path)
                }

                Section {
                    Button(model.isPlaying ? "Restart" : "Play") {
                        Task { await model.play() }
                    }
                    .disabled(!model.canPlay)

                    if model.isLoading {
                        ProgressView("Connecting…")
                    }

                    if let errorMessage = model.errorMessage {
                        Text(errorMessage)
                            .foregroundStyle(.red)
                    }
                }

                if let player = model.player {
                    Section("Player") {
                        // Audio files play in the same view, which shows only the transport controls.
                        VideoPlayer(player: player)
                            .frame(minHeight: 220)
                    }
                }
            }
            .formStyle(.grouped)
            .autocorrectionDisabled()
            #if os(iOS)
                .textInputAutocapitalization(.never)
            #endif
            .navigationTitle("Play from SMB")
        }
        .onDisappear {
            Task { await model.stop() }
        }
    }
}

/// Owns the SMB connection and the player built on it.
@MainActor
@Observable
final class PlayerModel {
    var host = ""
    var share = ""
    var user = ""
    var password = ""
    var path = ""

    private(set) var player: AVPlayer?
    private(set) var isLoading = false
    private(set) var errorMessage: String?

    /// The connection must stay open for as long as the player item streams from it.
    private var connection: SMB.Connection?
    private var statusObservation: NSKeyValueObservation?

    var isPlaying: Bool {
        player != nil
    }

    var canPlay: Bool {
        !isLoading && !host.isEmpty && !share.isEmpty && !path.isEmpty
    }

    func play() async {
        await stop()
        isLoading = true
        errorMessage = nil
        defer { isLoading = false }

        do {
            let credentials = user.isEmpty ? nil : SMB.Credentials(user: user, password: password)
            let connection = try await SMB.connect(
                server: SMB.Server(host: host),
                credentials: credentials,
                share: share
            )
            self.connection = connection

            // Nothing is read from the server yet; AVFoundation asks for byte ranges as it needs them.
            let item = connection.makePlayerItem(at: path)
            // Errors such as a missing file or an unsupported format surface through the item's status.
            statusObservation = item.observe(\.status) { [weak self] item, _ in
                guard item.status == .failed else { return }
                let message = item.error?.localizedDescription ?? "The file could not be played."
                Task { @MainActor in self?.errorMessage = message }
            }

            let player = AVPlayer(playerItem: item)
            self.player = player
            player.play()
        }
        catch {
            errorMessage = error.localizedDescription
            await stop()
        }
    }

    func stop() async {
        statusObservation = nil
        player?.pause()
        player?.replaceCurrentItem(with: nil)
        player = nil

        let connection = connection
        self.connection = nil
        try? await connection?.disconnect()
    }
}

#Preview {
    ContentView()
}
