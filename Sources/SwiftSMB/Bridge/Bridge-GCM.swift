//
// Part of SwiftSMB
// Bridge-GCM.swift
//
// Licensed under Apache License v2.0
// Copyright its respective authors
//

import SMB2.GCM

#if canImport(CryptoKit)
    import CryptoKit
    import Foundation
#endif

extension Bridge {
    /// Hands libsmb2's AES-128-GCM and AES-256-GCM sealing to CryptoKit, which uses the AES and GHASH instructions of
    /// the CPU and runs in constant time. Without CryptoKit, libsmb2 seals with BearSSL's GCM (the fork's
    /// `lib/aes-gcm.c`, `Vendored/libsmb2-SwiftSMB/MODS.md` M4).
    ///
    /// Runs once, before the first context is created.
    static let installGCMSeal: Void = {
        #if canImport(CryptoKit)
            swiftsmb_set_gcm_seal(cryptoKitGCMSeal)
        #endif
    }()
}

#if canImport(CryptoKit)
    /// `swiftsmb_gcm_seal_fn`: seals or opens one message in place. Returns 0 on success, -1 on failure.
    private let cryptoKitGCMSeal: swiftsmb_gcm_seal_fn =
        { encrypt, key, keyLength, iv, aad, aadLength, data, dataLength, tag in
            guard let key, keyLength == 16 || keyLength == 32, let iv, let tag else {
                return -1
            }
            let symmetricKey = SymmetricKey(data: UnsafeRawBufferPointer(start: key, count: keyLength))
            let authenticatedData = UnsafeRawBufferPointer(start: aad, count: aad == nil ? 0 : aadLength)
            let message = UnsafeMutableRawBufferPointer(start: data, count: data == nil ? 0 : dataLength)

            do {
                let nonce = try AES.GCM.Nonce(data: UnsafeRawBufferPointer(start: iv, count: 12))
                let output: Data
                if encrypt != 0 {
                    let box = try AES.GCM.seal(
                        UnsafeRawBufferPointer(message),
                        using: symmetricKey,
                        nonce: nonce,
                        authenticating: authenticatedData
                    )
                    output = box.ciphertext
                    box.tag.copyBytes(to: UnsafeMutableRawBufferPointer(start: tag, count: 16))
                }
                else {
                    let box = try AES.GCM.SealedBox(
                        nonce: nonce,
                        ciphertext: UnsafeRawBufferPointer(message),
                        tag: UnsafeRawBufferPointer(start: tag, count: 16)
                    )
                    output = try AES.GCM.open(box, using: symmetricKey, authenticating: authenticatedData)
                }
                guard output.count == message.count else {
                    return -1
                }
                output.copyBytes(to: message)
                return 0
            }
            catch {
                return -1
            }
        }
#endif
