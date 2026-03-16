// SPDX-License-Identifier: MIT
// Copyright © 2018-2023 WireGuard LLC. All Rights Reserved.

import Foundation

/// Configuration for traffic obfuscation to bypass DPI and censorship.
/// When enabled, WireGuard traffic is disguised as random data or other protocols.
public struct ObfuscatorConfiguration: Codable, Equatable {
    /// Whether obfuscation is enabled for this tunnel.
    public var isEnabled: Bool = false

    /// The XOR key used for obfuscation (1-255 characters).
    /// A longer key provides stronger obfuscation but may impact performance.
    public var key: String = ""

    /// The type of masking to apply to obfuscated packets.
    public var maskingType: MaskingType = .auto

    /// Maximum length of dummy data to add to packets (0-1024 bytes).
    /// Higher values increase traffic randomness but reduce throughput.
    public var maxDummyLength: UInt16 = 4

    /// Creates a new obfuscator configuration with default values.
    public init() {}

    /// Creates a new obfuscator configuration with the specified values.
    public init(isEnabled: Bool = false, key: String = "", maskingType: MaskingType = .auto, maxDummyLength: UInt16 = 4) {
        self.isEnabled = isEnabled
        self.key = key
        self.maskingType = maskingType
        self.maxDummyLength = maxDummyLength
    }

    /// The type of protocol masking to apply to obfuscated traffic.
    public enum MaskingType: String, Codable, CaseIterable {
        /// No masking - traffic appears as random data.
        case none = "NONE"
        /// Auto-detect masking type from peer configuration.
        case auto = "AUTO"
        /// Mask traffic as STUN protocol packets.
        case stun = "STUN"
    }
}

// MARK: - Validation

extension ObfuscatorConfiguration {
    /// Validates the obfuscator configuration.
    /// - Returns: nil if valid, or an error message if invalid.
    public func validate() -> String? {
        // Key validation
        if isEnabled {
            guard !key.isEmpty else {
                return "Obfuscation key is required when obfuscation is enabled"
            }
            guard key.count >= 1 && key.count <= 255 else {
                return "Obfuscation key must be between 1 and 255 characters"
            }
        }

        // Max dummy length validation
        guard maxDummyLength <= 1024 else {
            return "Max dummy length must be between 0 and 1024 bytes"
        }

        return nil
    }

    /// Returns true if the configuration is valid.
    public var isValid: Bool {
        return validate() == nil
    }
}

// MARK: - Key Generation

extension ObfuscatorConfiguration {
    /// Generates a random obfuscation key of the specified length.
    /// - Parameter length: The length of the key to generate (1-255).
    /// - Returns: A random base64-encoded key.
    public static func generateKey(length: Int = 32) -> String {
        let validLength = min(max(length, 1), 255)
        var bytes = [UInt8](repeating: 0, count: validLength)
        _ = SecRandomCopyBytes(kSecRandomDefault, validLength, &bytes)
        return Data(bytes).base64EncodedString()
    }
}
