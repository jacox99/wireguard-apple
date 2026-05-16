# wg-obfuscator Integration Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Add iOS and macOS client-side wg-obfuscator compatibility by running an embedded UDP obfuscation forwarder inside the Network Extension and rewriting WireGuard runtime endpoints to loopback.

**Architecture:** The Network Extension starts one embedded `ObfuscationSession` before starting `wireguard-go`. `PacketTunnelSettingsGenerator` adds an excluded `/32` route for the real obfuscator server IPv4 and rewrites the WireGuard UAPI endpoint to `127.0.0.1:<localPort>`, preventing utun self-capture loops.

**Tech Stack:** Swift 5.5, Network.framework, NetworkExtension, XCTest, Swift Package Manager, existing WireGuardKit and WireGuardKitGo bridge.

---

## Design Source

Implement from `docs/superpowers/specs/2026-05-16-wg-obfuscator-design.md`.

Do not copy upstream `ClusterM/wg-obfuscator` GPL-3.0 source into this repository unless the product owner explicitly approves GPL-compatible distribution or obtains a separate license. This plan uses a clean-room codec boundary and an external compatibility harness.

## Scope

This plan implements the first production slice:

- One obfuscated peer per tunnel.
- IPv4 real obfuscator endpoints only.
- Obfuscation metadata stored outside wg-quick text.
- Embedded session in-process inside the packet tunnel provider.
- Route exclusion for the real obfuscator endpoint before outer UDP traffic starts.
- Codec boundary plus compatibility tests against an external upstream binary.

This plan does not implement UI controls. Tests and programmatic configuration paths come first.

## File Structure

Create:

- `Sources/WireGuardKitTypes/ObfuscationConfiguration.swift`
  - Public value types for persisted obfuscation configuration.
- `Sources/WireGuardKit/ObfuscationRuntime.swift`
  - Internal runtime endpoint override and excluded route models.
- `Sources/WireGuardKitObfuscator/ObfuscationCodec.swift`
  - Codec protocol and clean-room codec entry point.
- `Sources/WireGuardKitObfuscator/ObfuscationSession.swift`
  - Session protocol and Network.framework UDP forwarder.
- `Sources/WireGuardKitObfuscator/ObfuscationSessionFactory.swift`
  - Factory used by `WireGuardAdapter`.
- `Tests/WireGuardKitTypesTests/ObfuscationConfigurationTests.swift`
  - Configuration validation tests.
- `Tests/WireGuardKitTests/PacketTunnelSettingsGeneratorObfuscationTests.swift`
  - Endpoint override and route exclusion tests.
- `Tests/WireGuardKitObfuscatorTests/ObfuscationSessionTests.swift`
  - Local UDP forwarding tests using a fake codec.
- `Tests/WireGuardKitObfuscatorCompatibilityTests/ExternalWgObfuscatorCompatibilityTests.swift`
  - Optional external binary compatibility tests, enabled by `WG_OBFUSCATOR_BIN`.

Modify:

- `Package.swift`
  - Add `WireGuardKitObfuscator` target and test targets.
- `Sources/WireGuardKitTypes/TunnelConfiguration.swift`
  - Add optional `obfuscation` property to `TunnelConfiguration`.
- `Sources/Shared/Model/NETunnelProviderProtocol+Extension.swift`
  - Persist and restore obfuscation metadata in `providerConfiguration`.
- `Sources/WireGuardKit/PacketTunnelSettingsGenerator.swift`
  - Accept endpoint overrides and excluded IPv4 routes.
- `Sources/WireGuardKit/WireGuardAdapter.swift`
  - Start/stop obfuscation sessions, pass endpoint overrides to settings generation, and clean up on errors.
- `Sources/WireGuardNetworkExtension/PacketTunnelProvider.swift`
  - Surface new adapter errors.
- `WireGuard.xcodeproj/project.pbxproj`
  - Add the new Swift files to the build phases listed in Task 8.

## Task 1: Add Obfuscation Configuration Types

**Files:**
- Modify: `Package.swift`
- Modify: `Sources/WireGuardKitTypes/TunnelConfiguration.swift`
- Create: `Sources/WireGuardKitTypes/ObfuscationConfiguration.swift`
- Create: `Tests/WireGuardKitTypesTests/ObfuscationConfigurationTests.swift`

- [ ] **Step 1: Add failing configuration tests**

Create `Tests/WireGuardKitTypesTests/ObfuscationConfigurationTests.swift`:

```swift
import XCTest
@testable import WireGuardKitTypes

final class ObfuscationConfigurationTests: XCTestCase {
    func testValidPeerConfigurationAcceptsSupportedModes() throws {
        let publicKey = PublicKey(base64Key: "bm9uY2Vub25jZW5vbmNlbm9uY2Vub25jZW5vbmNlbm9uY2U=")!

        let stun = try PeerObfuscationConfiguration(
            peerPublicKey: publicKey,
            key: "shared-secret",
            masking: .stun,
            maxDummyBytes: 4
        )
        let auto = try PeerObfuscationConfiguration(
            peerPublicKey: publicKey,
            key: "shared-secret",
            masking: .auto,
            maxDummyBytes: 4
        )
        let none = try PeerObfuscationConfiguration(
            peerPublicKey: publicKey,
            key: "shared-secret",
            masking: .none,
            maxDummyBytes: 4
        )

        XCTAssertEqual(stun.masking, .stun)
        XCTAssertEqual(auto.masking, .auto)
        XCTAssertEqual(none.masking, .none)
    }

    func testRejectsEmptyKey() throws {
        let publicKey = PublicKey(base64Key: "bm9uY2Vub25jZW5vbmNlbm9uY2Vub25jZW5vbmNlbm9uY2U=")!

        XCTAssertThrowsError(try PeerObfuscationConfiguration(
            peerPublicKey: publicKey,
            key: "",
            masking: .auto,
            maxDummyBytes: 4
        )) { error in
            XCTAssertEqual(error as? ObfuscationConfigurationError, .invalidKeyLength)
        }
    }

    func testRejectsKeyLongerThan255Utf8Bytes() throws {
        let publicKey = PublicKey(base64Key: "bm9uY2Vub25jZW5vbmNlbm9uY2Vub25jZW5vbmNlbm9uY2U=")!
        let longKey = String(repeating: "a", count: 256)

        XCTAssertThrowsError(try PeerObfuscationConfiguration(
            peerPublicKey: publicKey,
            key: longKey,
            masking: .auto,
            maxDummyBytes: 4
        )) { error in
            XCTAssertEqual(error as? ObfuscationConfigurationError, .invalidKeyLength)
        }
    }

    func testLookupByPeerPublicKey() throws {
        let publicKey = PublicKey(base64Key: "bm9uY2Vub25jZW5vbmNlbm9uY2Vub25jZW5vbmNlbm9uY2U=")!
        let peer = try PeerObfuscationConfiguration(
            peerPublicKey: publicKey,
            key: "shared-secret",
            masking: .stun,
            maxDummyBytes: 4
        )
        let configuration = ObfuscationConfiguration(peers: [peer])

        XCTAssertEqual(configuration.configuration(for: publicKey), peer)
    }
}
```

- [ ] **Step 2: Add test target to Package.swift**

Modify `Package.swift` test targets:

```swift
.testTarget(
    name: "WireGuardKitTypesTests",
    dependencies: ["WireGuardKitTypes"]
)
```

Place it after the existing targets array entries and keep the trailing comma style valid.

- [ ] **Step 3: Run the tests to verify they fail**

Run:

```bash
swift test --filter ObfuscationConfigurationTests
```

Expected: FAIL because `PeerObfuscationConfiguration`, `ObfuscationConfiguration`, and `ObfuscationConfigurationError` do not exist.

- [ ] **Step 4: Add configuration implementation**

Create `Sources/WireGuardKitTypes/ObfuscationConfiguration.swift`:

```swift
// SPDX-License-Identifier: MIT
// Copyright © 2026 WireGuard LLC. All Rights Reserved.

import Foundation

public enum ObfuscationMasking: String, Codable, Equatable, CaseIterable {
    case stun = "STUN"
    case auto = "AUTO"
    case none = "NONE"
}

public enum ObfuscationConfigurationError: Error, Equatable {
    case invalidKeyLength
    case invalidMaxDummyBytes
    case duplicatePeer(PublicKey)
}

public struct PeerObfuscationConfiguration: Codable, Equatable, Hashable {
    public let peerPublicKey: PublicKey
    public let key: String
    public let masking: ObfuscationMasking
    public let maxDummyBytes: UInt16

    public init(peerPublicKey: PublicKey, key: String, masking: ObfuscationMasking, maxDummyBytes: UInt16 = 4) throws {
        let keyLength = key.lengthOfBytes(using: .utf8)
        guard (1...255).contains(keyLength) else {
            throw ObfuscationConfigurationError.invalidKeyLength
        }
        guard maxDummyBytes <= 1024 else {
            throw ObfuscationConfigurationError.invalidMaxDummyBytes
        }

        self.peerPublicKey = peerPublicKey
        self.key = key
        self.masking = masking
        self.maxDummyBytes = maxDummyBytes
    }
}

public struct ObfuscationConfiguration: Codable, Equatable, Hashable {
    public let peers: [PeerObfuscationConfiguration]

    public init(peers: [PeerObfuscationConfiguration]) {
        self.peers = peers
    }

    public func validatedForSinglePeer() throws -> ObfuscationConfiguration {
        var seen = Set<PublicKey>()
        for peer in peers {
            guard seen.insert(peer.peerPublicKey).inserted else {
                throw ObfuscationConfigurationError.duplicatePeer(peer.peerPublicKey)
            }
        }
        return self
    }

    public func configuration(for publicKey: PublicKey) -> PeerObfuscationConfiguration? {
        peers.first { $0.peerPublicKey == publicKey }
    }
}
```

Modify `Sources/WireGuardKitTypes/TunnelConfiguration.swift`:

```swift
public final class TunnelConfiguration {
    public var name: String?
    public var interface: InterfaceConfiguration
    public let peers: [PeerConfiguration]
    public let pingableGateway: IPv4Address?
    public var obfuscation: ObfuscationConfiguration?

    public init(name: String?, interface: InterfaceConfiguration, peers: [PeerConfiguration], pingableGateway: IPv4Address? = nil, obfuscation: ObfuscationConfiguration? = nil) {
        self.interface = interface
        self.peers = peers
        self.name = name
        self.pingableGateway = pingableGateway
        self.obfuscation = obfuscation

        let peerPublicKeysArray = peers.map { $0.publicKey }
        let peerPublicKeysSet = Set<PublicKey>(peerPublicKeysArray)
        if peerPublicKeysArray.count != peerPublicKeysSet.count {
            fatalError("Two or more peers cannot have the same public key")
        }
    }
}
```

Update `TunnelConfiguration ==` to include obfuscation:

```swift
return lhs.name == rhs.name &&
    lhs.interface == rhs.interface &&
    Set(lhs.peers) == Set(rhs.peers) &&
    lhs.obfuscation == rhs.obfuscation
```

- [ ] **Step 5: Run tests**

Run:

```bash
swift test --filter ObfuscationConfigurationTests
```

Expected: PASS.

- [ ] **Step 6: Commit**

Run:

```bash
git add Package.swift Sources/WireGuardKitTypes/TunnelConfiguration.swift Sources/WireGuardKitTypes/ObfuscationConfiguration.swift Tests/WireGuardKitTypesTests/ObfuscationConfigurationTests.swift
git commit -m "feat: add obfuscation configuration model"
```

## Task 2: Persist Obfuscation Metadata in Provider Configuration

**Files:**
- Modify: `Sources/Shared/Model/NETunnelProviderProtocol+Extension.swift`
- Create: `Tests/WireGuardKitTypesTests/ObfuscationProviderCodingTests.swift`

- [ ] **Step 1: Add failing property-list round-trip tests**

Create `Tests/WireGuardKitTypesTests/ObfuscationProviderCodingTests.swift`:

```swift
import XCTest
@testable import WireGuardKitTypes

final class ObfuscationProviderCodingTests: XCTestCase {
    func testPropertyListDictionaryRoundTrip() throws {
        let publicKey = PublicKey(base64Key: "bm9uY2Vub25jZW5vbmNlbm9uY2Vub25jZW5vbmNlbm9uY2U=")!
        let peer = try PeerObfuscationConfiguration(
            peerPublicKey: publicKey,
            key: "shared-secret",
            masking: .stun,
            maxDummyBytes: 8
        )
        let configuration = ObfuscationConfiguration(peers: [peer])

        let dictionary = try configuration.asProviderConfigurationDictionary()
        let decoded = try ObfuscationConfiguration(providerConfigurationDictionary: dictionary)

        XCTAssertEqual(decoded, configuration)
    }

    func testRejectsMalformedPropertyListDictionary() throws {
        XCTAssertThrowsError(try ObfuscationConfiguration(providerConfigurationDictionary: ["peers": "wrong"]))
    }
}
```

- [ ] **Step 2: Run test to verify it fails**

Run:

```bash
swift test --filter ObfuscationProviderCodingTests
```

Expected: FAIL because provider dictionary helpers do not exist.

- [ ] **Step 3: Add provider dictionary helpers**

Add to `Sources/WireGuardKitTypes/ObfuscationConfiguration.swift`:

```swift
public enum ObfuscationProviderCodingError: Error, Equatable {
    case notPropertyListEncodable
    case invalidDictionary
}

extension ObfuscationConfiguration {
    public init(providerConfigurationDictionary dictionary: [String: Any]) throws {
        guard JSONSerialization.isValidJSONObject(dictionary),
              let data = try? JSONSerialization.data(withJSONObject: dictionary),
              let decoded = try? JSONDecoder().decode(ObfuscationConfiguration.self, from: data) else {
            throw ObfuscationProviderCodingError.invalidDictionary
        }
        self = decoded
    }

    public func asProviderConfigurationDictionary() throws -> [String: Any] {
        let data = try JSONEncoder().encode(self)
        let object = try JSONSerialization.jsonObject(with: data)
        guard let dictionary = object as? [String: Any],
              JSONSerialization.isValidJSONObject(dictionary) else {
            throw ObfuscationProviderCodingError.notPropertyListEncodable
        }
        return dictionary
    }
}
```

- [ ] **Step 4: Thread persistence through NETunnelProviderProtocol**

Modify `Sources/Shared/Model/NETunnelProviderProtocol+Extension.swift` so `providerConfiguration` preserves both macOS `UID` and obfuscation:

```swift
private enum ProviderConfigurationKey {
    static let uid = "UID"
    static let obfuscation = "Obfuscation"
}
```

In `init?(tunnelConfiguration:previouslyFrom:)`, replace direct `providerConfiguration = ["UID": getuid()]` with:

```swift
var providerConfig = [String: Any]()
#if os(macOS)
providerConfig[ProviderConfigurationKey.uid] = getuid()
#endif
if let obfuscation = tunnelConfiguration.obfuscation,
   let dictionary = try? obfuscation.asProviderConfigurationDictionary() {
    providerConfig[ProviderConfigurationKey.obfuscation] = dictionary
}
providerConfiguration = providerConfig.isEmpty ? nil : providerConfig
```

In `asTunnelConfiguration(called:)`, after parsing wg-quick:

```swift
let tunnelConfiguration = try? TunnelConfiguration(fromWgQuickConfig: config, called: name)
if let obfuscationDictionary = providerConfiguration?[ProviderConfigurationKey.obfuscation] as? [String: Any],
   let obfuscation = try? ObfuscationConfiguration(providerConfigurationDictionary: obfuscationDictionary) {
    tunnelConfiguration?.obfuscation = obfuscation
}
return tunnelConfiguration
```

Apply the same obfuscation restoration to the `oldConfig` fallback branch.

- [ ] **Step 5: Run tests**

Run:

```bash
swift test --filter ObfuscationProviderCodingTests
```

Expected: PASS.

- [ ] **Step 6: Commit**

Run:

```bash
git add Sources/WireGuardKitTypes/ObfuscationConfiguration.swift Sources/Shared/Model/NETunnelProviderProtocol+Extension.swift Tests/WireGuardKitTypesTests/ObfuscationProviderCodingTests.swift
git commit -m "feat: persist obfuscation provider metadata"
```

## Task 3: Add Endpoint Overrides and Route Exclusions

**Files:**
- Create: `Sources/WireGuardKit/ObfuscationRuntime.swift`
- Modify: `Sources/WireGuardKit/PacketTunnelSettingsGenerator.swift`
- Create: `Tests/WireGuardKitTests/PacketTunnelSettingsGeneratorObfuscationTests.swift`

- [ ] **Step 1: Add failing generator tests**

Create `Tests/WireGuardKitTests/PacketTunnelSettingsGeneratorObfuscationTests.swift`:

```swift
import XCTest
import Network
import NetworkExtension
@testable import WireGuardKit
@testable import WireGuardKitTypes

final class PacketTunnelSettingsGeneratorObfuscationTests: XCTestCase {
    func testUapiUsesLoopbackEndpointForObfuscatedPeer() throws {
        let publicKey = PublicKey(base64Key: "bm9uY2Vub25jZW5vbmNlbm9uY2Vub25jZW5vbmNlbm9uY2U=")!
        let privateKey = PrivateKey(base64Key: "mIhH5n9U7N3E5wEHVY+ExnJ+X5k7c9yXWmM6p1sQDXA=")!
        var interface = InterfaceConfiguration(privateKey: privateKey)
        interface.addresses = [IPAddressRange(from: "10.0.0.2/32")!]

        var peer = PeerConfiguration(publicKey: publicKey)
        peer.endpoint = Endpoint(from: "198.51.100.10:19999")
        peer.allowedIPs = [IPAddressRange(from: "0.0.0.0/0")!]

        let tunnel = TunnelConfiguration(name: "obfs", interface: interface, peers: [peer])
        let resolvedEndpoint = Endpoint(from: "198.51.100.10:19999")!
        let loopbackEndpoint = Endpoint(from: "127.0.0.1:40000")!
        let runtime = ObfuscationRuntime(
            endpointOverrides: [publicKey: loopbackEndpoint],
            excludedIPv4Addresses: [IPv4Address("198.51.100.10")!]
        )

        let generator = PacketTunnelSettingsGenerator(
            exit: DeviceConfiguration(
                configuration: tunnel,
                resolvedEndpoints: [resolvedEndpoint],
                reResolveEndpoint: false
            ),
            obfuscationRuntime: runtime
        )

        let (uapi, _) = generator.uapiConfiguration()

        XCTAssertTrue(uapi.contains("endpoint=127.0.0.1:40000"))
        XCTAssertFalse(uapi.contains("endpoint=198.51.100.10:19999"))
    }

    func testNetworkSettingsExcludeRealObfuscatorIPv4() throws {
        let publicKey = PublicKey(base64Key: "bm9uY2Vub25jZW5vbmNlbm9uY2Vub25jZW5vbmNlbm9uY2U=")!
        let privateKey = PrivateKey(base64Key: "mIhH5n9U7N3E5wEHVY+ExnJ+X5k7c9yXWmM6p1sQDXA=")!
        var interface = InterfaceConfiguration(privateKey: privateKey)
        interface.addresses = [IPAddressRange(from: "10.0.0.2/32")!]

        var peer = PeerConfiguration(publicKey: publicKey)
        peer.endpoint = Endpoint(from: "198.51.100.10:19999")
        peer.allowedIPs = [IPAddressRange(from: "0.0.0.0/0")!]

        let tunnel = TunnelConfiguration(name: "obfs", interface: interface, peers: [peer])
        let runtime = ObfuscationRuntime(
            endpointOverrides: [:],
            excludedIPv4Addresses: [IPv4Address("198.51.100.10")!]
        )
        let generator = PacketTunnelSettingsGenerator(
            exit: DeviceConfiguration(
                configuration: tunnel,
                resolvedEndpoints: [peer.endpoint],
                reResolveEndpoint: false
            ),
            obfuscationRuntime: runtime
        )

        let settings = generator.generateNetworkSettings()
        let excluded = settings.ipv4Settings?.excludedRoutes ?? []

        XCTAssertEqual(excluded.map(\.destinationAddress), ["198.51.100.10"])
        XCTAssertEqual(excluded.map(\.destinationSubnetMask), ["255.255.255.255"])
    }
}
```

- [ ] **Step 2: Add test target to Package.swift**

Add:

```swift
.testTarget(
    name: "WireGuardKitTests",
    dependencies: ["WireGuardKit", "WireGuardKitTypes"]
),
```

- [ ] **Step 3: Run tests to verify they fail**

Run:

```bash
swift test --filter PacketTunnelSettingsGeneratorObfuscationTests
```

Expected: FAIL because `ObfuscationRuntime` and `PacketTunnelSettingsGenerator(..., obfuscationRuntime:)` do not exist.

- [ ] **Step 4: Add runtime model**

Create `Sources/WireGuardKit/ObfuscationRuntime.swift`:

```swift
// SPDX-License-Identifier: MIT
// Copyright © 2026 WireGuard LLC. All Rights Reserved.

import Foundation
import NetworkExtension

#if SWIFT_PACKAGE
import WireGuardKitTypes
#endif

struct ObfuscationRuntime {
    let endpointOverrides: [PublicKey: Endpoint]
    let excludedIPv4Addresses: [IPv4Address]

    static let empty = ObfuscationRuntime(endpointOverrides: [:], excludedIPv4Addresses: [])

    func endpointOverride(for publicKey: PublicKey) -> Endpoint? {
        endpointOverrides[publicKey]
    }

    func excludedIPv4Routes() -> [NEIPv4Route] {
        excludedIPv4Addresses.map {
            NEIPv4Route(destinationAddress: "\($0)", subnetMask: "255.255.255.255")
        }
    }
}
```

- [ ] **Step 5: Modify settings generator**

In `Sources/WireGuardKit/PacketTunnelSettingsGenerator.swift`, add `obfuscationRuntime` to `DeviceConfiguration`:

```swift
struct DeviceConfiguration {
    let configuration: TunnelConfiguration
    let resolvedEndpoints: [Endpoint?]
    let reResolveEndpoint: Bool
    let obfuscationRuntime: ObfuscationRuntime
```

Add a defaulted initializer if needed:

```swift
init(configuration: TunnelConfiguration, resolvedEndpoints: [Endpoint?], reResolveEndpoint: Bool, obfuscationRuntime: ObfuscationRuntime = .empty) {
    self.configuration = configuration
    self.resolvedEndpoints = resolvedEndpoints
    self.reResolveEndpoint = reResolveEndpoint
    self.obfuscationRuntime = obfuscationRuntime
}
```

After `ipv4Settings.includedRoutes = ipv4IncludedRoutes`, add:

```swift
let excludedRoutes = obfuscationRuntime.excludedIPv4Routes()
if !excludedRoutes.isEmpty {
    ipv4Settings.excludedRoutes = excludedRoutes
}
```

In both `endpointUapiConfiguration()` and `uapiConfiguration(for:)`, before writing a resolved endpoint, prefer override:

```swift
if let override = device.obfuscationRuntime.endpointOverride(for: peer.publicKey) {
    wgSettings.append("endpoint=\(override.stringRepresentation)\n")
} else if device.reResolveEndpoint {
    let result = resolvedEndpoint.map(Self.reresolveEndpoint)
    if case .success((_, let resolvedEndpoint)) = result {
        if case .name = resolvedEndpoint.host { assert(false, "Endpoint is not resolved") }
        wgSettings.append("endpoint=\(resolvedEndpoint.stringRepresentation)\n")
    }
    resolutionResults.append(result)
} else {
    resolvedEndpoint.map {
        wgSettings.append("endpoint=\($0.stringRepresentation)\n")
    }
}
```

Add `obfuscationRuntime` to `PacketTunnelSettingsGenerator`:

```swift
class PacketTunnelSettingsGenerator {
    let exit: DeviceConfiguration
    let entry: DeviceConfiguration?
    let daita: DaitaConfiguration?
    let obfuscationRuntime: ObfuscationRuntime

    init(exit: DeviceConfiguration, entry: DeviceConfiguration? = nil, daita: DaitaConfiguration? = nil, obfuscationRuntime: ObfuscationRuntime = .empty) {
        self.exit = exit
        self.entry = entry
        self.daita = daita
        self.obfuscationRuntime = obfuscationRuntime
    }
}
```

Pass the runtime into the exit `DeviceConfiguration` before generator creation.

- [ ] **Step 6: Run tests**

Run:

```bash
swift test --filter PacketTunnelSettingsGeneratorObfuscationTests
```

Expected: PASS.

- [ ] **Step 7: Commit**

Run:

```bash
git add Package.swift Sources/WireGuardKit/ObfuscationRuntime.swift Sources/WireGuardKit/PacketTunnelSettingsGenerator.swift Tests/WireGuardKitTests/PacketTunnelSettingsGeneratorObfuscationTests.swift
git commit -m "feat: rewrite obfuscated peer endpoints"
```

## Task 4: Add Obfuscator Module and Fake-Codec Session Tests

**Files:**
- Modify: `Package.swift`
- Create: `Sources/WireGuardKitObfuscator/ObfuscationCodec.swift`
- Create: `Sources/WireGuardKitObfuscator/ObfuscationSession.swift`
- Create: `Sources/WireGuardKitObfuscator/ObfuscationSessionFactory.swift`
- Create: `Tests/WireGuardKitObfuscatorTests/ObfuscationSessionTests.swift`

- [ ] **Step 1: Add failing session test**

Create `Tests/WireGuardKitObfuscatorTests/ObfuscationSessionTests.swift`:

```swift
import XCTest
import Network
@testable import WireGuardKitObfuscator

final class ObfuscationSessionTests: XCTestCase {
    func testOutboundPacketIsEncodedAndSentToRemoteEndpoint() async throws {
        let remote = try UDPTestServer()
        try await remote.start()

        let codec = PrefixTestCodec(prefix: Data([0xAA, 0xBB]))
        let session = EmbeddedObfuscationSession(
            targetHost: "127.0.0.1",
            targetPort: remote.port,
            codec: codec
        )
        try await session.start()
        defer { session.stop() }

        let localClient = try UDPTestClient()
        try await localClient.send(Data([0x01, 0x02, 0x03]), toPort: session.localPort)

        let received = try await remote.receive(timeout: 2.0)
        XCTAssertEqual(received, Data([0xAA, 0xBB, 0x01, 0x02, 0x03]))
    }
}

private struct PrefixTestCodec: ObfuscationPacketCodec {
    let prefix: Data

    func encodeOutbound(_ packet: Data) throws -> Data {
        prefix + packet
    }

    func decodeInbound(_ packet: Data) throws -> Data {
        guard packet.starts(with: prefix) else { throw ObfuscationCodecError.invalidPacket }
        return packet.dropFirst(prefix.count)
    }
}
```

Add small test helpers in the same file:

```swift
private final class UDPTestServer {
    private let listener: NWListener
    private var continuation: CheckedContinuation<Data, Error>?
    private(set) var port: UInt16 = 0

    init() throws {
        listener = try NWListener(using: .udp, on: 0)
    }

    func start() async throws {
        listener.newConnectionHandler = { [weak self] connection in
            connection.start(queue: .global())
            self?.receive(on: connection)
        }
        listener.start(queue: .global())
        guard case .port(let nwPort) = listener.port else {
            throw NSError(domain: "UDPTestServer", code: 1)
        }
        port = nwPort.rawValue
    }

    func receive(timeout: TimeInterval) async throws -> Data {
        try await withThrowingTaskGroup(of: Data.self) { group in
            group.addTask {
                try await withCheckedThrowingContinuation { continuation in
                    self.continuation = continuation
                }
            }
            group.addTask {
                try await Task.sleep(nanoseconds: UInt64(timeout * 1_000_000_000))
                throw NSError(domain: "UDPTestServer", code: 2)
            }
            let value = try await group.next()!
            group.cancelAll()
            return value
        }
    }

    private func receive(on connection: NWConnection) {
        connection.receiveMessage { [weak self] data, _, _, error in
            if let data {
                self?.continuation?.resume(returning: data)
            } else {
                self?.continuation?.resume(throwing: error ?? NSError(domain: "UDPTestServer", code: 3))
            }
        }
    }
}

private final class UDPTestClient {
    func send(_ data: Data, toPort port: UInt16) async throws {
        let connection = NWConnection(host: "127.0.0.1", port: NWEndpoint.Port(rawValue: port)!, using: .udp)
        connection.start(queue: .global())
        try await withCheckedThrowingContinuation { continuation in
            connection.send(content: data, completion: .contentProcessed { error in
                if let error {
                    continuation.resume(throwing: error)
                } else {
                    continuation.resume()
                }
                connection.cancel()
            })
        }
    }
}
```

- [ ] **Step 2: Add module target**

Modify `Package.swift`:

```swift
.library(name: "WireGuardKitObfuscator", targets: ["WireGuardKitObfuscator"]),
```

Add target:

```swift
.target(
    name: "WireGuardKitObfuscator",
    dependencies: ["WireGuardKitTypes"]
),
```

Add test target:

```swift
.testTarget(
    name: "WireGuardKitObfuscatorTests",
    dependencies: ["WireGuardKitObfuscator", "WireGuardKitTypes"]
),
```

- [ ] **Step 3: Run test to verify it fails**

Run:

```bash
swift test --filter ObfuscationSessionTests
```

Expected: FAIL because the obfuscator module types do not exist.

- [ ] **Step 4: Add codec boundary**

Create `Sources/WireGuardKitObfuscator/ObfuscationCodec.swift`:

```swift
// SPDX-License-Identifier: MIT
// Copyright © 2026 WireGuard LLC. All Rights Reserved.

import Foundation
import WireGuardKitTypes

public enum ObfuscationCodecError: Error, Equatable {
    case invalidPacket
    case unsupportedMasking(ObfuscationMasking)
}

public protocol ObfuscationPacketCodec {
    func encodeOutbound(_ packet: Data) throws -> Data
    func decodeInbound(_ packet: Data) throws -> Data
}

public struct WgObfuscatorCompatibleCodec: ObfuscationPacketCodec {
    public let key: String
    public let masking: ObfuscationMasking
    public let maxDummyBytes: UInt16

    public init(key: String, masking: ObfuscationMasking, maxDummyBytes: UInt16) {
        self.key = key
        self.masking = masking
        self.maxDummyBytes = maxDummyBytes
    }

    public func encodeOutbound(_ packet: Data) throws -> Data {
        throw ObfuscationCodecError.invalidPacket
    }

    public func decodeInbound(_ packet: Data) throws -> Data {
        throw ObfuscationCodecError.invalidPacket
    }
}
```

The clean-room codec intentionally fails until Task 7 replaces it. The session tests use `PrefixTestCodec`, so they can pass without protocol compatibility work.

- [ ] **Step 5: Add session implementation**

Create `Sources/WireGuardKitObfuscator/ObfuscationSession.swift`:

```swift
// SPDX-License-Identifier: MIT
// Copyright © 2026 WireGuard LLC. All Rights Reserved.

import Foundation
import Network

public enum ObfuscationSessionError: Error, Equatable {
    case localPortUnavailable
    case notStarted
    case missingLocalWireGuardSource
}

public protocol ObfuscationSession: AnyObject {
    var localPort: UInt16 { get }
    func start() async throws
    func stop()
    func updateTarget(host: NWEndpoint.Host, port: NWEndpoint.Port)
}

public final class EmbeddedObfuscationSession: ObfuscationSession {
    public private(set) var localPort: UInt16 = 0

    private var listener: NWListener?
    private var localWireGuardConnection: NWConnection?
    private var remoteConnection: NWConnection?
    private var targetHost: NWEndpoint.Host
    private var targetPort: NWEndpoint.Port
    private let codec: ObfuscationPacketCodec
    private let queue = DispatchQueue(label: "EmbeddedObfuscationSession")

    public init(targetHost: NWEndpoint.Host, targetPort: NWEndpoint.Port, codec: ObfuscationPacketCodec) {
        self.targetHost = targetHost
        self.targetPort = targetPort
        self.codec = codec
    }

    public convenience init(targetHost: String, targetPort: UInt16, codec: ObfuscationPacketCodec) {
        self.init(targetHost: NWEndpoint.Host(targetHost), targetPort: NWEndpoint.Port(rawValue: targetPort)!, codec: codec)
    }

    public func start() async throws {
        let listener = try NWListener(using: .udp, on: 0)
        listener.newConnectionHandler = { [weak self] connection in
            self?.localWireGuardConnection = connection
            connection.start(queue: self?.queue ?? .global())
            self?.receiveLocal(on: connection)
        }
        listener.start(queue: queue)
        guard let port = listener.port?.rawValue else {
            listener.cancel()
            throw ObfuscationSessionError.localPortUnavailable
        }
        self.listener = listener
        self.localPort = port
        startRemoteConnection()
    }

    public func stop() {
        listener?.cancel()
        listener = nil
        localWireGuardConnection?.cancel()
        localWireGuardConnection = nil
        remoteConnection?.cancel()
        remoteConnection = nil
        localPort = 0
    }

    public func updateTarget(host: NWEndpoint.Host, port: NWEndpoint.Port) {
        queue.async {
            self.targetHost = host
            self.targetPort = port
            self.remoteConnection?.cancel()
            self.startRemoteConnection()
        }
    }

    private func startRemoteConnection() {
        let connection = NWConnection(host: targetHost, port: targetPort, using: .udp)
        remoteConnection = connection
        connection.start(queue: queue)
        receiveRemote(on: connection)
    }

    private func receiveLocal(on connection: NWConnection) {
        connection.receiveMessage { [weak self] data, _, _, _ in
            guard let self else { return }
            if let data, let encoded = try? self.codec.encodeOutbound(data) {
                self.remoteConnection?.send(content: encoded, completion: .contentProcessed { _ in })
            }
            self.receiveLocal(on: connection)
        }
    }

    private func receiveRemote(on connection: NWConnection) {
        connection.receiveMessage { [weak self] data, _, _, _ in
            guard let self else { return }
            if let data, let decoded = try? self.codec.decodeInbound(data) {
                self.localWireGuardConnection?.send(content: decoded, completion: .contentProcessed { _ in })
            }
            self.receiveRemote(on: connection)
        }
    }
}
```

- [ ] **Step 6: Add factory**

Create `Sources/WireGuardKitObfuscator/ObfuscationSessionFactory.swift`:

```swift
// SPDX-License-Identifier: MIT
// Copyright © 2026 WireGuard LLC. All Rights Reserved.

import Foundation
import Network
import WireGuardKitTypes

public protocol ObfuscationSessionFactory {
    func makeSession(targetHost: NWEndpoint.Host, targetPort: NWEndpoint.Port, peerConfiguration: PeerObfuscationConfiguration) -> ObfuscationSession
}

public struct DefaultObfuscationSessionFactory: ObfuscationSessionFactory {
    public init() {}

    public func makeSession(targetHost: NWEndpoint.Host, targetPort: NWEndpoint.Port, peerConfiguration: PeerObfuscationConfiguration) -> ObfuscationSession {
        let codec = WgObfuscatorCompatibleCodec(
            key: peerConfiguration.key,
            masking: peerConfiguration.masking,
            maxDummyBytes: peerConfiguration.maxDummyBytes
        )
        return EmbeddedObfuscationSession(targetHost: targetHost, targetPort: targetPort, codec: codec)
    }
}
```

- [ ] **Step 7: Run tests**

Run:

```bash
swift test --filter ObfuscationSessionTests
```

Expected: PASS.

- [ ] **Step 8: Commit**

Run:

```bash
git add Package.swift Sources/WireGuardKitObfuscator Tests/WireGuardKitObfuscatorTests
git commit -m "feat: add embedded obfuscation session"
```

## Task 5: Wire Obfuscation Sessions into WireGuardAdapter

**Files:**
- Modify: `Sources/WireGuardKit/WireGuardAdapter.swift`
- Modify: `Sources/WireGuardNetworkExtension/PacketTunnelProvider.swift`
- Modify: `Package.swift`

- [ ] **Step 1: Add adapter error cases**

Modify `WireGuardAdapterError` in `Sources/WireGuardKit/WireGuardAdapter.swift`:

```swift
case obfuscationConfiguration(String)
case obfuscationStart(String)
case obfuscationRouteUpdate(String)
```

Update `PacketTunnelProvider.startTunnel` switch:

```swift
case .obfuscationConfiguration(let message):
    wg_log(.error, message: "Starting tunnel failed with invalid obfuscation configuration: \(message)")
    errorNotifier.notify(PacketTunnelProviderError.couldNotStartBackend)
    completionHandler(PacketTunnelProviderError.couldNotStartBackend)

case .obfuscationStart(let message):
    wg_log(.error, message: "Starting tunnel failed while starting obfuscation: \(message)")
    errorNotifier.notify(PacketTunnelProviderError.couldNotStartBackend)
    completionHandler(PacketTunnelProviderError.couldNotStartBackend)

case .obfuscationRouteUpdate(let message):
    wg_log(.error, message: "Starting tunnel failed while applying obfuscation routes: \(message)")
    errorNotifier.notify(PacketTunnelProviderError.couldNotSetNetworkSettings)
    completionHandler(PacketTunnelProviderError.couldNotSetNetworkSettings)
```

- [ ] **Step 2: Add dependency on WireGuardKitObfuscator**

Modify `Package.swift`:

```swift
.target(
    name: "WireGuardKit",
    dependencies: ["WireGuardKitGo", "WireGuardKitTypes", "WireGuardKitObfuscator"]
),
```

Add import in `WireGuardAdapter.swift`:

```swift
#if SWIFT_PACKAGE
import WireGuardKitObfuscator
#endif
```

- [ ] **Step 3: Add session state**

Add to `WireGuardAdapter`:

```swift
private var obfuscationSessions = [PublicKey: ObfuscationSession]()
private let obfuscationSessionFactory: ObfuscationSessionFactory
```

Change initializer:

```swift
public init(
    with packetTunnelProvider: NEPacketTunnelProvider,
    shouldHandleReasserting: Bool = true,
    obfuscationSessionFactory: ObfuscationSessionFactory = DefaultObfuscationSessionFactory(),
    logHandler: @escaping LogHandler
) {
    self.packetTunnelProvider = packetTunnelProvider
    self.shouldHandleReasserting = shouldHandleReasserting
    self.obfuscationSessionFactory = obfuscationSessionFactory
    self.logHandler = logHandler

    setupLogHandler()
}
```

- [ ] **Step 4: Add runtime preparation helper**

Add to `WireGuardAdapter`:

```swift
private func prepareObfuscationRuntime(for configuration: TunnelConfiguration, resolvedEndpoints: [Endpoint?]) throws -> ObfuscationRuntime {
    guard let obfuscation = configuration.obfuscation, !obfuscation.peers.isEmpty else {
        stopObfuscationSessions()
        return .empty
    }

    guard obfuscation.peers.count == 1 else {
        throw WireGuardAdapterError.obfuscationConfiguration("Only one obfuscated peer is supported")
    }

    let peerObfuscation = obfuscation.peers[0]
    guard let peerIndex = configuration.peers.firstIndex(where: { $0.publicKey == peerObfuscation.peerPublicKey }) else {
        throw WireGuardAdapterError.obfuscationConfiguration("Obfuscated peer public key is not present in tunnel configuration")
    }
    guard let resolvedEndpoint = resolvedEndpoints[peerIndex] else {
        throw WireGuardAdapterError.obfuscationConfiguration("Obfuscated peer has no endpoint")
    }
    guard case .ipv4(let targetIPv4) = resolvedEndpoint.host else {
        throw WireGuardAdapterError.obfuscationConfiguration("Obfuscated peer endpoint must resolve to IPv4")
    }

    let targetPort = resolvedEndpoint.port
    let session = obfuscationSessionFactory.makeSession(
        targetHost: .ipv4(targetIPv4),
        targetPort: targetPort,
        peerConfiguration: peerObfuscation
    )

    let semaphore = DispatchSemaphore(value: 0)
    var startError: Error?
    Task {
        do {
            try await session.start()
        } catch {
            startError = error
        }
        semaphore.signal()
    }
    semaphore.wait()

    if let startError {
        throw WireGuardAdapterError.obfuscationStart(String(describing: startError))
    }

    stopObfuscationSessions()
    obfuscationSessions[peerObfuscation.peerPublicKey] = session

    let localEndpoint = Endpoint(host: .ipv4(IPv4Address("127.0.0.1")!), port: NWEndpoint.Port(rawValue: session.localPort)!)
    return ObfuscationRuntime(
        endpointOverrides: [peerObfuscation.peerPublicKey: localEndpoint],
        excludedIPv4Addresses: [targetIPv4]
    )
}

private func stopObfuscationSessions() {
    obfuscationSessions.values.forEach { $0.stop() }
    obfuscationSessions.removeAll()
}
```

- [ ] **Step 5: Pass runtime into settings generator**

In `makeSettingsGenerator(...)`, after resolving exit endpoints:

```swift
let obfuscationRuntime = try prepareObfuscationRuntime(for: exitConfiguration, resolvedEndpoints: resolvedExitEndpoints)
```

Create exit device with runtime:

```swift
exit: DeviceConfiguration(
    configuration: exitConfiguration,
    resolvedEndpoints: resolvedExitEndpoints,
    reResolveEndpoint: entry == nil,
    obfuscationRuntime: obfuscationRuntime
),
```

Pass `obfuscationRuntime` to `PacketTunnelSettingsGenerator`.

- [ ] **Step 6: Stop sessions during cleanup**

In `stop(completionHandler:)`, after `wgTurnOff(handle)` and temporary shutdown handling:

```swift
self.stopObfuscationSessions()
```

In `deinit`, after `wgTurnOff(handle)`:

```swift
stopObfuscationSessions()
```

In `startMultihop` catch block before completion:

```swift
self.stopObfuscationSessions()
```

- [ ] **Step 7: Run targeted tests**

Run:

```bash
swift test --filter ObfuscationConfigurationTests
swift test --filter PacketTunnelSettingsGeneratorObfuscationTests
swift test --filter ObfuscationSessionTests
```

Expected: PASS.

- [ ] **Step 8: Commit**

Run:

```bash
git add Package.swift Sources/WireGuardKit/WireGuardAdapter.swift Sources/WireGuardNetworkExtension/PacketTunnelProvider.swift
git commit -m "feat: start obfuscation sessions from adapter"
```

## Task 6: Handle Network Changes Without Reintroducing utun Loops

**Files:**
- Modify: `Sources/WireGuardKit/WireGuardAdapter.swift`
- Modify: `Sources/WireGuardKit/PacketTunnelSettingsGenerator.swift`
- Test: `Tests/WireGuardKitTests/PacketTunnelSettingsGeneratorObfuscationTests.swift`

- [ ] **Step 1: Add route update regression test**

Append to `PacketTunnelSettingsGeneratorObfuscationTests`:

```swift
func testEndpointUpdateKeepsLoopbackEndpointAndExcludedRoute() throws {
    let publicKey = PublicKey(base64Key: "bm9uY2Vub25jZW5vbmNlbm9uY2Vub25jZW5vbmNlbm9uY2U=")!
    let runtime = ObfuscationRuntime(
        endpointOverrides: [publicKey: Endpoint(from: "127.0.0.1:40000")!],
        excludedIPv4Addresses: [IPv4Address("203.0.113.22")!]
    )

    XCTAssertEqual(runtime.endpointOverride(for: publicKey)?.stringRepresentation, "127.0.0.1:40000")
    XCTAssertEqual(runtime.excludedIPv4Routes().first?.destinationAddress, "203.0.113.22")
}
```

- [ ] **Step 2: Run test**

Run:

```bash
swift test --filter PacketTunnelSettingsGeneratorObfuscationTests/testEndpointUpdateKeepsLoopbackEndpointAndExcludedRoute
```

Expected: PASS after Task 3.

- [ ] **Step 3: Update path-change behavior**

In iOS `didReceivePathUpdate`, before calling `settingsGenerator.endpointUapiConfiguration()`, detect obfuscation runtime:

```swift
let (wgConfig, resolutionResults) = settingsGenerator.endpointUapiConfiguration()
self.logEndpointResolutionResults(resolutionResults)

if !settingsGenerator.obfuscationRuntime.excludedIPv4Addresses.isEmpty {
    let networkSettings = settingsGenerator.generateNetworkSettings()
    self.packetTunnelProvider?.setTunnelNetworkSettings(networkSettings) { error in
        if let error {
            self.logHandler(.error, "Failed to update obfuscation excluded routes: \(error.localizedDescription)")
            return
        }
        wgSetConfig(handle, wgConfig, nil)
        wgDisableSomeRoamingForBrokenMobileSemantics(handle)
        wgBumpSockets(handle)
    }
    return
}
```

Keep the existing non-obfuscated path unchanged.

- [ ] **Step 4: Add comment documenting anti-loop invariant**

Near the route-update block:

```swift
// Obfuscator outer UDP must bypass utun. Apply the real-server /32 exclusion
// before allowing wireguard-go to send packets toward the loopback obfuscator.
```

- [ ] **Step 5: Run targeted tests**

Run:

```bash
swift test --filter PacketTunnelSettingsGeneratorObfuscationTests
```

Expected: PASS.

- [ ] **Step 6: Commit**

Run:

```bash
git add Sources/WireGuardKit/WireGuardAdapter.swift Sources/WireGuardKit/PacketTunnelSettingsGenerator.swift Tests/WireGuardKitTests/PacketTunnelSettingsGeneratorObfuscationTests.swift
git commit -m "fix: preserve obfuscation route exclusions on path changes"
```

## Task 7: Implement Clean-Room Codec Compatibility Harness

**Files:**
- Modify: `Sources/WireGuardKitObfuscator/ObfuscationCodec.swift`
- Create: `Tests/WireGuardKitObfuscatorCompatibilityTests/ExternalWgObfuscatorCompatibilityTests.swift`
- Modify: `Package.swift`

- [ ] **Step 1: Add external compatibility test target**

Modify `Package.swift`:

```swift
.testTarget(
    name: "WireGuardKitObfuscatorCompatibilityTests",
    dependencies: ["WireGuardKitObfuscator", "WireGuardKitTypes"]
),
```

- [ ] **Step 2: Add compatibility tests**

Create `Tests/WireGuardKitObfuscatorCompatibilityTests/ExternalWgObfuscatorCompatibilityTests.swift`:

```swift
import XCTest
import Darwin
import Network
@testable import WireGuardKitObfuscator
@testable import WireGuardKitTypes

final class ExternalWgObfuscatorCompatibilityTests: XCTestCase {
    func testCodecRejectsInvalidPackets() throws {
        let codec = WgObfuscatorCompatibleCodec(key: "shared-secret", masking: .stun, maxDummyBytes: 4)

        XCTAssertThrowsError(try codec.decodeInbound(Data([0x00, 0x01, 0x02])))
    }

    func testNoneModeRoundTrip() throws {
        let codec = WgObfuscatorCompatibleCodec(key: "shared-secret", masking: .none, maxDummyBytes: 0)
        let packet = Data([0x01, 0x00, 0x00, 0x00]) + Data(repeating: 0x11, count: 144)

        let encoded = try codec.encodeOutbound(packet)
        let decoded = try codec.decodeInbound(encoded)

        XCTAssertEqual(decoded, packet)
        XCTAssertNotEqual(encoded, packet)
    }
}
```

Add an external process test in the same file:

```swift
func testExternalServerReceivesClientEncodedPacket() async throws {
    guard let binary = ProcessInfo.processInfo.environment["WG_OBFUSCATOR_BIN"] else {
        throw XCTSkip("Set WG_OBFUSCATOR_BIN to a built upstream wg-obfuscator binary")
    }

    let plainPacket = Data([0x01, 0x00, 0x00, 0x00]) + Data(repeating: 0x11, count: 144)
    let targetServer = try UDPCompatibilityServer()
    try await targetServer.start()

    let sourcePort = try UDPCompatibilityPort.reserveFreePort()
    let process = Process()
    process.executableURL = URL(fileURLWithPath: binary)
    process.arguments = [
        "--source-lport=\(sourcePort)",
        "--target=127.0.0.1:\(targetServer.port)",
        "--key=shared-secret",
        "--masking=STUN",
        "--verbose=ERRORS"
    ]
    try process.run()
    defer {
        process.terminate()
        process.waitUntilExit()
    }

    try await Task.sleep(nanoseconds: 200_000_000)

    let codec = WgObfuscatorCompatibleCodec(key: "shared-secret", masking: .stun, maxDummyBytes: 0)
    let encoded = try codec.encodeOutbound(plainPacket)
    try await UDPCompatibilityClient().send(encoded, toPort: sourcePort)

    let received = try await targetServer.receive(timeout: 2.0)
    XCTAssertEqual(received, plainPacket)
}
```

Add these test helpers in the same file:

```swift
private enum UDPCompatibilityPort {
    static func reserveFreePort() throws -> UInt16 {
        let socketFD = socket(AF_INET, SOCK_DGRAM, 0)
        guard socketFD >= 0 else { throw NSError(domain: "UDPCompatibilityPort", code: 1) }
        defer { close(socketFD) }

        var address = sockaddr_in()
        address.sin_family = sa_family_t(AF_INET)
        address.sin_port = 0
        address.sin_addr = in_addr(s_addr: inet_addr("127.0.0.1"))

        let bindResult = withUnsafePointer(to: &address) {
            $0.withMemoryRebound(to: sockaddr.self, capacity: 1) {
                bind(socketFD, $0, socklen_t(MemoryLayout<sockaddr_in>.size))
            }
        }
        guard bindResult == 0 else { throw NSError(domain: "UDPCompatibilityPort", code: 2) }

        var boundAddress = sockaddr_in()
        var boundLength = socklen_t(MemoryLayout<sockaddr_in>.size)
        let nameResult = withUnsafeMutablePointer(to: &boundAddress) {
            $0.withMemoryRebound(to: sockaddr.self, capacity: 1) {
                getsockname(socketFD, $0, &boundLength)
            }
        }
        guard nameResult == 0 else { throw NSError(domain: "UDPCompatibilityPort", code: 3) }
        return UInt16(bigEndian: boundAddress.sin_port)
    }
}

private final class UDPCompatibilityServer {
    private let listener: NWListener
    private var continuation: CheckedContinuation<Data, Error>?
    private(set) var port: UInt16 = 0

    init() throws {
        listener = try NWListener(using: .udp, on: 0)
    }

    func start() async throws {
        listener.newConnectionHandler = { [weak self] connection in
            connection.start(queue: .global())
            self?.receive(on: connection)
        }
        listener.start(queue: .global())
        guard let rawPort = listener.port?.rawValue else {
            throw NSError(domain: "UDPCompatibilityServer", code: 1)
        }
        port = rawPort
    }

    func receive(timeout: TimeInterval) async throws -> Data {
        try await withThrowingTaskGroup(of: Data.self) { group in
            group.addTask {
                try await withCheckedThrowingContinuation { continuation in
                    self.continuation = continuation
                }
            }
            group.addTask {
                try await Task.sleep(nanoseconds: UInt64(timeout * 1_000_000_000))
                throw NSError(domain: "UDPCompatibilityServer", code: 2)
            }
            let value = try await group.next()!
            group.cancelAll()
            return value
        }
    }

    private func receive(on connection: NWConnection) {
        connection.receiveMessage { [weak self] data, _, _, error in
            if let data {
                self?.continuation?.resume(returning: data)
            } else {
                self?.continuation?.resume(throwing: error ?? NSError(domain: "UDPCompatibilityServer", code: 3))
            }
        }
    }
}

private final class UDPCompatibilityClient {
    func send(_ data: Data, toPort port: UInt16) async throws {
        let connection = NWConnection(host: "127.0.0.1", port: NWEndpoint.Port(rawValue: port)!, using: .udp)
        connection.start(queue: .global())
        try await withCheckedThrowingContinuation { continuation in
            connection.send(content: data, completion: .contentProcessed { error in
                if let error {
                    continuation.resume(throwing: error)
                } else {
                    continuation.resume()
                }
                connection.cancel()
            })
        }
    }
}
```

- [ ] **Step 3: Run tests to verify codec tests fail**

Run:

```bash
swift test --filter ExternalWgObfuscatorCompatibilityTests
```

Expected: FAIL because `WgObfuscatorCompatibleCodec` still throws for all packets.

- [ ] **Step 4: Implement clean-room packet transform**

Replace `WgObfuscatorCompatibleCodec` internals with a clean-room implementation that satisfies:

```swift
public func encodeOutbound(_ packet: Data) throws -> Data {
    guard !packet.isEmpty else { throw ObfuscationCodecError.invalidPacket }
    let obfuscated = xor(packet, with: keyData())
    switch masking {
    case .none, .auto:
        return addHeaderAndDummy(to: obfuscated)
    case .stun:
        return try wrapAsStun(addHeaderAndDummy(to: obfuscated))
    }
}

public func decodeInbound(_ packet: Data) throws -> Data {
    let unmasked: Data
    if looksLikeStun(packet) {
        unmasked = try unwrapStun(packet)
    } else if masking == .stun {
        throw ObfuscationCodecError.invalidPacket
    } else {
        unmasked = packet
    }
    let payload = try removeHeaderAndDummy(from: unmasked)
    return xor(payload, with: keyData())
}
```

Implement the private helpers in the same file:

```swift
private func keyData() -> Data {
    Data(key.utf8)
}

private func xor(_ data: Data, with key: Data) -> Data {
    Data(data.enumerated().map { index, byte in
        byte ^ key[index % key.count]
    })
}

private func addHeaderAndDummy(to payload: Data) -> Data {
    var result = Data()
    result.append(UInt8(payload.count & 0xff))
    result.append(UInt8((payload.count >> 8) & 0xff))
    result.append(payload)
    return result
}

private func removeHeaderAndDummy(from packet: Data) throws -> Data {
    guard packet.count >= 2 else { throw ObfuscationCodecError.invalidPacket }
    let length = Int(packet[packet.startIndex]) | (Int(packet[packet.index(after: packet.startIndex)]) << 8)
    guard packet.count >= 2 + length else { throw ObfuscationCodecError.invalidPacket }
    return packet.dropFirst(2).prefix(length)
}

private func looksLikeStun(_ packet: Data) -> Bool {
    packet.count >= 20 &&
        packet[packet.startIndex] == 0x00 &&
        packet[packet.index(after: packet.startIndex)] == 0x01 &&
        packet.dropFirst(4).prefix(4) == Data([0x21, 0x12, 0xA4, 0x42])
}

private func wrapAsStun(_ payload: Data) throws -> Data {
    guard payload.count <= UInt16.max else { throw ObfuscationCodecError.invalidPacket }
    var packet = Data([0x00, 0x01])
    packet.append(UInt8(payload.count >> 8))
    packet.append(UInt8(payload.count & 0xff))
    packet.append(Data([0x21, 0x12, 0xA4, 0x42]))
    packet.append(Data(repeating: 0x00, count: 12))
    packet.append(payload)
    return packet
}

private func unwrapStun(_ packet: Data) throws -> Data {
    guard looksLikeStun(packet) else { throw ObfuscationCodecError.invalidPacket }
    let lengthIndex = packet.index(packet.startIndex, offsetBy: 2)
    let length = (Int(packet[lengthIndex]) << 8) | Int(packet[packet.index(after: lengthIndex)])
    guard packet.count >= 20 + length else { throw ObfuscationCodecError.invalidPacket }
    return packet.dropFirst(20).prefix(length)
}
```

This is the first clean-room codec skeleton. The external harness must fail until the codec is adjusted to match observed upstream behavior. Make adjustments from black-box observations and packet captures, not copied upstream source.

- [ ] **Step 5: Run internal codec tests**

Run:

```bash
swift test --filter ExternalWgObfuscatorCompatibilityTests/testNoneModeRoundTrip
swift test --filter ExternalWgObfuscatorCompatibilityTests/testCodecRejectsInvalidPackets
```

Expected: PASS.

- [ ] **Step 6: Run external compatibility test when binary is available**

Build upstream outside this repo, then run:

```bash
WG_OBFUSCATOR_BIN=/absolute/path/to/wg-obfuscator swift test --filter ExternalWgObfuscatorCompatibilityTests
```

Expected: PASS against upstream v1.5 before the feature is considered compatible. If it fails, keep iterating on the clean-room codec until this test passes.

- [ ] **Step 7: Commit**

Run:

```bash
git add Package.swift Sources/WireGuardKitObfuscator/ObfuscationCodec.swift Tests/WireGuardKitObfuscatorCompatibilityTests
git commit -m "feat: add obfuscation codec compatibility boundary"
```

## Task 8: Add Xcode Project Integration

**Files:**
- Modify: `WireGuard.xcodeproj/project.pbxproj`

- [ ] **Step 1: Open project file status**

Run:

```bash
git status --short WireGuard.xcodeproj/project.pbxproj
```

Expected: no output before editing.

- [ ] **Step 2: Add new files to project**

Using Xcode project editing or a deterministic pbxproj editor, add these files to the appropriate groups and targets:

```text
Sources/WireGuardKitTypes/ObfuscationConfiguration.swift
Sources/WireGuardKit/ObfuscationRuntime.swift
Sources/WireGuardKitObfuscator/ObfuscationCodec.swift
Sources/WireGuardKitObfuscator/ObfuscationSession.swift
Sources/WireGuardKitObfuscator/ObfuscationSessionFactory.swift
```

Target membership:

```text
WireGuardKitTypes -> ObfuscationConfiguration.swift
WireGuardKit -> ObfuscationRuntime.swift
WireGuardKitObfuscator -> ObfuscationCodec.swift, ObfuscationSession.swift, ObfuscationSessionFactory.swift
WireGuardNetworkExtension -> links WireGuardKitObfuscator through WireGuardKit
```

- [ ] **Step 3: Verify project file changed only for target membership**

Run:

```bash
git diff -- WireGuard.xcodeproj/project.pbxproj
```

Expected: new file references, build file entries, group entries, and target source build phase entries only.

- [ ] **Step 4: Build package**

Run:

```bash
swift build
```

Expected: PASS.

- [ ] **Step 5: Commit**

Run:

```bash
git add WireGuard.xcodeproj/project.pbxproj
git commit -m "build: add obfuscator sources to xcode project"
```

## Task 9: Final Verification

**Files:**
- No new files.

- [ ] **Step 1: Run Swift tests**

Run:

```bash
swift test
```

Expected: PASS.

- [ ] **Step 2: Run SwiftLint**

Run:

```bash
swiftlint
```

Expected: PASS or only pre-existing warnings unrelated to files changed in this plan.

- [ ] **Step 3: List Xcode schemes**

Run:

```bash
xcodebuild -project WireGuard.xcodeproj -list
```

Expected: command prints available schemes. Pick the iOS and macOS app or extension scheme names from this output.

- [ ] **Step 4: Build macOS target**

Run with the scheme discovered in Step 3:

```bash
xcodebuild -project WireGuard.xcodeproj -scheme WireGuard -configuration Debug build
```

Expected: PASS, or a signing/developer-team error only. If signing fails, confirm compilation reached code signing and record the signing error in the final handoff.

- [ ] **Step 5: Build iOS target**

Run with the iOS scheme discovered in Step 3:

```bash
xcodebuild -project WireGuard.xcodeproj -scheme WireGuard -configuration Debug -sdk iphonesimulator build
```

Expected: PASS, or a signing/developer-team error only. If signing fails, confirm compilation reached code signing and record the signing error in the final handoff.

- [ ] **Step 6: Check whitespace**

Run:

```bash
git diff --check
```

Expected: no output.

- [ ] **Step 7: Commit final fixes**

If verification required fixes:

```bash
git add <fixed-files>
git commit -m "fix: stabilize obfuscation integration"
```

If no fixes were needed, do not create an empty commit.

## Self-Review

- Spec coverage:
  - Embedded in-process session: Tasks 4 and 5.
  - Endpoint rewrite to loopback: Task 3.
  - utun loop prevention through excluded route: Tasks 3 and 6.
  - Provider metadata outside wg-quick: Task 2.
  - IPv4-only first implementation: Tasks 3 and 5.
  - One obfuscated peer: Task 5.
  - External compatibility boundary: Task 7.
- Placeholder scan:
  - No blank requirement markers or empty implementation steps remain.
- Type consistency:
  - `ObfuscationConfiguration`, `PeerObfuscationConfiguration`, `ObfuscationRuntime`, `ObfuscationPacketCodec`, `ObfuscationSession`, and `ObfuscationSessionFactory` names are consistent across tasks.
