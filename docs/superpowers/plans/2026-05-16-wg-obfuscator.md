# wg-obfuscator Bind Integration Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Add iOS and macOS client-side wg-obfuscator compatibility by wrapping `wireguard-go`'s UDP `conn.Bind` with an obfuscating bind.

**Architecture:** Swift persists and validates obfuscation metadata, then passes a C-compatible config to the Go bridge. The Go bridge wraps `conn.NewStdNetBind()` with `obfuscator.Bind` for single-hop and for the physical entry leg of multihop; peer endpoints stay real and are not rewritten to loopback.

**Tech Stack:** Swift 5.5, NetworkExtension, XCTest, Go 1.21, wireguard-go `conn.Bind`, CGO C bridge, Swift Package Manager, Xcode project.

---

## Design Source

Implement from `docs/superpowers/specs/2026-05-16-wg-obfuscator-design.md`.

Do not copy upstream `ClusterM/wg-obfuscator` GPL-3.0 source into this repository unless the product owner explicitly approves GPL-compatible distribution or obtains a separate license. This plan assumes clean-room codec implementation and black-box compatibility tests against an externally built upstream binary.

## Scope

This plan implements:

- One physical obfuscated transport per tunnel.
- Single-hop obfuscation by wrapping the device's `conn.NewStdNetBind()`.
- Multihop physical entry-leg obfuscation by wrapping the entry device's `conn.NewStdNetBind()`.
- No Swift UDP forwarding session.
- No endpoint rewrite to `127.0.0.1`.
- Optional `/32` excluded route hardening for the real obfuscator server IPv4.

This plan does not implement UI controls or custom wg-quick import/export keys.

## File Structure

Create:

- `Sources/WireGuardKitTypes/ObfuscationConfiguration.swift`
  - Public Swift value types for persisted obfuscation metadata.
- `Sources/WireGuardKit/ObfuscationRouteExclusion.swift`
  - Internal Swift helper that validates the physical obfuscator endpoint and creates excluded routes.
- `Sources/WireGuardKitGo/obfuscator/config.go`
  - Go config types and validation.
- `Sources/WireGuardKitGo/obfuscator/codec.go`
  - Clean-room codec interface and initial implementation boundary.
- `Sources/WireGuardKitGo/obfuscator/bind.go`
  - `conn.Bind` wrapper.
- `Sources/WireGuardKitGo/obfuscator/bind_test.go`
  - Bind behavior tests with a fake base bind and fake codec.
- `Sources/WireGuardKitGo/obfuscator/config_test.go`
  - Config validation tests.
- `Tests/WireGuardKitTypesTests/ObfuscationConfigurationTests.swift`
  - Swift model validation tests.
- `Tests/WireGuardKitTests/ObfuscationRouteExclusionTests.swift`
  - Route hardening and no-endpoint-rewrite tests.

Modify:

- `Package.swift`
  - Add `WireGuardKitTypesTests` and `WireGuardKitTests` test targets.
- `Sources/WireGuardKitTypes/TunnelConfiguration.swift`
  - Add optional `obfuscation` property.
- `Sources/Shared/Model/NETunnelProviderProtocol+Extension.swift`
  - Persist and restore obfuscation metadata in `providerConfiguration`.
- `Sources/WireGuardKit/PacketTunnelSettingsGenerator.swift`
  - Accept optional obfuscation excluded IPv4 routes. Do not rewrite endpoints.
- `Sources/WireGuardKit/WireGuardAdapter.swift`
  - Validate obfuscation, pass C bridge config, and add route hardening before backend start.
- `Sources/WireGuardNetworkExtension/PacketTunnelProvider.swift`
  - Surface new adapter errors.
- `Sources/WireGuardKitGo/wireguard.h`
  - Add C bridge structs and updated function signatures.
- `Sources/WireGuardKitGo/api-apple.go`
  - Convert C bridge config and wrap binds.
- `WireGuard.xcodeproj/project.pbxproj`
  - Add new Swift files to existing targets.

## Task 1: Add Swift Obfuscation Configuration Types

**Files:**
- Modify: `Package.swift`
- Modify: `Sources/WireGuardKitTypes/TunnelConfiguration.swift`
- Create: `Sources/WireGuardKitTypes/ObfuscationConfiguration.swift`
- Create: `Tests/WireGuardKitTypesTests/ObfuscationConfigurationTests.swift`

- [ ] **Step 1: Write failing Swift model tests**

Create `Tests/WireGuardKitTypesTests/ObfuscationConfigurationTests.swift`:

```swift
import XCTest
@testable import WireGuardKitTypes

final class ObfuscationConfigurationTests: XCTestCase {
    func testValidPeerConfigurationAcceptsSupportedModes() throws {
        let publicKey = PublicKey(rawValue: Data(repeating: 1, count: 32))!

        let stun = try PeerObfuscationConfiguration(peerPublicKey: publicKey, key: "shared-secret", masking: .stun)
        let auto = try PeerObfuscationConfiguration(peerPublicKey: publicKey, key: "shared-secret", masking: .auto)
        let none = try PeerObfuscationConfiguration(peerPublicKey: publicKey, key: "shared-secret", masking: .none)

        XCTAssertEqual(stun.masking, .stun)
        XCTAssertEqual(auto.masking, .auto)
        XCTAssertEqual(none.masking, .none)
        XCTAssertEqual(stun.transportLeg, .physical)
    }

    func testRejectsEmptyKey() throws {
        let publicKey = PublicKey(rawValue: Data(repeating: 1, count: 32))!

        XCTAssertThrowsError(try PeerObfuscationConfiguration(peerPublicKey: publicKey, key: "", masking: .auto)) { error in
            XCTAssertEqual(error as? ObfuscationConfigurationError, .invalidKeyLength)
        }
    }

    func testRejectsKeyLongerThan255Utf8Bytes() throws {
        let publicKey = PublicKey(rawValue: Data(repeating: 1, count: 32))!
        let longKey = String(repeating: "a", count: 256)

        XCTAssertThrowsError(try PeerObfuscationConfiguration(peerPublicKey: publicKey, key: longKey, masking: .auto)) { error in
            XCTAssertEqual(error as? ObfuscationConfigurationError, .invalidKeyLength)
        }
    }

    func testValidatedForPhysicalTransportRejectsMultiplePeers() throws {
        let publicKeyA = PublicKey(rawValue: Data(repeating: 1, count: 32))!
        let publicKeyB = PublicKey(rawValue: Data(repeating: 2, count: 32))!
        let peerA = try PeerObfuscationConfiguration(peerPublicKey: publicKeyA, key: "shared-secret", masking: .stun)
        let peerB = try PeerObfuscationConfiguration(peerPublicKey: publicKeyB, key: "shared-secret", masking: .stun)
        let configuration = ObfuscationConfiguration(peers: [peerA, peerB])

        XCTAssertThrowsError(try configuration.validatedForSinglePhysicalTransport()) { error in
            XCTAssertEqual(error as? ObfuscationConfigurationError, .multiplePhysicalTransports)
        }
    }
}
```

- [ ] **Step 2: Add Swift test target**

Modify `Package.swift` by adding:

```swift
.testTarget(
    name: "WireGuardKitTypesTests",
    dependencies: ["WireGuardKitTypes"]
),
```

- [ ] **Step 3: Run the tests to confirm failure**

Run:

```bash
swift test --filter ObfuscationConfigurationTests
```

Expected: FAIL because the obfuscation Swift types do not exist.

- [ ] **Step 4: Implement Swift model types**

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

public enum ObfuscationTransportLeg: String, Codable, Equatable {
    case physical = "physical"
}

public enum ObfuscationConfigurationError: Error, Equatable {
    case invalidKeyLength
    case invalidMaxDummyBytes
    case duplicatePeer(PublicKey)
    case multiplePhysicalTransports
}

public struct PeerObfuscationConfiguration: Codable, Equatable, Hashable {
    public let peerPublicKey: PublicKey
    public let key: String
    public let masking: ObfuscationMasking
    public let maxDummyBytes: UInt16
    public let transportLeg: ObfuscationTransportLeg

    public init(peerPublicKey: PublicKey, key: String, masking: ObfuscationMasking, maxDummyBytes: UInt16 = 4, transportLeg: ObfuscationTransportLeg = .physical) throws {
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
        self.transportLeg = transportLeg
    }
}

public struct ObfuscationConfiguration: Codable, Equatable, Hashable {
    public let peers: [PeerObfuscationConfiguration]

    public init(peers: [PeerObfuscationConfiguration]) {
        self.peers = peers
    }

    public func configuration(for publicKey: PublicKey) -> PeerObfuscationConfiguration? {
        peers.first { $0.peerPublicKey == publicKey }
    }

    public func validatedForSinglePhysicalTransport() throws -> ObfuscationConfiguration {
        var seen = Set<PublicKey>()
        let physicalPeers = peers.filter { $0.transportLeg == .physical }
        guard physicalPeers.count <= 1 else {
            throw ObfuscationConfigurationError.multiplePhysicalTransports
        }
        for peer in peers {
            guard seen.insert(peer.peerPublicKey).inserted else {
                throw ObfuscationConfigurationError.duplicatePeer(peer.peerPublicKey)
            }
        }
        return self
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

Update equality:

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

## Task 2: Persist Obfuscation Metadata Outside wg-quick

**Files:**
- Modify: `Sources/WireGuardKitTypes/ObfuscationConfiguration.swift`
- Modify: `Sources/Shared/Model/NETunnelProviderProtocol+Extension.swift`
- Create: `Tests/WireGuardKitTypesTests/ObfuscationProviderCodingTests.swift`

- [ ] **Step 1: Write failing provider coding tests**

Create `Tests/WireGuardKitTypesTests/ObfuscationProviderCodingTests.swift`:

```swift
import XCTest
@testable import WireGuardKitTypes

final class ObfuscationProviderCodingTests: XCTestCase {
    func testProviderDictionaryRoundTrip() throws {
        let publicKey = PublicKey(rawValue: Data(repeating: 1, count: 32))!
        let peer = try PeerObfuscationConfiguration(peerPublicKey: publicKey, key: "shared-secret", masking: .stun, maxDummyBytes: 8)
        let configuration = ObfuscationConfiguration(peers: [peer])

        let dictionary = try configuration.asProviderConfigurationDictionary()
        let decoded = try ObfuscationConfiguration(providerConfigurationDictionary: dictionary)

        XCTAssertEqual(decoded, configuration)
    }

    func testRejectsMalformedDictionary() throws {
        XCTAssertThrowsError(try ObfuscationConfiguration(providerConfigurationDictionary: ["peers": "wrong"]))
    }
}
```

- [ ] **Step 2: Run test to confirm failure**

Run:

```bash
swift test --filter ObfuscationProviderCodingTests
```

Expected: FAIL because provider dictionary helpers do not exist.

- [ ] **Step 3: Implement provider dictionary helpers**

Append to `Sources/WireGuardKitTypes/ObfuscationConfiguration.swift`:

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

- [ ] **Step 4: Persist metadata in provider configuration**

Modify `Sources/Shared/Model/NETunnelProviderProtocol+Extension.swift` by adding:

```swift
private enum ProviderConfigurationKey {
    static let uid = "UID"
    static let obfuscation = "Obfuscation"
    static let wgQuickConfig = "WgQuickConfig"
}
```

In `init?(tunnelConfiguration:previouslyFrom:)`, replace direct provider configuration assignment with:

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

In `asTunnelConfiguration(called:)`, restore obfuscation after parsing the wg-quick text:

```swift
private func applyObfuscationProviderConfiguration(to tunnelConfiguration: TunnelConfiguration?) -> TunnelConfiguration? {
    guard let tunnelConfiguration else { return nil }
    if let dictionary = providerConfiguration?[ProviderConfigurationKey.obfuscation] as? [String: Any],
       let obfuscation = try? ObfuscationConfiguration(providerConfigurationDictionary: dictionary) {
        tunnelConfiguration.obfuscation = obfuscation
    }
    return tunnelConfiguration
}
```

Use it in both branches:

```swift
let tunnelConfiguration = try? TunnelConfiguration(fromWgQuickConfig: config, called: name)
return applyObfuscationProviderConfiguration(to: tunnelConfiguration)
```

and:

```swift
if let oldConfig = providerConfiguration?[ProviderConfigurationKey.wgQuickConfig] as? String {
    let tunnelConfiguration = try? TunnelConfiguration(fromWgQuickConfig: oldConfig, called: name)
    return applyObfuscationProviderConfiguration(to: tunnelConfiguration)
}
```

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

## Task 3: Add Route Hardening Without Endpoint Rewrite

**Files:**
- Create: `Sources/WireGuardKit/ObfuscationRouteExclusion.swift`
- Modify: `Sources/WireGuardKit/PacketTunnelSettingsGenerator.swift`
- Create: `Tests/WireGuardKitTests/ObfuscationRouteExclusionTests.swift`

- [ ] **Step 1: Write failing route and UAPI tests**

Create `Tests/WireGuardKitTests/ObfuscationRouteExclusionTests.swift`:

```swift
import XCTest
import NetworkExtension
@testable import WireGuardKit
@testable import WireGuardKitTypes

final class ObfuscationRouteExclusionTests: XCTestCase {
    func testExcludedRouteUsesRealEndpointIPv4() throws {
        let endpoint = Endpoint(from: "198.51.100.10:19999")!
        let route = try ObfuscationRouteExclusion.excludedIPv4Route(for: endpoint)

        XCTAssertEqual(route.destinationAddress, "198.51.100.10")
        XCTAssertEqual(route.destinationSubnetMask, "255.255.255.255")
    }

    func testUapiKeepsRealEndpointWhenObfuscationRouteExists() throws {
        let publicKey = PublicKey(rawValue: Data(repeating: 1, count: 32))!
        let privateKey = PrivateKey(rawValue: Data(repeating: 3, count: 32))!
        var interface = InterfaceConfiguration(privateKey: privateKey)
        interface.addresses = [IPAddressRange(from: "10.0.0.2/32")!]

        var peer = PeerConfiguration(publicKey: publicKey)
        peer.endpoint = Endpoint(from: "198.51.100.10:19999")
        peer.allowedIPs = [IPAddressRange(from: "0.0.0.0/0")!]

        let tunnel = TunnelConfiguration(name: "obfs", interface: interface, peers: [peer])
        let generator = PacketTunnelSettingsGenerator(
            exit: DeviceConfiguration(
                configuration: tunnel,
                resolvedEndpoints: [peer.endpoint],
                reResolveEndpoint: false,
                obfuscationExcludedRoutes: [try ObfuscationRouteExclusion.excludedIPv4Route(for: peer.endpoint!)]
            )
        )

        let (uapi, _) = generator.uapiConfiguration()

        XCTAssertTrue(uapi.contains("endpoint=198.51.100.10:19999"))
        XCTAssertFalse(uapi.contains("127.0.0.1"))
    }
}
```

- [ ] **Step 2: Add Swift test target**

Modify `Package.swift` by adding:

```swift
.testTarget(
    name: "WireGuardKitTests",
    dependencies: ["WireGuardKit", "WireGuardKitTypes"]
),
```

- [ ] **Step 3: Run tests to confirm failure**

Run:

```bash
swift test --filter ObfuscationRouteExclusionTests
```

Expected: FAIL because `ObfuscationRouteExclusion` and `obfuscationExcludedRoutes` do not exist.

- [ ] **Step 4: Implement route helper**

Create `Sources/WireGuardKit/ObfuscationRouteExclusion.swift`:

```swift
// SPDX-License-Identifier: MIT
// Copyright © 2026 WireGuard LLC. All Rights Reserved.

import NetworkExtension

#if SWIFT_PACKAGE
import WireGuardKitTypes
#endif

enum ObfuscationRouteExclusionError: Error, Equatable {
    case endpointIsNotIPv4
}

enum ObfuscationRouteExclusion {
    static func excludedIPv4Route(for endpoint: Endpoint) throws -> NEIPv4Route {
        guard case .ipv4(let address) = endpoint.host else {
            throw ObfuscationRouteExclusionError.endpointIsNotIPv4
        }
        return NEIPv4Route(destinationAddress: "\(address)", subnetMask: "255.255.255.255")
    }
}
```

- [ ] **Step 5: Add excluded routes to settings generator**

Modify `Sources/WireGuardKit/PacketTunnelSettingsGenerator.swift`:

```swift
struct DeviceConfiguration {
    let configuration: TunnelConfiguration
    let resolvedEndpoints: [Endpoint?]
    let reResolveEndpoint: Bool
    let obfuscationExcludedRoutes: [NEIPv4Route]

    init(configuration: TunnelConfiguration, resolvedEndpoints: [Endpoint?], reResolveEndpoint: Bool, obfuscationExcludedRoutes: [NEIPv4Route] = []) {
        self.configuration = configuration
        self.resolvedEndpoints = resolvedEndpoints
        self.reResolveEndpoint = reResolveEndpoint
        self.obfuscationExcludedRoutes = obfuscationExcludedRoutes
    }
}
```

After `ipv4Settings.includedRoutes = ipv4IncludedRoutes`, add:

```swift
if !obfuscationExcludedRoutes.isEmpty {
    ipv4Settings.excludedRoutes = obfuscationExcludedRoutes
}
```

Do not change the endpoint-writing logic in `uapiConfiguration(for:)` or `endpointUapiConfiguration()`.

- [ ] **Step 6: Run tests**

Run:

```bash
swift test --filter ObfuscationRouteExclusionTests
```

Expected: PASS.

- [ ] **Step 7: Commit**

Run:

```bash
git add Package.swift Sources/WireGuardKit/ObfuscationRouteExclusion.swift Sources/WireGuardKit/PacketTunnelSettingsGenerator.swift Tests/WireGuardKitTests/ObfuscationRouteExclusionTests.swift
git commit -m "feat: add obfuscation route hardening"
```

## Task 4: Add Go Obfuscator Config and Bind Tests

**Files:**
- Create: `Sources/WireGuardKitGo/obfuscator/config.go`
- Create: `Sources/WireGuardKitGo/obfuscator/codec.go`
- Create: `Sources/WireGuardKitGo/obfuscator/bind.go`
- Create: `Sources/WireGuardKitGo/obfuscator/config_test.go`
- Create: `Sources/WireGuardKitGo/obfuscator/bind_test.go`

- [ ] **Step 1: Write failing Go config tests**

Create `Sources/WireGuardKitGo/obfuscator/config_test.go`:

```go
package obfuscator

import "testing"

func TestConfigValidateAcceptsSupportedModes(t *testing.T) {
    for _, mode := range []MaskingMode{MaskingSTUN, MaskingAUTO, MaskingNONE} {
        cfg := Config{Key: "shared-secret", Masking: mode, MaxDummyBytes: 4, Enabled: true}
        if err := cfg.Validate(); err != nil {
            t.Fatalf("Validate() failed for %s: %v", mode, err)
        }
    }
}

func TestConfigValidateRejectsEmptyKey(t *testing.T) {
    cfg := Config{Key: "", Masking: MaskingAUTO, MaxDummyBytes: 4, Enabled: true}
    if err := cfg.Validate(); err != ErrInvalidKeyLength {
        t.Fatalf("expected ErrInvalidKeyLength, got %v", err)
    }
}

func TestConfigValidateRejectsUnsupportedMode(t *testing.T) {
    cfg := Config{Key: "shared-secret", Masking: MaskingMode("BAD"), MaxDummyBytes: 4, Enabled: true}
    if err := cfg.Validate(); err != ErrUnsupportedMasking {
        t.Fatalf("expected ErrUnsupportedMasking, got %v", err)
    }
}
```

- [ ] **Step 2: Write failing bind tests**

Create `Sources/WireGuardKitGo/obfuscator/bind_test.go`:

```go
package obfuscator

import (
    "errors"
    "net/netip"
    "testing"

    "golang.zx2c4.com/wireguard/conn"
)

func TestBindSendEncodesBeforeDelegating(t *testing.T) {
    base := newFakeBind([]fakeReceive{})
    codec := fakeCodec{encoded: []byte{9, 8, 7}}
    bind := NewBind(base, Config{Enabled: true, Key: "shared-secret", Masking: MaskingNONE}, codec)
    endpoint, _ := base.ParseEndpoint("198.51.100.10:19999")

    if err := bind.Send([]byte{1, 2, 3}, endpoint); err != nil {
        t.Fatalf("Send() failed: %v", err)
    }

    if got := string(base.sent); got != string([]byte{9, 8, 7}) {
        t.Fatalf("sent bytes = %v", base.sent)
    }
}

func TestBindReceiveDecodesBeforeReturning(t *testing.T) {
    endpoint := conn.StdNetEndpoint(netip.MustParseAddrPort("198.51.100.10:19999"))
    base := newFakeBind([]fakeReceive{{packet: []byte{9, 8, 7}, endpoint: endpoint}})
    codec := fakeCodec{decoded: []byte{1, 2, 3}}
    bind := NewBind(base, Config{Enabled: true, Key: "shared-secret", Masking: MaskingNONE}, codec)

    fns, _, err := bind.Open(0)
    if err != nil {
        t.Fatalf("Open() failed: %v", err)
    }

    buf := make([]byte, 16)
    n, gotEndpoint, err := fns[0](buf)
    if err != nil {
        t.Fatalf("receive failed: %v", err)
    }
    if n != 3 || string(buf[:n]) != string([]byte{1, 2, 3}) {
        t.Fatalf("decoded packet = %v", buf[:n])
    }
    if gotEndpoint.DstToString() != endpoint.DstToString() {
        t.Fatalf("endpoint = %s", gotEndpoint.DstToString())
    }
}

func TestBindReceiveDropsInvalidPacketsUntilValid(t *testing.T) {
    endpoint := conn.StdNetEndpoint(netip.MustParseAddrPort("198.51.100.10:19999"))
    base := newFakeBind([]fakeReceive{
        {packet: []byte{0}, endpoint: endpoint},
        {packet: []byte{9, 8, 7}, endpoint: endpoint},
    })
    codec := fakeCodec{decoded: []byte{1, 2, 3}, failFirstDecode: true}
    bind := NewBind(base, Config{Enabled: true, Key: "shared-secret", Masking: MaskingNONE}, codec)

    fns, _, err := bind.Open(0)
    if err != nil {
        t.Fatalf("Open() failed: %v", err)
    }

    buf := make([]byte, 16)
    n, _, err := fns[0](buf)
    if err != nil {
        t.Fatalf("receive failed: %v", err)
    }
    if n != 3 {
        t.Fatalf("n = %d", n)
    }
}

type fakeCodec struct {
    encoded []byte
    decoded []byte
    failFirstDecode bool
    decodeCalls int
}

func (f *fakeCodec) Encode(packet []byte) ([]byte, error) {
    if f.encoded != nil {
        return f.encoded, nil
    }
    return append([]byte{}, packet...), nil
}

func (f *fakeCodec) Decode(packet []byte) ([]byte, error) {
    f.decodeCalls++
    if f.failFirstDecode && f.decodeCalls == 1 {
        return nil, ErrInvalidPacket
    }
    if f.decoded != nil {
        return f.decoded, nil
    }
    return append([]byte{}, packet...), nil
}

type fakeReceive struct {
    packet []byte
    endpoint conn.Endpoint
    err error
}

type fakeBind struct {
    receives []fakeReceive
    sent []byte
}

func newFakeBind(receives []fakeReceive) *fakeBind {
    return &fakeBind{receives: receives}
}

func (f *fakeBind) Open(port uint16) ([]conn.ReceiveFunc, uint16, error) {
    return []conn.ReceiveFunc{func(buf []byte) (int, conn.Endpoint, error) {
        if len(f.receives) == 0 {
            return 0, nil, errors.New("empty receive queue")
        }
        next := f.receives[0]
        f.receives = f.receives[1:]
        copy(buf, next.packet)
        return len(next.packet), next.endpoint, next.err
    }}, port, nil
}

func (f *fakeBind) Close() error { return nil }
func (f *fakeBind) SetMark(mark uint32) error { return nil }
func (f *fakeBind) Send(buf []byte, ep conn.Endpoint) error {
    f.sent = append([]byte{}, buf...)
    return nil
}
func (f *fakeBind) ParseEndpoint(s string) (conn.Endpoint, error) {
    endpoint, err := netip.ParseAddrPort(s)
    if err != nil {
        return nil, err
    }
    return conn.StdNetEndpoint(endpoint), nil
}
```

- [ ] **Step 3: Run Go tests to confirm failure**

Run:

```bash
cd Sources/WireGuardKitGo
go test ./obfuscator
```

Expected: FAIL because the obfuscator package implementation does not exist.

- [ ] **Step 4: Implement Go config**

Create `Sources/WireGuardKitGo/obfuscator/config.go`:

```go
package obfuscator

import "errors"

type MaskingMode string

const (
    MaskingSTUN MaskingMode = "STUN"
    MaskingAUTO MaskingMode = "AUTO"
    MaskingNONE MaskingMode = "NONE"
)

var (
    ErrInvalidKeyLength = errors.New("invalid obfuscation key length")
    ErrUnsupportedMasking = errors.New("unsupported obfuscation masking mode")
    ErrInvalidPacket = errors.New("invalid obfuscated packet")
)

type Config struct {
    Enabled bool
    Key string
    Masking MaskingMode
    MaxDummyBytes uint16
}

func (c Config) Validate() error {
    if !c.Enabled {
        return nil
    }
    if len([]byte(c.Key)) < 1 || len([]byte(c.Key)) > 255 {
        return ErrInvalidKeyLength
    }
    switch c.Masking {
    case MaskingSTUN, MaskingAUTO, MaskingNONE:
        return nil
    default:
        return ErrUnsupportedMasking
    }
}
```

- [ ] **Step 5: Implement codec boundary**

Create `Sources/WireGuardKitGo/obfuscator/codec.go`:

```go
package obfuscator

type Codec interface {
    Encode(packet []byte) ([]byte, error)
    Decode(packet []byte) ([]byte, error)
}

type CleanRoomCodec struct {
    config Config
}

func NewCleanRoomCodec(config Config) *CleanRoomCodec {
    return &CleanRoomCodec{config: config}
}

func (c *CleanRoomCodec) Encode(packet []byte) ([]byte, error) {
    if len(packet) == 0 {
        return nil, ErrInvalidPacket
    }
    encoded := make([]byte, len(packet))
    key := []byte(c.config.Key)
    for i, b := range packet {
        encoded[i] = b ^ key[i%len(key)]
    }
    return encoded, nil
}

func (c *CleanRoomCodec) Decode(packet []byte) ([]byte, error) {
    if len(packet) == 0 {
        return nil, ErrInvalidPacket
    }
    decoded := make([]byte, len(packet))
    key := []byte(c.config.Key)
    for i, b := range packet {
        decoded[i] = b ^ key[i%len(key)]
    }
    return decoded, nil
}
```

This codec is a testable boundary. Task 8 replaces its internals based on black-box upstream behavior.

- [ ] **Step 6: Implement bind wrapper**

Create `Sources/WireGuardKitGo/obfuscator/bind.go`:

```go
package obfuscator

import "golang.zx2c4.com/wireguard/conn"

type Bind struct {
    base conn.Bind
    config Config
    codec Codec
}

func NewBind(base conn.Bind, config Config, codec Codec) *Bind {
    if codec == nil {
        codec = NewCleanRoomCodec(config)
    }
    return &Bind{base: base, config: config, codec: codec}
}

func (b *Bind) Open(port uint16) ([]conn.ReceiveFunc, uint16, error) {
    fns, actualPort, err := b.base.Open(port)
    if err != nil {
        return nil, 0, err
    }

    wrapped := make([]conn.ReceiveFunc, 0, len(fns))
    for _, receive := range fns {
        receive := receive
        wrapped = append(wrapped, func(buf []byte) (int, conn.Endpoint, error) {
            for {
                n, endpoint, err := receive(buf)
                if err != nil {
                    return 0, endpoint, err
                }
                decoded, err := b.codec.Decode(buf[:n])
                if err != nil {
                    continue
                }
                copy(buf, decoded)
                return len(decoded), endpoint, nil
            }
        })
    }

    return wrapped, actualPort, nil
}

func (b *Bind) Close() error {
    return b.base.Close()
}

func (b *Bind) SetMark(mark uint32) error {
    return b.base.SetMark(mark)
}

func (b *Bind) Send(buf []byte, endpoint conn.Endpoint) error {
    encoded, err := b.codec.Encode(buf)
    if err != nil {
        return err
    }
    return b.base.Send(encoded, endpoint)
}

func (b *Bind) ParseEndpoint(s string) (conn.Endpoint, error) {
    return b.base.ParseEndpoint(s)
}
```

- [ ] **Step 7: Run Go tests**

Run:

```bash
cd Sources/WireGuardKitGo
go test ./obfuscator
```

Expected: PASS.

- [ ] **Step 8: Commit**

Run:

```bash
git add Sources/WireGuardKitGo/obfuscator
git commit -m "feat: add obfuscating bind wrapper"
```

## Task 5: Add C Bridge Configuration

**Files:**
- Modify: `Sources/WireGuardKitGo/wireguard.h`
- Modify: `Sources/WireGuardKitGo/api-apple.go`
- Create: `Sources/WireGuardKitGo/obfuscation_config_test.go`

- [ ] **Step 1: Add failing Go bridge config tests**

Create `Sources/WireGuardKitGo/obfuscation_config_test.go`:

```go
package main

import (
    "testing"

    "golang.zx2c4.com/wireguard/apple/obfuscator"
    "golang.zx2c4.com/wireguard/conn"
)

func TestMaybeObfuscatingBindReturnsBaseWhenDisabled(t *testing.T) {
    base := &bridgeFakeBind{}
    bind := maybeWrapObfuscationBind(base, obfuscator.Config{})
    if bind != base {
        t.Fatalf("disabled config should return base bind")
    }
}

func TestMaybeObfuscatingBindWrapsWhenEnabled(t *testing.T) {
    base := &bridgeFakeBind{}
    bind := maybeWrapObfuscationBind(base, obfuscator.Config{
        Enabled: true,
        Key: "shared-secret",
        Masking: obfuscator.MaskingSTUN,
        MaxDummyBytes: 4,
    })
    if _, ok := bind.(*obfuscator.Bind); !ok {
        t.Fatalf("enabled config should return *obfuscator.Bind, got %T", bind)
    }
}
```

Add minimal fake bind in the same file:

```go
type bridgeFakeBind struct{}

func (*bridgeFakeBind) Open(port uint16) ([]conn.ReceiveFunc, uint16, error) { return nil, port, nil }
func (*bridgeFakeBind) Close() error { return nil }
func (*bridgeFakeBind) SetMark(mark uint32) error { return nil }
func (*bridgeFakeBind) Send(buf []byte, ep conn.Endpoint) error { return nil }
func (*bridgeFakeBind) ParseEndpoint(s string) (conn.Endpoint, error) { return nil, nil }
```

- [ ] **Step 2: Run bridge tests to confirm failure**

Run:

```bash
cd Sources/WireGuardKitGo
go test ./... -run 'TestMaybeObfuscatingBind'
```

Expected: FAIL because `maybeWrapObfuscationBind` does not exist.

- [ ] **Step 3: Add C bridge structs**

Modify `Sources/WireGuardKitGo/wireguard.h`:

```c
typedef struct WgObfuscationConfig {
    bool enabled;
    const char *key;
    const char *masking;
    uint16_t max_dummy_bytes;
} WgObfuscationConfig;
```

Update function declarations:

```c
extern int wgTurnOnIAN(const char *settings, int32_t tun_fd, const char *private_ip, const char *maybeNotMachines, DaitaGoParameters *daitaParameters, WgObfuscationConfig *obfuscationConfig);
extern int wgTurnOn(const char *settings, int32_t tun_fd, const char *maybeNotMachines, DaitaGoParameters *daitaParameters, WgObfuscationConfig *obfuscationConfig);
extern int wgTurnOnMultihop(const char *exitSettings, const char *entrySettings, const char *privateIp, int32_t tun_fd, const char *maybenotMachines, DaitaGoParameters *daitaParameters, WgObfuscationConfig *entryObfuscationConfig);
```

- [ ] **Step 4: Add Go config conversion and wrapper helper**

Modify `Sources/WireGuardKitGo/api-apple.go` imports:

```go
"golang.zx2c4.com/wireguard/apple/obfuscator"
```

Add helper functions:

```go
func obfuscationConfigFromRaw(raw *C.WgObfuscationConfig) obfuscator.Config {
    if raw == nil || !bool(raw.enabled) {
        return obfuscator.Config{}
    }
    return obfuscator.Config{
        Enabled: true,
        Key: C.GoString(raw.key),
        Masking: obfuscator.MaskingMode(C.GoString(raw.masking)),
        MaxDummyBytes: uint16(raw.max_dummy_bytes),
    }
}

func maybeWrapObfuscationBind(base conn.Bind, config obfuscator.Config) conn.Bind {
    if !config.Enabled {
        return base
    }
    if err := config.Validate(); err != nil {
        return base
    }
    return obfuscator.NewBind(base, config, nil)
}
```

- [ ] **Step 5: Run bridge tests**

Run:

```bash
cd Sources/WireGuardKitGo
go test ./... -run 'TestMaybeObfuscatingBind'
```

Expected: PASS.

- [ ] **Step 6: Commit**

Run:

```bash
git add Sources/WireGuardKitGo/wireguard.h Sources/WireGuardKitGo/api-apple.go Sources/WireGuardKitGo/obfuscation_config_test.go
git commit -m "feat: add obfuscation bridge config"
```

## Task 6: Wrap Single-Hop and Multihop Entry Binds

**Files:**
- Modify: `Sources/WireGuardKitGo/api-apple.go`
- Modify: `Sources/WireGuardKit/WireGuardAdapter.swift`
- Modify: `Sources/WireGuardNetworkExtension/PacketTunnelProvider.swift`

- [ ] **Step 1: Add adapter error cases**

Modify `WireGuardAdapterError`:

```swift
case obfuscationConfiguration(String)
case obfuscationRouteUpdate(String)
```

Update `PacketTunnelProvider.startTunnel`:

```swift
case .obfuscationConfiguration(let message):
    wg_log(.error, message: "Starting tunnel failed with invalid obfuscation configuration: \(message)")
    errorNotifier.notify(PacketTunnelProviderError.couldNotStartBackend)
    completionHandler(PacketTunnelProviderError.couldNotStartBackend)

case .obfuscationRouteUpdate(let message):
    wg_log(.error, message: "Starting tunnel failed while applying obfuscation routes: \(message)")
    errorNotifier.notify(PacketTunnelProviderError.couldNotSetNetworkSettings)
    completionHandler(PacketTunnelProviderError.couldNotSetNetworkSettings)
```

- [ ] **Step 2: Update Go function signatures and bind construction**

Modify `wgTurnOnIANFromExistingTunnel` to accept `obfuscationConfig obfuscator.Config` and construct:

```go
baseBind := conn.NewStdNetBind()
bind := maybeWrapObfuscationBind(baseBind, obfuscationConfig)
dev := device.NewDevice(&wrapper, bind, logger)
```

Modify exported `wgTurnOnIAN`:

```go
func wgTurnOnIAN(settings *C.char, tunFd int32, privateIP *C.char, maybeNotMachines *C.char, daitaParameters *C.DaitaGoParameters, rawObfuscationConfig *C.WgObfuscationConfig) int32 {
    ...
    obfuscationConfig := obfuscationConfigFromRaw(rawObfuscationConfig)
    return wgTurnOnIANFromExistingTunnel(tun, C.GoString(settings), privateAddr, daitaParams, obfuscationConfig)
}
```

Modify multihop entry device construction:

```go
entryBaseBind := conn.NewStdNetBind()
entryBind := maybeWrapObfuscationBind(entryBaseBind, obfuscationConfigFromRaw(rawEntryObfuscationConfig))
entryDev := device.NewDevice(&singletun, entryBind, logger)
```

Keep exit device bind unchanged:

```go
exitDev := device.NewDevice(&wrapper, singletun.Binder(), logger)
```

- [ ] **Step 3: Build Swift C config helper**

Add to `WireGuardAdapter.swift`:

```swift
private func makeGoObfuscationConfig(for tunnelConfiguration: TunnelConfiguration) throws -> WgObfuscationConfig {
    guard let obfuscation = tunnelConfiguration.obfuscation else {
        return WgObfuscationConfig(enabled: false, key: nil, masking: nil, max_dummy_bytes: 0)
    }
    let validated = try obfuscation.validatedForSinglePhysicalTransport()
    guard let peer = validated.peers.first(where: { $0.transportLeg == .physical }) else {
        return WgObfuscationConfig(enabled: false, key: nil, masking: nil, max_dummy_bytes: 0)
    }
    guard tunnelConfiguration.peers.contains(where: { $0.publicKey == peer.peerPublicKey }) else {
        throw WireGuardAdapterError.obfuscationConfiguration("Obfuscated peer public key is not present in tunnel configuration")
    }

    return WgObfuscationConfig(
        enabled: true,
        key: strdup(peer.key),
        masking: strdup(peer.masking.rawValue),
        max_dummy_bytes: peer.maxDummyBytes
    )
}

private func freeGoObfuscationConfig(_ config: inout WgObfuscationConfig) {
    if let key = config.key {
        free(UnsafeMutableRawPointer(mutating: key))
        config.key = nil
    }
    if let masking = config.masking {
        free(UnsafeMutableRawPointer(mutating: masking))
        config.masking = nil
    }
}
```

- [ ] **Step 4: Pass config to Go start functions**

In `startWireGuardBackend(...)`, add parameter:

```swift
obfuscationConfiguration: ObfuscationConfiguration?
```

Before calling Go:

```swift
var obfsConfig = try makeGoObfuscationConfig(for: settingsGenerator.exit.configuration)
defer { freeGoObfuscationConfig(&obfsConfig) }
```

Call:

```swift
wgTurnOnIAN(exitWgConfig, tunnelFileDescriptor, privateAddr, daita?.machines ?? nil, &params, &obfsConfig)
```

For multihop:

```swift
wgTurnOnMultihop(exitWgConfig, entryWgConfig, privateAddr, tunnelFileDescriptor, daita?.machines ?? nil, &params, &obfsConfig)
```

This first slice uses the same physical obfuscation config for single-hop and multihop entry leg.

- [ ] **Step 5: Run Go and Swift focused tests**

Run:

```bash
cd Sources/WireGuardKitGo
go test ./... -run 'TestMaybeObfuscatingBind|TestConfigValidate|TestBind'
cd ../..
swift test --filter ObfuscationConfigurationTests
```

Expected: PASS.

- [ ] **Step 6: Commit**

Run:

```bash
git add Sources/WireGuardKitGo/api-apple.go Sources/WireGuardKit/WireGuardAdapter.swift Sources/WireGuardNetworkExtension/PacketTunnelProvider.swift
git commit -m "feat: wrap wireguard transport with obfuscation bind"
```

## Task 7: Apply Route Hardening From Adapter

**Files:**
- Modify: `Sources/WireGuardKit/WireGuardAdapter.swift`
- Modify: `Sources/WireGuardKit/PacketTunnelSettingsGenerator.swift`

- [ ] **Step 1: Prepare excluded route during settings generation**

In `makeSettingsGenerator(...)`, after resolving exit endpoints:

```swift
let obfuscationRoutes = try makeObfuscationExcludedRoutes(for: exitConfiguration, resolvedEndpoints: resolvedExitEndpoints)
```

Add helper:

```swift
private func makeObfuscationExcludedRoutes(for configuration: TunnelConfiguration, resolvedEndpoints: [Endpoint?]) throws -> [NEIPv4Route] {
    guard let obfuscation = configuration.obfuscation else { return [] }
    let validated = try obfuscation.validatedForSinglePhysicalTransport()
    guard let physicalPeer = validated.peers.first(where: { $0.transportLeg == .physical }) else {
        return []
    }
    guard let index = configuration.peers.firstIndex(where: { $0.publicKey == physicalPeer.peerPublicKey }) else {
        throw WireGuardAdapterError.obfuscationConfiguration("Obfuscated peer public key is not present in tunnel configuration")
    }
    guard let endpoint = resolvedEndpoints[index] else {
        throw WireGuardAdapterError.obfuscationConfiguration("Obfuscated peer has no endpoint")
    }
    do {
        return [try ObfuscationRouteExclusion.excludedIPv4Route(for: endpoint)]
    } catch {
        throw WireGuardAdapterError.obfuscationConfiguration("Obfuscated peer endpoint must resolve to IPv4 for route hardening")
    }
}
```

Pass routes into exit `DeviceConfiguration`:

```swift
DeviceConfiguration(
    configuration: exitConfiguration,
    resolvedEndpoints: resolvedExitEndpoints,
    reResolveEndpoint: entry == nil,
    obfuscationExcludedRoutes: obfuscationRoutes
)
```

- [ ] **Step 2: Preserve route hardening on iOS path changes**

In `didReceivePathUpdate(path:)`, keep the existing endpoint update flow, but ensure `settingsGenerator.generateNetworkSettings()` is applied before `wgSetConfig(...)` when `settingsGenerator.exit.obfuscationExcludedRoutes` is non-empty:

```swift
if !settingsGenerator.exit.obfuscationExcludedRoutes.isEmpty {
    let networkSettings = settingsGenerator.generateNetworkSettings()
    self.packetTunnelProvider?.setTunnelNetworkSettings(networkSettings) { error in
        if let error {
            self.logHandler(.error, "Failed to update obfuscation route hardening: \(error.localizedDescription)")
            return
        }
        wgSetConfig(handle, wgConfig, nil)
        wgDisableSomeRoamingForBrokenMobileSemantics(handle)
        wgBumpSockets(handle)
    }
    return
}
```

- [ ] **Step 3: Run focused Swift tests**

Run:

```bash
swift test --filter ObfuscationRouteExclusionTests
```

Expected: PASS.

- [ ] **Step 4: Commit**

Run:

```bash
git add Sources/WireGuardKit/WireGuardAdapter.swift Sources/WireGuardKit/PacketTunnelSettingsGenerator.swift
git commit -m "fix: preserve obfuscation route hardening"
```

## Task 8: Add Codec Compatibility Harness

**Files:**
- Modify: `Sources/WireGuardKitGo/obfuscator/codec.go`
- Create: `Sources/WireGuardKitGo/obfuscator/compat_test.go`

- [ ] **Step 1: Add black-box compatibility test skeleton**

Create `Sources/WireGuardKitGo/obfuscator/compat_test.go`:

```go
package obfuscator

import (
    "net"
    "os"
    "os/exec"
    "testing"
    "time"
)

func TestExternalWgObfuscatorAcceptsEncodedPacket(t *testing.T) {
    binary := os.Getenv("WG_OBFUSCATOR_BIN")
    if binary == "" {
        t.Skip("set WG_OBFUSCATOR_BIN to a built upstream wg-obfuscator binary")
    }

    target, err := net.ListenPacket("udp4", "127.0.0.1:0")
    if err != nil {
        t.Fatalf("target listen: %v", err)
    }
    defer target.Close()

    source, err := net.ListenPacket("udp4", "127.0.0.1:0")
    if err != nil {
        t.Fatalf("source listen: %v", err)
    }
    sourceAddr := source.LocalAddr().String()
    source.Close()

    cmd := exec.Command(binary,
        "--source-laddr="+sourceAddr,
        "--target="+target.LocalAddr().String(),
        "--key=shared-secret",
        "--masking=STUN",
        "--verbose=ERRORS",
    )
    if err := cmd.Start(); err != nil {
        t.Fatalf("start wg-obfuscator: %v", err)
    }
    defer func() {
        _ = cmd.Process.Kill()
        _ = cmd.Wait()
    }()

    time.Sleep(200 * time.Millisecond)

    codec := NewCleanRoomCodec(Config{Enabled: true, Key: "shared-secret", Masking: MaskingSTUN, MaxDummyBytes: 0})
    plain := append([]byte{1, 0, 0, 0}, make([]byte, 144)...)
    encoded, err := codec.Encode(plain)
    if err != nil {
        t.Fatalf("encode: %v", err)
    }

    conn, err := net.Dial("udp4", sourceAddr)
    if err != nil {
        t.Fatalf("dial source: %v", err)
    }
    defer conn.Close()
    if _, err := conn.Write(encoded); err != nil {
        t.Fatalf("write encoded: %v", err)
    }

    buf := make([]byte, 2048)
    _ = target.SetReadDeadline(time.Now().Add(2 * time.Second))
    n, _, err := target.ReadFrom(buf)
    if err != nil {
        t.Fatalf("read target: %v", err)
    }
    if string(buf[:n]) != string(plain) {
        t.Fatalf("forwarded packet mismatch: got %x want %x", buf[:n], plain)
    }
}
```

- [ ] **Step 2: Run compatibility test without binary**

Run:

```bash
cd Sources/WireGuardKitGo
go test ./obfuscator -run TestExternalWgObfuscatorAcceptsEncodedPacket
```

Expected: SKIP with message about `WG_OBFUSCATOR_BIN`.

- [ ] **Step 3: Run compatibility test with upstream binary**

Run:

```bash
cd Sources/WireGuardKitGo
WG_OBFUSCATOR_BIN=/absolute/path/to/wg-obfuscator go test ./obfuscator -run TestExternalWgObfuscatorAcceptsEncodedPacket -count=1
```

Expected: FAIL until `CleanRoomCodec` matches upstream behavior.

- [ ] **Step 4: Iterate codec from black-box observations**

Modify `Sources/WireGuardKitGo/obfuscator/codec.go` only from observed packet behavior and generated vectors. Keep the public methods:

```go
func (c *CleanRoomCodec) Encode(packet []byte) ([]byte, error)
func (c *CleanRoomCodec) Decode(packet []byte) ([]byte, error)
```

The compatibility gate is:

```bash
WG_OBFUSCATOR_BIN=/absolute/path/to/wg-obfuscator go test ./obfuscator -run TestExternalWgObfuscatorAcceptsEncodedPacket -count=1
```

Expected after iteration: PASS.

- [ ] **Step 5: Commit**

Run:

```bash
git add Sources/WireGuardKitGo/obfuscator/codec.go Sources/WireGuardKitGo/obfuscator/compat_test.go
git commit -m "feat: verify obfuscation codec compatibility"
```

## Task 9: Xcode Project Integration

**Files:**
- Modify: `WireGuard.xcodeproj/project.pbxproj`

- [ ] **Step 1: Add Swift source files to Xcode project**

Add these files to the project:

```text
Sources/WireGuardKitTypes/ObfuscationConfiguration.swift
Sources/WireGuardKit/ObfuscationRouteExclusion.swift
```

Target membership:

```text
WireGuardKitTypes -> ObfuscationConfiguration.swift
WireGuardKit -> ObfuscationRouteExclusion.swift
```

- [ ] **Step 2: Verify project file diff**

Run:

```bash
git diff -- WireGuard.xcodeproj/project.pbxproj
```

Expected: file references, group entries, and source build phase entries for only the two new Swift files.

- [ ] **Step 3: Commit**

Run:

```bash
git add WireGuard.xcodeproj/project.pbxproj
git commit -m "build: add obfuscation swift sources"
```

## Task 10: Final Verification

**Files:**
- No new files.

- [ ] **Step 1: Run Swift focused tests**

Run:

```bash
swift test --filter ObfuscationConfigurationTests
swift test --filter ObfuscationProviderCodingTests
swift test --filter ObfuscationRouteExclusionTests
```

Expected: PASS.

- [ ] **Step 2: Run Go focused tests**

Run:

```bash
cd Sources/WireGuardKitGo
go test ./obfuscator
go test ./... -run 'TestMaybeObfuscatingBind|TestConfigValidate|TestBind'
```

Expected: PASS.

- [ ] **Step 3: Run lint**

Run:

```bash
swiftlint
```

Expected: PASS or only pre-existing warnings outside files changed by this plan.

- [ ] **Step 4: Run whitespace check**

Run:

```bash
git diff --check
```

Expected: no output.

- [ ] **Step 5: Build package**

Run:

```bash
swift build
```

Expected: PASS.

- [ ] **Step 6: Build Go archive**

Run:

```bash
make -C Sources/WireGuardKitGo build
```

Expected: PASS. If toolchain dependencies are missing, record exact missing tool output.

- [ ] **Step 7: Build Xcode scheme**

Run:

```bash
xcodebuild -project WireGuard.xcodeproj -list
```

Then run the available app or network extension scheme:

```bash
xcodebuild -project WireGuard.xcodeproj -scheme WireGuard -configuration Debug build
```

Expected: PASS, or a signing/developer-team error after compilation reaches code signing.

## Self-Review

- Spec coverage:
  - Bind-wrapper architecture: Tasks 4, 5, and 6.
  - No loopback endpoint rewrite: Task 3 tests UAPI keeps the real endpoint.
  - Single-hop physical transport: Task 6 wraps `StdNetBind`.
  - Multihop physical entry leg: Task 6 wraps entry `StdNetBind` and leaves `singletun.Binder()` unchanged.
  - Route hardening: Tasks 3 and 7.
  - Metadata outside wg-quick: Task 2.
  - Codec compatibility: Task 8.
- Red-flag scan:
  - No blank requirement markers, empty test steps, or unspecified implementation tasks remain.
- Type consistency:
  - `ObfuscationConfiguration`, `PeerObfuscationConfiguration`, `ObfuscationRouteExclusion`, `obfuscator.Config`, `obfuscator.Bind`, and `CleanRoomCodec` are used consistently.
