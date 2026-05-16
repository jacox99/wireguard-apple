# wg-obfuscator Integration Design

## Goal

Integrate wg-obfuscator-compatible traffic obfuscation into WireGuard for Apple on both iOS and macOS while keeping the server side as the existing standalone `wg-obfuscator` process.

The client must be wire-compatible with upstream `ClusterM/wg-obfuscator`. A server deployment should continue to look like:

```text
Apple client embedded obfuscator -> server wg-obfuscator -> server WireGuard UDP port
```

## References

- `ClusterM/wg-obfuscator` documents the independent-obfuscator topology, key-based obfuscation, masking modes, routing loop caveat, and server-side standalone deployment model: https://github.com/ClusterM/wg-obfuscator
- Apple documents packet tunnel route inclusion/exclusion through `NEPacketTunnelNetworkSettings`, `NEIPv4Settings.includedRoutes`, and `NEIPv4Settings.excludedRoutes`: https://developer.apple.com/documentation/networkextension/routing_your_vpn_network_traffic
- Apple documents `NEIPv4Settings.excludedRoutes` as IPv4 traffic routed to the primary physical interface, not the TUN interface: https://developer.apple.com/documentation/networkextension/neipv4settings/excludedroutes

## Current Project Context

The current app already runs `wireguard-go` inside `PacketTunnelProvider` and passes it the utun file descriptor from `WireGuardAdapter`.

Relevant files:

- `Sources/WireGuardNetworkExtension/PacketTunnelProvider.swift`
  - Loads `TunnelConfiguration` from the provider protocol.
  - Instantiates `WireGuardAdapter`.
  - Starts and stops the tunnel.
- `Sources/WireGuardKit/WireGuardAdapter.swift`
  - Resolves peer endpoints.
  - Builds `PacketTunnelSettingsGenerator`.
  - Starts `wireguard-go` using `wgTurnOnIAN(...)` or `wgTurnOnMultihop(...)`.
  - Applies endpoint updates on iOS network path changes.
- `Sources/WireGuardKit/PacketTunnelSettingsGenerator.swift`
  - Builds `NEPacketTunnelNetworkSettings`.
  - Builds WireGuard UAPI strings containing `endpoint=...`.
  - Currently includes default IPv4 and IPv6 routes and peer allowed IP routes.
- `Sources/WireGuardKitTypes/*.swift`
  - Defines `TunnelConfiguration`, `PeerConfiguration`, `Endpoint`, and IP types.
- `Sources/Shared/Model/NETunnelProviderProtocol+Extension.swift`
  - Stores wg-quick config in the keychain.
  - Uses `providerConfiguration` for a small amount of platform metadata.

## Chosen Approach

Use an embedded wg-obfuscator-compatible UDP forwarder inside the Network Extension on both iOS and macOS.

Do not run a standalone helper process on macOS. Do not modify `wireguard-go` packet encryption logic for the first implementation. The embedded forwarder is an in-process component that owns two UDP sides:

- Local side: listens on loopback for plain WireGuard UDP packets from `wireguard-go`.
- Outer side: sends and receives obfuscated UDP packets to and from the real remote wg-obfuscator server endpoint.

The adapter rewrites WireGuard runtime peer endpoints from the real endpoint to the local obfuscator endpoint before starting or updating `wireguard-go`.

## Licensing Gate

Upstream `ClusterM/wg-obfuscator` is GPL-3.0 licensed. The implementation must make an explicit licensing decision before copying or linking upstream source code into this project.

Acceptable implementation paths:

- Treat GPL-3.0 compatibility as acceptable for the distributed product and vendor/link upstream code with license notices.
- Obtain a separate license from upstream authors.
- Implement a clean-room compatible codec from protocol behavior and golden vectors without copying upstream source.

The implementation plan assumes the clean-room path for the first iteration: use upstream behavior as compatibility reference and test oracle, but do not copy upstream GPL source into this repository unless the licensing decision changes.

## Core Data Flow

### Stored Configuration

The normal WireGuard peer endpoint remains the real server-side wg-obfuscator endpoint:

```ini
[Peer]
Endpoint = example.com:19999
```

Obfuscation metadata is stored separately from the wg-quick text so normal import/export behavior remains understandable and compatible:

```text
enabled = true
key = "plain-text-shared-obfuscation-key"
masking = STUN | AUTO | NONE
maxDummyBytes = 4
peerPublicKey = <peer public key>
```

The first implementation supports one obfuscated peer per tunnel. If more than one peer is enabled for obfuscation, startup fails with a clear error. This keeps loopback port ownership, route exclusion, and server NAT mapping behavior simple.

### Tunnel Start

Startup order is strict:

```text
1. PacketTunnelProvider loads TunnelConfiguration and ObfuscationConfiguration.
2. WireGuardAdapter resolves the real obfuscator endpoint to IPv4.
3. WireGuardAdapter creates an ObfuscationSession for the obfuscated peer.
4. ObfuscationSession binds 127.0.0.1:<localPort>.
5. PacketTunnelSettingsGenerator builds NEPacketTunnelNetworkSettings.
6. Network settings include an excluded route for the resolved real obfuscator IPv4 /32.
7. setTunnelNetworkSettings(...) succeeds.
8. PacketTunnelSettingsGenerator builds WireGuard UAPI.
9. UAPI rewrites only the obfuscated peer endpoint to 127.0.0.1:<localPort>.
10. WireGuardAdapter starts wireguard-go with the rewritten UAPI and utun fd.
```

The local obfuscator socket must be bound before `wgTurnOnIAN(...)` or `wgTurnOnMultihop(...)` starts, because WireGuard may emit the first handshake immediately.

### Outbound Packet Flow

```text
wireguard-go
  -> sends encrypted WireGuard UDP packet to 127.0.0.1:<localPort>
  -> ObfuscationSession receives packet on local UDP socket
  -> ObfuscationSession records the local wireguard-go source address
  -> ObfuscationSession applies upstream-compatible wg-obfuscator transform
  -> ObfuscationSession applies masking mode if configured
  -> ObfuscationSession sends obfuscated UDP packet to realServerIPv4:obfsPort
  -> server wg-obfuscator receives packet first
  -> server wg-obfuscator forwards plain WireGuard packet to server WireGuard port
```

### Inbound Packet Flow

```text
server WireGuard
  -> server wg-obfuscator
  -> obfuscated UDP reply to Apple client outer socket
  -> ObfuscationSession validates source and deobfuscates packet
  -> ObfuscationSession removes masking if present
  -> ObfuscationSession sends plain WireGuard UDP packet to last local wireguard-go source address
  -> wireguard-go processes packet normally
```

The session must remember the last local source address seen from `wireguard-go`, because `wireguard-go` talks to the loopback listener through its own UDP bind.

## utun Loop Prevention

The critical loop to prevent is:

```text
ObfuscationSession outer UDP to realServerIPv4
  -> captured by full-tunnel route into utun
  -> wireguard-go encrypts it as user payload
  -> wireguard-go sends encrypted packet to 127.0.0.1:<localPort>
  -> ObfuscationSession sends another outer UDP packet
  -> repeat
```

The anti-loop invariant is:

```text
Only wireguard-go reads from and writes to the utun fd.
ObfuscationSession never injects IP packets into utun.
ObfuscationSession sends outer transport packets through a normal UDP socket.
The resolved real obfuscator server IPv4 address is excluded from the VPN route table before the first outer packet is sent.
```

For full-tunnel configurations such as `AllowedIPs = 0.0.0.0/0`, the generated network settings must include:

```text
includedRoutes = 0.0.0.0/0
excludedRoutes = realServerIPv4/32
```

The route exclusion applies to the real remote wg-obfuscator endpoint, not to `127.0.0.1:<localPort>`.

The first implementation requires IPv4 real obfuscator endpoints. If the hostname resolves only to IPv6, startup fails. This matches upstream wg-obfuscator's current practical deployment assumptions and avoids designing IPv6 route exclusion before the protocol path is proven.

## Network Changes

On path change:

```text
1. Re-resolve the real obfuscator hostname if the peer endpoint was a hostname.
2. If the resolved IPv4 changed, rebuild NEPacketTunnelNetworkSettings with the new excluded /32 route.
3. Apply the new network settings before sending outer packets to the new endpoint.
4. Update ObfuscationSession target endpoint.
5. Keep the WireGuard runtime endpoint as 127.0.0.1:<localPort>.
6. Bump or restart wireguard-go sockets using the existing adapter behavior.
```

If route update fails, the adapter must stop the obfuscation session and surface a tunnel error instead of risking looped traffic.

## Component Boundaries

### WireGuardKitTypes

Add small data models:

- `ObfuscationMode`
  - Values: `stun`, `auto`, `none`.
- `PeerObfuscationConfiguration`
  - Peer public key.
  - Key string, 1...255 bytes.
  - Masking mode.
  - Max dummy bytes, initially defaulting to 4.
- `ObfuscationConfiguration`
  - Collection of peer configs.
  - Helper for looking up settings by peer public key.

These types carry configuration only. They must not contain socket code, route code, or packet transform code.

### WireGuardKitObfuscator

Add a new module that owns upstream-compatible obfuscation behavior and UDP forwarding:

- `ObfuscationSession`
  - Starts and stops one local loopback listener.
  - Exposes `localEndpoint`.
  - Sends obfuscated packets to the real target endpoint.
  - Sends deobfuscated packets back to the local WireGuard source.
- `ObfuscationPacketCodec`
  - Wraps the upstream-compatible C codec.
  - Encodes outbound packets and decodes inbound packets.
- `ObfuscationRouteExclusion`
  - Creates `NEIPv4Route(destinationAddress: realServerIPv4, subnetMask: "255.255.255.255")`.

The module should compile for iOS and macOS and be usable by both the app target and Swift Package builds.

### WireGuardKit

Update the adapter and settings generator:

- `WireGuardAdapter.start(...)` and `startMultihop(...)` accept optional `ObfuscationConfiguration`.
- `makeSettingsGenerator(...)` creates obfuscation runtime state before producing network settings.
- `PacketTunnelSettingsGenerator` accepts endpoint overrides and excluded routes.
- UAPI generation uses endpoint overrides for obfuscated peers only.
- Network settings generation appends obfuscator excluded routes.

`WireGuardAdapter` should know session lifecycle and endpoint rewriting, but not packet transform internals.

### Shared App Model

Persist obfuscation metadata outside the wg-quick keychain text:

- `NETunnelProviderProtocol.providerConfiguration["Obfuscation"]` stores a property-list-safe dictionary.
- macOS must preserve the existing `providerConfiguration["UID"]`.
- Import/export of plain wg-quick configs remains unchanged for the first implementation.

## Error Handling

Startup fails if:

- Obfuscation is enabled but no peer endpoint exists.
- More than one obfuscated peer is configured.
- The key is empty or longer than 255 UTF-8 bytes.
- The masking mode is not one of `STUN`, `AUTO`, or `NONE`.
- The real endpoint cannot resolve to IPv4.
- The local UDP socket cannot bind.
- `setTunnelNetworkSettings(...)` fails after adding route exclusions.
- Starting `wireguard-go` fails after endpoint rewriting.

If `wireguard-go` startup fails after an obfuscation session starts, the adapter must stop that session before returning the error.

Runtime packet errors are logged and dropped:

- Bad obfuscated packet.
- Unexpected remote source.
- Decode failure.
- Missing local WireGuard source before first outbound packet.

Repeated runtime send failures should be logged. They should not crash the extension.

## Testing Strategy

### Unit Tests

Add tests for:

- Obfuscation configuration validation.
- Property-list round trip in `NETunnelProviderProtocol.providerConfiguration`.
- Endpoint override in generated UAPI.
- Excluded route generation for a resolved IPv4 endpoint.
- Startup failure when an obfuscated peer lacks an endpoint.
- Startup failure when endpoint resolution produces no IPv4 address.

### Codec Compatibility Tests

Vendor or wrap upstream codec code and add golden-vector tests generated from upstream `wg-obfuscator` source behavior:

- `NONE` round trip.
- `STUN` wrapped outbound packet can be unwrapped.
- `AUTO` accepts inbound STUN-masked first packet.
- Invalid masked packet is rejected.

### Integration Tests

Add local UDP integration tests for `ObfuscationSession`:

- WireGuard-side packet reaches fake remote server obfuscated.
- Fake remote reply reaches local WireGuard-side UDP socket deobfuscated.
- Session records local source address.
- Session drops inbound remote packets from unexpected source.

### Manual Verification

Manual device verification must include:

- iOS full-tunnel config with obfuscation enabled.
- macOS full-tunnel config with obfuscation enabled.
- Server running standalone `wg-obfuscator`.
- Confirm server sees traffic arrive at wg-obfuscator port first.
- Confirm real server IPv4 appears in excluded routes.
- Confirm no runaway local packet loop occurs after tunnel activation.

## Scope Exclusions

The first implementation does not include:

- UI editing controls for obfuscation settings.
- Import/export custom wg-quick keys.
- Multiple simultaneous obfuscated peers.
- IPv6 real obfuscator endpoints.
- Static bindings or two-way mode UI.
- Running a standalone helper process on macOS.
- Deep changes inside `wireguard-go` send/receive internals.
