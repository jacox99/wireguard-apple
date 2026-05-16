# wg-obfuscator Bind Integration Design

## Goal

Integrate wg-obfuscator-compatible traffic obfuscation into WireGuard for Apple on both iOS and macOS while keeping the server side as the existing standalone `wg-obfuscator` process.

The client must be wire-compatible with upstream `ClusterM/wg-obfuscator`. A server deployment should continue to look like:

```text
Apple client wireguard-go obfuscating bind -> server wg-obfuscator -> server WireGuard UDP port
```

## References

- `ClusterM/wg-obfuscator` documents the independent-obfuscator topology, key-based obfuscation, masking modes, routing loop caveat, and server-side standalone deployment model: https://github.com/ClusterM/wg-obfuscator
- Apple documents packet tunnel route inclusion/exclusion through `NEPacketTunnelNetworkSettings`, `NEIPv4Settings.includedRoutes`, and `NEIPv4Settings.excludedRoutes`: https://developer.apple.com/documentation/networkextension/routing_your_vpn_network_traffic
- Apple documents `NEIPv4Settings.excludedRoutes` as IPv4 traffic routed to the primary physical interface, not the TUN interface: https://developer.apple.com/documentation/networkextension/neipv4settings/excludedroutes

## Current Project Context

The app runs `wireguard-go` inside `PacketTunnelProvider` and passes it the utun file descriptor from `WireGuardAdapter`.

Relevant files:

- `Sources/WireGuardNetworkExtension/PacketTunnelProvider.swift`
  - Loads `TunnelConfiguration`.
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
- `Sources/Shared/Model/NETunnelProviderProtocol+Extension.swift`
  - Stores wg-quick config in the keychain.
  - Sets `NETunnelProviderProtocol.serverAddress` to the peer endpoint when there is one endpoint.
- `Sources/WireGuardKitGo/api-apple.go`
  - Creates Go WireGuard devices.
  - Single-hop currently uses `conn.NewStdNetBind()`.
  - Multihop creates an entry device using `conn.NewStdNetBind()` and an exit device using `singletun.Binder()`.
- `Sources/WireGuardKitGo/wireguard-go/tun/multihoptun/*`
  - Shows the relevant local pattern: replace a WireGuard device's `conn.Bind` to change transport behavior without changing WireGuard encryption logic.

## Chosen Approach

Implement wg-obfuscator as a Go `conn.Bind` wrapper inside `wireguard-go`.

Do not run a standalone helper process on macOS. Do not add a Swift-side loopback UDP forwarder. Do not rewrite WireGuard peer endpoints to `127.0.0.1:<port>`.

The peer endpoint remains the real server-side wg-obfuscator endpoint:

```ini
[Peer]
Endpoint = example.com:19999
```

At runtime, the Go backend wraps the normal bind:

```go
baseBind := conn.NewStdNetBind()
bind := obfuscator.NewBind(baseBind, obfuscationConfig)
dev := device.NewDevice(tun, bind, logger)
```

The wrapper intercepts transport datagrams at the same layer where `wireguard-go` already sends and receives UDP packets.

## Why This Matches Multihop Better

Multihop avoids an inner packet loop by replacing a WireGuard device's `conn.Bind`:

```go
exitDev := device.NewDevice(&wrapper, singletun.Binder(), logger)
```

The exit device's encrypted UDP packet is not sent through OS routing. It is handed through `multihopBind` into `MultihopTun`, where it becomes payload for the entry WireGuard device.

wg-obfuscator needs the same architectural shape, not the same multihop machinery:

```text
wireguard-go device
  -> ObfuscatingBind
  -> obfuscate/mask UDP datagram
  -> underlying StdNetBind
  -> server wg-obfuscator endpoint
```

The transform is inside the WireGuard transport boundary. This avoids a fake local endpoint, a local UDP listener, local source tracking, and app-level forwarding state.

## Licensing Gate

Upstream `ClusterM/wg-obfuscator` is GPL-3.0 licensed. The implementation must make an explicit licensing decision before copying or linking upstream source code into this project.

Acceptable implementation paths:

- Treat GPL-3.0 compatibility as acceptable for the distributed product and vendor/link upstream code with license notices.
- Obtain a separate license from upstream authors.
- Implement a clean-room compatible codec from protocol behavior, black-box tests, and golden vectors without copying upstream source.

The implementation plan assumes the clean-room path for the first iteration.

## Stored Configuration

The normal WireGuard peer endpoint remains the real server-side wg-obfuscator endpoint. Obfuscation metadata is stored separately from wg-quick text:

```text
enabled = true
key = "plain-text-shared-obfuscation-key"
masking = STUN | AUTO | NONE
maxDummyBytes = 4
peerPublicKey = <peer public key>
transportLeg = physical
```

The first implementation supports one physical obfuscated transport per tunnel:

- Single-hop: the one WireGuard peer transport is obfuscated.
- Multihop: the entry relay transport is obfuscated, because that is the physical packet visible to the outside network.

The first implementation does not support obfuscating the multihop exit leg inside the entry tunnel. That can be added later by wrapping `singletun.Binder()`.

## Runtime Data Flow

### Single-Hop Start

```text
1. PacketTunnelProvider loads TunnelConfiguration and ObfuscationConfiguration.
2. WireGuardAdapter resolves the real peer endpoint as it does today.
3. PacketTunnelSettingsGenerator builds network settings.
4. If hardening is enabled, network settings include real obfuscator IPv4 /32 as excluded route.
5. setTunnelNetworkSettings(...) succeeds.
6. WireGuardAdapter calls wgTurnOnIAN(...) with normal WireGuard UAPI and obfuscation bridge config.
7. Go bridge constructs conn.NewStdNetBind().
8. Go bridge wraps it in obfuscator.Bind when obfuscation is enabled.
9. Go bridge starts device.NewDevice(..., obfuscatingBind, ...).
```

There is no UAPI endpoint rewrite.

### Single-Hop Outbound Packet Flow

```text
utun
  -> Router
  -> wireguard-go encrypts user packet as normal WireGuard UDP datagram
  -> ObfuscatingBind.Send(buf, endpoint)
  -> codec encodes and masks buf using key/masking settings
  -> underlying StdNetBind.Send(encoded, endpoint)
  -> provider-owned UDP socket sends to server wg-obfuscator endpoint
  -> server wg-obfuscator deobfuscates
  -> server wg-obfuscator forwards normal WireGuard UDP to server WireGuard port
```

### Single-Hop Inbound Packet Flow

```text
server WireGuard
  -> server wg-obfuscator
  -> obfuscated UDP reply to Apple client
  -> underlying StdNetBind receive function reads UDP datagram
  -> ObfuscatingBind receive wrapper decodes and unmasks datagram
  -> wireguard-go receives normal WireGuard UDP datagram
  -> wireguard-go decrypts
  -> Router writes payload to utun
```

Invalid or undecodable inbound datagrams are dropped and logged at verbose/debug level.

### Multihop Physical Entry Leg

Current multihop shape:

```text
real utun
  -> Router
  -> exit WireGuard device
  -> singletun.Binder()
  -> entry WireGuard device
  -> conn.StdNetBind
  -> entry relay
```

Revised obfuscated multihop shape:

```text
real utun
  -> Router
  -> exit WireGuard device
  -> singletun.Binder()
  -> entry WireGuard device
  -> ObfuscatingBind wrapping conn.StdNetBind
  -> server wg-obfuscator in front of entry relay
  -> entry relay
```

Only the physical entry leg is obfuscated in the first implementation. The exit leg remains carried inside the entry WireGuard tunnel via `singletun.Binder()`.

## Loop Prevention

There are two loop categories:

### Inner Transport Loops

The old loopback-forwarder design risked:

```text
wireguard-go -> local UDP -> Swift obfuscator -> real server -> utun capture -> wireguard-go -> local UDP -> repeat
```

The bind-wrapper design removes the local UDP hop and endpoint rewrite. WireGuard continues to use the real peer endpoint, and the obfuscation transform runs inside `conn.Bind.Send` and receive wrappers.

This mirrors multihop's useful property: transport customization happens by replacing a bind, not by creating an app-level local forwarder.

### Physical Outer UDP Capture

The final packet still goes to the physical server-side wg-obfuscator endpoint:

```text
ObfuscatingBind -> StdNetBind -> server wg-obfuscator public IP
```

On Apple platforms there is no Linux-style `fwmark` bypass. The local `wireguard-go` implementation confirms `SetMark` is a no-op on Darwin.

The primary expectation is that this remains the provider-owned tunnel transport path, as normal WireGuard already uses. As a safety backstop, network settings may add an explicit `/32` excluded route for the resolved real obfuscator IPv4. This is especially useful if the obfuscator endpoint differs from the value stored in `NETunnelProviderProtocol.serverAddress`.

The first implementation should add this route exclusion when the real endpoint resolves to IPv4. If route setup fails, startup fails rather than risking silent recursion.

## Network Changes

On path change:

```text
1. Resolve updated real peer endpoint using the existing adapter path.
2. Keep UAPI endpoint as the real endpoint.
3. If the resolved IPv4 changed, rebuild network settings with the new excluded /32 route.
4. Call wgSetConfig(...) with normal endpoint update.
5. Bump wireguard-go sockets using the existing adapter behavior.
6. ObfuscatingBind continues to encode/decode at the bind layer.
```

No local obfuscator session needs to be restarted because there is no local listener.

## Component Boundaries

### WireGuardKitTypes

Add small Swift value models:

- `ObfuscationMasking`
  - Values: `stun`, `auto`, `none`.
- `PeerObfuscationConfiguration`
  - Peer public key.
  - Key string, 1...255 UTF-8 bytes.
  - Masking mode.
  - Max dummy bytes, default 4.
  - Transport leg, initially `physical`.
- `ObfuscationConfiguration`
  - Collection of peer configs.
  - Helper for looking up settings by peer public key.

These types carry configuration only.

### Shared App Model

Persist obfuscation metadata outside wg-quick text:

- `NETunnelProviderProtocol.providerConfiguration["Obfuscation"]` stores a property-list-safe dictionary.
- macOS must preserve existing `providerConfiguration["UID"]`.
- Import/export of plain wg-quick configs remains unchanged for the first implementation.

### WireGuardKit

Update Swift bridge code:

- `WireGuardAdapter.start(...)` and `startMultihop(...)` read optional `ObfuscationConfiguration`.
- `WireGuardAdapter` validates one physical obfuscated peer.
- `PacketTunnelSettingsGenerator` may add excluded IPv4 host routes for the resolved physical obfuscator endpoint.
- `WireGuardAdapter` passes a C-compatible obfuscation config into `wgTurnOnIAN(...)` or `wgTurnOnMultihop(...)`.

Swift does not transform packets and does not own an obfuscation session lifecycle.

### WireGuardKitGo

Add Go obfuscation package:

- `obfuscator.Codec`
  - Clean-room wire-compatible encode/decode logic.
- `obfuscator.Bind`
  - Implements `conn.Bind`.
  - Delegates `Open`, `Close`, `ParseEndpoint`, and `SetMark` to the wrapped bind.
  - Wraps receive functions returned from `Open`.
  - Encodes outbound datagrams in `Send`.
- C bridge config conversion.
  - Converts Swift-provided config into Go config structs.
  - Single-hop wraps `conn.NewStdNetBind()`.
  - Multihop wraps the entry device's `conn.NewStdNetBind()` for the physical leg.

## Error Handling

Startup fails if:

- Obfuscation is enabled but no matching peer exists.
- More than one physical obfuscated peer is configured.
- The key is empty or longer than 255 UTF-8 bytes.
- The masking mode is unsupported.
- The physical endpoint is missing.
- IPv4 route exclusion is required but endpoint resolution has no IPv4 address.
- Applying network settings with the excluded route fails.
- Go bridge obfuscation config conversion fails.
- Starting `wireguard-go` fails after bind wrapping.

Runtime packet errors:

- Decode failure: drop packet and log verbose/debug.
- Encode failure: return an error from `Send` so WireGuard's normal send error path handles it.
- Unexpected packet shape: drop packet and log verbose/debug.

## Testing Strategy

### Swift Unit Tests

Add tests for:

- Obfuscation configuration validation.
- Property-list round trip in `NETunnelProviderProtocol.providerConfiguration`.
- Physical endpoint IPv4 exclusion route generation.
- No UAPI endpoint rewrite when obfuscation is enabled.

### Go Unit Tests

Add tests for:

- `obfuscator.Bind.Send` encodes before delegating to base bind.
- `obfuscator.Bind.Open` wraps receive functions and decodes before returning to WireGuard.
- Invalid inbound datagrams are dropped until a valid datagram is received or the base receive function errors.
- `Close`, `ParseEndpoint`, and `SetMark` delegate to the base bind.
- Single-hop bridge wraps `StdNetBind` only when obfuscation is enabled.
- Multihop bridge wraps the entry leg bind when physical entry obfuscation is enabled.

### Codec Compatibility Tests

Use black-box tests against an externally built upstream `wg-obfuscator` binary:

- Client-encoded packet is accepted by upstream server mode and forwarded as plain WireGuard UDP.
- Upstream-encoded reply is decoded by local clean-room codec.
- `NONE`, `STUN`, and `AUTO` modes are covered.
- Invalid masked packets are rejected.

### Manual Verification

Manual device verification must include:

- iOS single-hop full-tunnel config with obfuscation enabled.
- macOS single-hop full-tunnel config with obfuscation enabled.
- iOS or macOS multihop config with physical entry-leg obfuscation enabled.
- Server running standalone `wg-obfuscator`.
- Confirm server sees traffic arrive at wg-obfuscator port first.
- Confirm WireGuard UAPI runtime endpoint remains the real server endpoint.
- Confirm no runaway packet recursion after activation.

## Scope Exclusions

The first implementation does not include:

- UI editing controls for obfuscation settings.
- Import/export custom wg-quick keys.
- Multiple simultaneous obfuscated physical transports.
- IPv6-only real obfuscator endpoints.
- Obfuscating the multihop exit leg inside the entry tunnel.
- Running a standalone helper process on macOS.
- Swift-side local UDP forwarding.
- Rewriting endpoints to loopback.
