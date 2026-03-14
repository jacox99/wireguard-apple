# CLAUDE.md

This file provides guidance to Claude Code (claude.ai/code) when working with code in this repository.

## Project Overview

WireGuard for iOS and macOS - a native VPN client application implementing the WireGuard protocol. The project contains a reusable Swift library (`WireGuardKit`) and platform-specific applications for iOS and macOS.

## Building

### Prerequisites
- Xcode
- Go 1.19+ (`brew install go`)
- swiftlint (`brew install swiftlint`)

### Initial Setup
```bash
# Clone and configure developer team
cp Sources/WireGuardApp/Config/Developer.xcconfig.template Sources/WireGuardApp/Config/Developer.xcconfig
# Edit Developer.xcconfig with your Apple Developer team ID

# Open in Xcode
open WireGuard.xcodeproj
```

### Build Commands
- **Build project**: Build via Xcode (Cmd+B) or use `xcodebuild -project WireGuard.xcodeproj -scheme WireGuard -configuration Debug build`
- **Build wireguard-go bridge**: `cd Sources/WireGuardKitGo && make` (normally handled by Xcode build phases)

### Linting
```bash
swiftlint
```

## Architecture

### Module Structure

```
Sources/
├── WireGuardApp/         # Main app (iOS + macOS UI, tunnel management)
│   ├── UI/iOS/           # iOS-specific UI (UIKit)
│   ├── UI/macOS/         # macOS-specific UI (AppKit, menu bar app)
│   ├── Tunnel/           # Tunnel lifecycle, status, configuration parsing
│   └── Config/           # Xcode config files
├── WireGuardKit/         # Reusable Swift library for WireGuard
├── WireGuardKitC/        # C implementation (x25519 cryptography)
├── WireGuardKitGo/       # Go-based WireGuard backend (compiled to static lib)
├── WireGuardNetworkExtension/  # NEPacketTunnelProvider implementation
├── Shared/               # Shared utilities (logging, keychain, model extensions)
└── WireGuardKitRust/     # (Experimental) Rust backend
```

### Key Components

**WireGuardAdapter** (`Sources/WireGuardKit/WireGuardAdapter.swift`):
- Core adapter bridging Swift and the Go WireGuard backend
- Manages tunnel lifecycle (start/stop/update)
- Handles DNS resolution and network path monitoring
- Provides interface name via utun file descriptor

**TunnelsManager** (`Sources/WireGuardApp/Tunnel/TunnelsManager.swift`):
- Manages `NETunnelProviderManager` instances
- Handles tunnel creation, deletion, and status observation
- Coordinates with iOS/macOS system VPN frameworks

**PacketTunnelProvider** (`Sources/WireGuardNetworkExtension/PacketTunnelProvider.swift`):
- iOS/macOS network extension entry point
- Instantiates `WireGuardAdapter` and handles tunnel start/stop

**TunnelConfiguration** (`Sources/WireGuardKit/TunnelConfiguration.swift`):
- Data model: `InterfaceConfiguration` + `[PeerConfiguration]`
- Parses from/to wg-quick config format

### WireGuardKit Integration

`WireGuardKit` is published as a Swift Package for third-party apps:
- Package URL: `https://git.zx2c4.com/wireguard-apple`
- Requires external build target for `wireguard-go-bridge` (see README.md)

### Platform Differences

- **iOS**: Full-screen app with tunnel list, uses `NEVPNManager`/`NETunnelProviderManager`
- **macOS**: Menu bar app (no dock icon), handles multiple users, uses `StatusItemController`

## Configuration

- Config files stored in iOS Keychain / macOS per-user keychain
- Import formats: `.conf` files, `.zip` archives, `.mobileconfig` profiles
- wg-quick format supported (excluding: FwMark, Table, PreUp, PostUp, PreDown, PostDown, SaveConfig)

## Code Conventions

- SwiftLint configuration in `.swiftlint.yml`
- SPDX license headers on all source files
- Platform-specific code gated with `#if os(iOS)` / `#if os(macOS)`
