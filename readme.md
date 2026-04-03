# EspreSSHo - SSH keys on JavaCards

EspreSSHo is a hardware-backed SSH agent and Git commit signing system built on JavaCard smart cards. The project provides secure key storage where private keys never leave the card.

> [!warning] This is unstable, probably unsafe software!
> This is a personal project and should not be used for real security purposes. It is intended for educational and experimental use only. Use at your own risk!
> The project is in early development and may contain security vulnerabilities. Do not use for protecting real secrets or in production environments.
> Always review the code and understand the risks before using. Contributions and feedback are welcome to improve security and functionality.
> The project is licensed under MIT, but that does not imply any warranty or liability. Use responsibly and securely.

I have done the barest of testing to make this work.

## Components

- **Mokapot** — JavaCard applet running on the card (AID: CA:FE:4D:6F:6B:61)
- **Barista** — Go host-side SSH agent that communicates with the card

## Features

- Up to 4 ECC P-256 keypairs stored on card
- Per-key security policies:
  - PIN-on-use requirement
  - PIN timeout (0-7 minutes)
  - Key erasure when PIN becomes blocked
- SSH agent protocol support
- Git commit signing via SSH signing protocol
- PC/SC smart card interface

## Quick Start

### Prerequisites

1. **Java 21** - Required for both build and runtime
2. **JavaCard SDK 3.2.0v25.1** - For the applet converter (ARM64 support)
3. **Go 1.23+** - For the client SSH agent
4. **Git submodules** - For JavaCard SDK dependencies

### Environment Setup

```bash
# Initialize git submodules (provides JavaCard SDKs)
git submodule update --init --recursive

# Set environment variables
export JAVA_HOME=/path/to/java21
export JC_HOME=sdks/javacard-3.2.0v25.1

# Verify JC_HOME points to correct SDK version
ls $JC_HOME/bin/converter  # Should exist
echo $JC_HOME | grep 3.2.0v25.1  # Should match version
```

### Build

```bash
# Build everything
just all

# Build applet only
just buildApplet

# Build client only
just buildClient
```

### Install Applet

```bash
# Load applet onto card (requires GlobalPlatformPro)
gp --install mokapot/build/mokapot-1.0.cap
```

### Use SSH Agent

```bash
# Generate a key in slot 0 with PIN protection
barista keys gen 0 --pin 1234 --require-pin

# List keys on card
barista keys list

# Start SSH agent
eval $(barista serve)

# Use with SSH/Git (SSH_AUTH_SOCK is set by serve command)
ssh user@host
git commit -S -m "signed commit"
```

## Commands

### Key Management

```bash
# Generate new key in slot 0-3 with explicit flags
barista keys gen <slot> --pin <pin> [--require-pin] [--timeout=N] [--erase-on-lock]

# List all keys on card
barista keys list

# Clear key from slot
barista keys clear <slot> --pin <pin>

# Regenerate key with new flags
barista keys regen <slot> --pin <pin> [--require-pin] [--timeout=N] [--erase-on-lock]

# Sign arbitrary data
barista keys sign <slot> <file>
```

### PIN Management

```bash
# Change PIN
barista pin change

# Unblock PIN using PUK
barista pin unblock
```

### SSH Agent

```bash
# Start agent (prints shell export commands)
barista serve

# List available card readers
barista readers

# Check card/applet status
barista status
```

### Automation

**CLI flags** (for scripts):

```bash
barista keys gen 0 --pin 1234 --require-pin
barista pin unblock --puk 12345678
```

**SSH_ASKPASS** (for GUI environments):

```bash
SSH_ASKPASS='echo 1234' barista serve
```

**Priority**: CLI flags → SSH_ASKPASS → terminal prompt

## Git Signing Setup

```bash
# Configure Git for SSH signing
git config --global gpg.format ssh
git config --global user.signingKey "$(barista keys list -q | head -1)"
git config --global commit.gpgSign true

# Test signing
git commit -S -m "test signed commit"
```

## Build Requirements

- **JavaCard SDK 3.2.0v25.1** (set JC_HOME environment variable - newer converter supports ARM64)
- **Java 21+** (set JAVA_HOME environment variable)
- **Go 1.23+**
- **Apache Ant** (for JavaCard build)
- **just** command runner
- **Git submodules** (`git submodule update --init --recursive`)

## Security Notes

- Private keys never leave the smart card
- All cryptographic operations performed on-card
- PIN required for key generation and optionally for signing
- Keys can be configured to self-destruct if PIN becomes blocked
