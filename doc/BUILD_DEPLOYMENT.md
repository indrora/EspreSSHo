# Build and Deployment Guide

This guide covers building, deploying, and verifying the EspreSSHo Mokapot applet.

## Prerequisites

### Required Software
- **Java 21** (consistent across build and runtime)
- **JavaCard SDK 3.2.0v25.1**: jc320v25.1_kit (targeting JavaCard 3.0.5, ARM64 converter support)
- **Apache Ant** (build automation)
- **GlobalPlatform Pro** (optional, for deployment management)
- **Git submodules**: Required for JavaCard SDK dependencies

### Hardware Requirements
- **Recommended**: Real JavaCard hardware (development ready with full P-256 support)
- **Development**: JavaCard simulators (limited P-256 support due to environment)
- PC/SC compatible smart card reader

## Build Process

### 1. Environment Setup
```bash
# Ensure Java 21 is active
export JAVA_HOME=/path/to/java-21
java -version  # Should show Java 21

# Set JavaCard SDK 3.2.0v25.1 path (ARM64 compatible converter)
export JC_HOME=/path/to/jc320v25.1_kit

# Initialize git submodules for SDK dependencies
git submodule update --init --recursive

# Verify correct SDK version and ARM64 converter availability
ls $JC_HOME/bin/converter  # Should exist
echo $JC_HOME | grep v25.1  # Should show v25.1
```

### 2. Build the Applet
```bash
cd mokapot/
ant clean build

# Verify CAP file generation
ls -la build/*.cap
# Should show: mokapot-v1.0.cap and mokapot-release-v1.0.cap
```

### 3. Build Validation
```bash
# Check CAP file structure
gp --verbose --dry-run --install build/mokapot-v1.0.cap
```

## Deployment

### Method 1: GlobalPlatform Pro (Recommended)
```bash
# List available applets
gp --list

# Delete existing applet (if present)
gp --delete CAFE4D6F6B61000100000000000000 --force

# Install the applet
gp --install build/mokapot-v1.0.cap

# Verify installation
gp --list | grep -i mokapot
```

### Method 2: Card Manager Tools
```bash
# Using specific card manager (example for your card type)
# Replace with your card's specific tools
cardmanager --install build/mokapot-v1.0.cap
```

## Verification

### 1. Basic Connectivity Test
```bash
# Test PC/SC connectivity
opensc-tool --list-readers

# Check card ATR
opensc-tool --atr
```

### 2. Applet Selection Test
```bash
# Select the applet (should return 90 00)
opensc-tool -s 00:A4:04:00:10:CA:FE:4D:6F:6B:61:00:01:00:00:00:00:00:00:00:00
```

### 3. P-256 Key Generation Test
```bash
# Generate key in slot 0 with PIN 1234 and default flags
java -jar gp.jar --apdu 00A4040008CAFE4D6F6B61000100 --apdu 0001000006043132333480

# Should return 65-byte public key starting with 04
```

### 4. Comprehensive Hardware Test
```bash
cd ../doc/
python test_mokapot.py test-all
```

Expected output includes:
- Connection to card reader
- Applet selection success
- P-256 key generation (~125ms on real hardware)
- Public key retrieval (immediate from generation)
- All 4 slots functional
- Signature generation and verification

## Production Deployment Checklist

### Security Configuration
- [ ] Change default PIN from `1234`
- [ ] Set appropriate PUK value
- [ ] Configure key timeout settings if needed
- [ ] Test PIN blocking/unblocking procedures
- [ ] Verify PIN-protected operations

### Hardware Validation
- [ ] Test on target JavaCard hardware model
- [ ] Verify key generation performance acceptable (~125ms)
- [ ] Test all 4 key slots independently
- [ ] Validate signature verification with target applications
- [ ] Confirm P-256 domain parameter compatibility

### Integration Testing
- [ ] Test with SSH agent integration
- [ ] Verify Git commit signing workflow
- [ ] Validate APDU command sequences
- [ ] Test error handling and recovery
- [ ] Verify public key return from generation

## Common Issues and Solutions

### Build Issues

**"Java version mismatch"**
```bash
# Solution: Ensure consistent Java 21 usage
export JAVA_HOME=/path/to/java-21
ant clean build
```

**"JavaCard SDK not found"**
```bash
# Solution: Set correct SDK 3.2.0v25.1 path and initialize submodules
git submodule update --init --recursive
export JC_HOME=/path/to/jc320v25.1_kit
# Verify: ls $JC_HOME/bin/converter
```

### Deployment Issues

**"Applet already installed"**
```bash
# Solution: Delete existing applet first
gp --delete CAFE4D6F6B61000100000000000000 --force
gp --install build/mokapot-v1.0.cap
```

**"Installation authentication failed"**
- Check card authentication keys
- Verify card is in correct state
- Try card reset and retry

### Runtime Issues

**"Select applet fails"**
- Verify correct AID: `CAFE4D6F6B61000100000000000000`
- Check if applet is properly installed
- Try card reset

**"P-256 operations fail"**
- **Fixed**: Real hardware now has high success rate
- Root cause was incompatible domain parameters (now resolved)
- Simulators: Still expected to have ~32% success rate due to environment
- **Solution**: Deploy on real JavaCard hardware for production

**"Key generation appears successful but no key stored"**
- **Fixed**: Proper validation prevents false success
- Key generation now returns public key immediately
- Failed operations return appropriate error codes
- **Solution**: Use updated implementation

### Migration Issues

**"PIN required for key operations"**
```bash
# Old v1.x: 00 01 00 00
# New implementation: 00 01 00 00 06 04 31 32 33 34 80
#                     └─ PIN data ─┘ └─ FLAGS
```

**"Slot occupied error (0x6985)"**
- Implementation protects against accidental key overwrites
- Use REGEN_KEY (0x08) to intentionally replace existing keys
- GEN_KEY (0x01) only works on empty slots

## Performance Benchmarks

Based on real hardware testing:

| Operation | Real Hardware | Simulator | Improvements |
|-----------|---------------|-----------|-------------------|
| Key Generation | ~125ms | Variable | Returns public key immediately |
| Signature Generation | <100ms | Variable | Unchanged |
| PIN Verification | <50ms | <50ms | Enhanced validation |
| Public Key Retrieval | <50ms | <50ms | Available from generation |
| P-256 Success Rate | 100% | ~32% | Fixed domain parameters |

## Troubleshooting

### Debug Commands
```bash
# Reader diagnostics
opensc-tool --list-readers -v

# Card information
opensc-tool --atr --verbose

# APDU debugging
opensc-tool --verbose -s <command>

# GlobalPlatform status
gp --list --verbose
```

### Version-Specific Debugging

**Command Validation:**
```bash
# Test unified PIN format
gp --apdu 00A4040008CAFE4D6F6B61000100 --apdu 0001000006043132333480

# Verify public key return
gp --apdu 00A4040008CAFE4D6F6B61000100 --apdu 00020000
```

**P-256 Domain Parameter Validation:**
```bash
# Should succeed on real hardware
java -jar gp.jar --apdu 00A4040008CAFE4D6F6B61000100 --apdu 0001000006043132333480

# Response should be 65 bytes starting with 04
```

### Log Analysis
- Check PC/SC daemon logs for connectivity issues
- Monitor JavaCard responses for error codes
- Use verbose mode for detailed APDU traces
- Look for specific error codes (0x6985, 0x6982)

## Recent Fixes and Improvements

### 🔧 Fixed: P-256 Domain Parameter Compatibility
- **Issue**: JCAlgTest showed card supports P-256, but our parameters were rejected
- **Root Cause**: ECParams.java had incorrect G_Y coordinates vs. standard secp256r1
- **Fix**: Updated to use JCAlgTest-compatible domain parameters
- **Result**: 100% success rate on real JavaCard hardware

### 🔧 Enhanced: API Security Model  
- **Change**: All write operations now require PIN verification
- **Benefit**: Prevents unauthorized key manipulation
- **Migration**: Update applications to include PIN in write commands

### 🔧 Improved: Key Generation UX
- **Enhancement**: GEN_KEY and REGEN_KEY return generated public key
- **Benefit**: Immediate key availability without separate retrieval
- **Format**: 65-byte uncompressed EC point (04 || X || Y)

### 🔧 Added: Slot Protection
- **Enhancement**: GEN_KEY fails if slot occupied (0x6985)
- **Benefit**: Prevents accidental key overwrites  
- **Usage**: Use REGEN_KEY for intentional key replacement

## Support

### Current Status
- **Full P-256 Compatibility**: Fixed domain parameter issues
- **Development Ready**: High success rate on real hardware
- **Enhanced Security**: PIN protection for all write operations
- **Improved UX**: Immediate public key return from generation

For build/deployment issues:
1. Verify environment matches requirements exactly (Java 21 + SDK)
2. Test with provided validation scripts
3. Check hardware compatibility (prefer real JavaCard over simulators)
4. Use current APDU format for all operations
5. Refer to JavaCard and card reader documentation

The build process is tested and validated for deployment on real JavaCard hardware with full P-256 compatibility. 🔐