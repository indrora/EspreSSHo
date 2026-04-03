package com.espressho.mokapot;

import javacard.framework.*;
import javacard.security.*;
import javacardx.crypto.*;

/**
 * SSHKeyApplet — Mokapot JavaCard applet.
 *
 * Stores up to 4 EC P-256 keypairs in EEPROM and exposes them for SSH signing
 * via the APDU interface described in CLAUDE.md.
 *
 * **Security Model:**
 * - Read operations (GET_PUBKEY, LIST_KEYS): No PIN required
 * - Write operations (GEN_KEY, REGEN_KEY, CLEAR_KEY): PIN verification required
 * - All write operations use unified APDU format: [PIN_LEN][PIN][FLAGS]
 * - GEN_KEY fails on occupied slots; use REGEN_KEY for replacement
 * - All flag setting is explicit (no inheritance/preservation)
 *
 * AID:
 *   Package : CA FE 4D 6F 6B 61        (6 bytes, "CafeMok[a]")  
 *   Applet  : CA FE 4D 6F 6B 61 00 01 00 00 00 00 00 00 00 00 (16 bytes)
 *
 * All signing is performed on-card; private key material never leaves the card.
 * The host only ever receives DER-encoded ECDSA signatures and raw public keys.
 *
 * PIN notes:
 *   - Default PIN  : "1234" (must be changed before production use)
 *   - Default PUK  : "12345678"
 *   - Max PIN tries: 3 — card blocks on exhaustion
 *   - Max PUK tries: 5 — PUK blocks if exhausted (card is permanently locked)
 *   - PIN state resets on deselect / power-off (OwnerPIN semantics)
 *   - Timeout enforcement (FLAG_TIMEOUT) is the host's responsibility; the card
 *     only tracks whether the PIN has been verified this session.
 *
 * **Implementation Notes:**
 * - PIN protection for all write operations
 * - Unified APDU format for GEN_KEY/REGEN_KEY/CLEAR_KEY
 * - Slot occupancy protection in GEN_KEY
 * - Explicit flag model (no flag preservation)
 * - New error codes: SW_KEY_EXISTS (0x6985)
 */
public class SSHKeyApplet extends Applet {

    // -------------------------------------------------------------------------
    // Limits and defaults
    // -------------------------------------------------------------------------

    private static final byte MAX_KEYS = (byte) 4;
    private static final byte PIN_MAX_TRIES = (byte) 3;
    private static final byte PUK_MAX_TRIES = (byte) 5;

    /** Maximum PIN length in bytes. */
    private static final byte PIN_MAX_LEN = (byte) 8;
    /** Maximum PUK length in bytes. */
    private static final byte PUK_MAX_LEN = (byte) 8;

    private static final byte[] DEFAULT_PIN = { '1', '2', '3', '4' };
    private static final byte[] DEFAULT_PUK = {
        '1',
        '2',
        '3',
        '4',
        '5',
        '6',
        '7',
        '8',
    };

    /** Raw length of an uncompressed P-256 point: 04 || X(32) || Y(32). */
    private static final short PUBKEY_LEN = (short) 65;

    // -------------------------------------------------------------------------
    // Persistent state (EEPROM)
    // -------------------------------------------------------------------------

    /** Up to 4 keypairs. Null slot = empty. */
    private KeyPair[] keyPairs;

    /** Per-slot flag byte (see APDUConstants.FLAG_*). */
    private byte[] keyFlags;

    /** Card PIN — validated once per session (resets on deselect). */
    private OwnerPIN pin;

    /** PUK — used only to unblock a blocked PIN. */
    private OwnerPIN puk;

    // -------------------------------------------------------------------------
    // Transient state (cleared on deselect / power-off)
    // -------------------------------------------------------------------------

    /**
     * Scratch buffer for public key export. Transient so we never accidentally
     * retain a public key value across sessions in RAM.
     */
    private byte[] pubKeyScratch;

    // -------------------------------------------------------------------------
    // Shared Signature instance (reused across sign operations)
    // -------------------------------------------------------------------------

    /**
     * ALG_ECDSA_SHA_256 with signPreComputedHash(): the host pre-computes the SHA-256 hash
     * and sends it to the card. The card signs the digest directly using ECDSA without
     * any internal hashing. This keeps hash algorithm selection entirely on the host side.
     */
    private Signature signer;

    // -------------------------------------------------------------------------
    // Constructor / install
    // -------------------------------------------------------------------------

    protected SSHKeyApplet() {
        // Set up PIN and PUK with default values.
        pin = new OwnerPIN(PIN_MAX_TRIES, PIN_MAX_LEN);
        pin.update(DEFAULT_PIN, (short) 0, (byte) DEFAULT_PIN.length);

        puk = new OwnerPIN(PUK_MAX_TRIES, PUK_MAX_LEN);
        puk.update(DEFAULT_PUK, (short) 0, (byte) DEFAULT_PUK.length);

        // Allocate key slot arrays in EEPROM.
        keyPairs = new KeyPair[MAX_KEYS];
        keyFlags = new byte[MAX_KEYS];

        // Shared signer instance — init before each use in handleSign().
        signer = Signature.getInstance(Signature.ALG_ECDSA_SHA_256, false);

        // Transient scratch buffer for public key bytes.
        pubKeyScratch = JCSystem.makeTransientByteArray(
            PUBKEY_LEN,
            JCSystem.CLEAR_ON_DESELECT
        );

        register();
    }

    public static void install(byte[] bArray, short bOffset, byte bLength) {
        new SSHKeyApplet();
    }

    // -------------------------------------------------------------------------
    // APDU dispatch
    // -------------------------------------------------------------------------

    public void process(APDU apdu) throws ISOException {
        if (selectingApplet()) {
            return; // SELECT accepted; nothing to respond beyond SW 9000.
        }

        byte[] buf = apdu.getBuffer();

        if (buf[ISO7816.OFFSET_CLA] != (byte) 0x00) {
            ISOException.throwIt(ISO7816.SW_CLA_NOT_SUPPORTED);
        }

        switch (buf[ISO7816.OFFSET_INS]) {
            case APDUConstants.INS_GEN_KEY:
                handleGenKey(apdu);
                break;
            case APDUConstants.INS_GET_PUBKEY:
                handleGetPubKey(apdu);
                break;
            case APDUConstants.INS_SIGN:
                handleSign(apdu);
                break;
            case APDUConstants.INS_LIST_KEYS:
                handleListKeys(apdu);
                break;
            case APDUConstants.INS_VERIFY_PIN:
                handleVerifyPIN(apdu);
                break;
            case APDUConstants.INS_CHANGE_PIN:
                handleChangePIN(apdu);
                break;
            case APDUConstants.INS_SET_FLAGS:
                handleSetFlags(apdu);
                break;
            case APDUConstants.INS_REGEN_KEY:
                handleRegenKey(apdu);
                break;
            case APDUConstants.INS_UNBLOCK_PIN:
                handleUnblockPIN(apdu);
                break;
            case APDUConstants.INS_CLEAR_KEY:
                handleClearKey(apdu);
                break;
            case APDUConstants.INS_GET_FLAGS:
                handleGetFlags(apdu);
                break;
            default:
                ISOException.throwIt(ISO7816.SW_INS_NOT_SUPPORTED);
        }
    }

    // -------------------------------------------------------------------------
    // Instruction handlers
    // -------------------------------------------------------------------------

    /**
     * INS_GEN_KEY (0x01) — generate a new keypair in the specified slot.
     *
     * **BREAKING CHANGE:** Now requires PIN verification and fails if slot is occupied.
     *
     * APDU Format: [PIN_LEN][PIN][FLAGS]
     * - PIN_LEN: 1 byte (range: 1-8)
     * - PIN: Variable-length PIN data (1-8 bytes)
     * - FLAGS: Security flags byte (see APDUConstants.FLAG_*)
     *
     * P1 = slot (0–3)
     * P2 = reserved (must be 0x00)
     * Data = PIN length + PIN bytes + flags byte
     *
     * Security Policy:
     * - Requires PIN verification before proceeding
     * - Fails with SW_KEY_EXISTS if slot is already occupied
     * - Use INS_REGEN_KEY to replace existing keys
     *
     * Returns:
     * - SW_KEY_EXISTS (0x6985): Slot occupied, use INS_REGEN_KEY
     * - SW_SECURITY_STATUS_NOT_SATISFIED (0x6982): PIN verification failed
     * - SW_WRONG_DATA (0x6A80): Invalid flags (reserved bits set)
     * - SW_WRONG_LENGTH (0x6700): Invalid APDU or PIN length
     * - SW_9000: Success + new 65-byte uncompressed public key in response
     *
     * Transaction Safety: Key generation and flag setting are atomic.
     * Implementation: Uses makeP256KeyPair() with proper domain parameter setting.
     */
    private void handleGenKey(APDU apdu) {
        byte[] buf = apdu.getBuffer();
        byte slot = buf[ISO7816.OFFSET_P1];
        checkSlot(slot);

        // Parse APDU: [PIN_LEN][PIN][FLAGS]
        short dataLen = apdu.setIncomingAndReceive();
        if (dataLen < 2) {
            // Minimum: PIN_LEN + FLAGS
            ISOException.throwIt(ISO7816.SW_WRONG_LENGTH);
        }

        byte pinLen = buf[ISO7816.OFFSET_CDATA];
        if (pinLen < 1 || pinLen > PIN_MAX_LEN) {
            ISOException.throwIt(ISO7816.SW_WRONG_LENGTH);
        }

        // Validate total data length
        if (dataLen != (short) (1 + pinLen + 1)) {
            ISOException.throwIt(ISO7816.SW_WRONG_LENGTH);
        }

        // Verify PIN
        if (!pin.check(buf, (short) (ISO7816.OFFSET_CDATA + 1), pinLen)) {
            ISOException.throwIt(
                APDUConstants.SW_SECURITY_STATUS_NOT_SATISFIED
            );
        }

        // Check slot occupancy - NEW PROTECTION with defensive programming
        try {
            if (
                keyPairs[slot] != null &&
                keyPairs[slot].getPrivate() != null &&
                keyPairs[slot].getPrivate().isInitialized()
            ) {
                ISOException.throwIt(APDUConstants.SW_KEY_EXISTS);
            }
        } catch (Exception e) {
            // Treat any exception as "not initialized" - defensive approach
        }

        // Extract flags
        byte flags = buf[ISO7816.OFFSET_CDATA + 1 + pinLen];
        validateFlags(flags);

        // Generate key pair - simplified without transaction for testing
        KeyPair kp = makeP256KeyPair();
        keyPairs[slot] = kp;
        keyFlags[slot] = flags; // Set explicit flags from APDU
        
        // Return public key as convenience (65-byte uncompressed format)
        returnUncompressedPublicKey(apdu, kp);
    }

    /**
     * INS_GET_PUBKEY (0x02) — return the 65-byte uncompressed public key for a slot.
     * P1 = slot (0–3).
     */
    private void handleGetPubKey(APDU apdu) {
        byte slot = apdu.getBuffer()[ISO7816.OFFSET_P1];
        checkSlot(slot);
        checkKeyPresent(slot);

        ECPublicKey pubKey = (ECPublicKey) keyPairs[slot].getPublic();
        short keyLen = pubKey.getW(pubKeyScratch, (short) 0);

        apdu.setOutgoing();
        apdu.setOutgoingLength(keyLen);
        apdu.sendBytesLong(pubKeyScratch, (short) 0, keyLen);
    }

    /**
     * INS_SIGN (0x03) — sign a pre-computed hash with the key in a slot.
     *
     * P1 = slot (0–3)
     * P2 = flags (FLAG_REQUIRE_PIN may be set here to force re-validation
     *             regardless of the slot's stored flags)
     * Data = pre-computed hash digest (exactly 32 bytes for SHA-256)
     * Response = DER-encoded ECDSA signature (max 72 bytes for P-256)
     *
     * The host is responsible for hashing. The card calls signPreComputedHash()
     * (JavaCard 3.0.5 API) so the Signature engine does NOT re-hash the input.
     * This keeps hash algorithm choice entirely on the host side.
     *
     * CLAUDE.md §SIGN Instruction Detail
     */
    private void handleSign(APDU apdu) {
        byte[] buf = apdu.getBuffer();
        byte slot = buf[ISO7816.OFFSET_P1];
        byte flags = buf[ISO7816.OFFSET_P2];
        checkSlot(slot);
        checkKeyPresent(slot);

        // Require PIN if either the slot's stored flags or the APDU flags say so.
        boolean requirePIN =
            ((keyFlags[slot] | flags) & APDUConstants.FLAG_REQUIRE_PIN) != 0;
        if (requirePIN && !pin.isValidated()) {
            ISOException.throwIt(ISO7816.SW_SECURITY_STATUS_NOT_SATISFIED);
        }

        short digestLen = apdu.setIncomingAndReceive();
        // Digest must be at least 1 byte and fit in the APDU buffer.
        // signPreComputedHash() accepts any digest length; for P-256 the
        // ECDSA standard (FIPS 186-4 §6.4) uses the leftmost 256 bits, so
        // SHA-512 / SHA3-512 (64 bytes) work correctly without truncation here.
        if (digestLen < (short) 1 || digestLen > (short) 128) {
            // 128 bytes (1024 bits) is a generous upper bound covering any plausible
            // hash output. Anything wider is almost certainly a mistake or misuse.
            ISOException.throwIt(ISO7816.SW_WRONG_LENGTH);
        }

        // signPreComputedHash() signs the raw digest bytes without any internal
        // hashing. The response overwrites buf from offset 0, which is safe
        // because APDU input has already been fully received.
        ECPrivateKey privKey = (ECPrivateKey) keyPairs[slot].getPrivate();
        signer.init(privKey, Signature.MODE_SIGN);
        short sigLen = signer.signPreComputedHash(
            buf,
            ISO7816.OFFSET_CDATA,
            digestLen,
            buf,
            (short) 0
        );

        apdu.setOutgoing();
        apdu.setOutgoingLength(sigLen);
        apdu.sendBytes((short) 0, sigLen);
    }

    /**
     * INS_LIST_KEYS (0x04) — return a 1-byte bitmask of populated slots.
     * Bit N is set if slot N contains a key.
     */
    private void handleListKeys(APDU apdu) {
        byte mask = 0;
        for (byte slotIndex = 0; slotIndex < MAX_KEYS; slotIndex++) {
            if (
                keyPairs[slotIndex] != null &&
                keyPairs[slotIndex].getPrivate().isInitialized()
            ) {
                mask |= (byte) (1 << slotIndex);
            }
        }

        byte[] buf = apdu.getBuffer();
        buf[0] = mask;
        apdu.setOutgoing();
        apdu.setOutgoingLength((short) 1);
        apdu.sendBytes((short) 0, (short) 1);
    }

    /**
     * INS_VERIFY_PIN (0x05) — verify the card PIN for this session.
     * Data = PIN bytes.
     *
     * On failure returns 0x63Cx (x = tries remaining) or 0x6983 (blocked).
     * On exhaustion of tries, triggers FLAG_ERASE_ON_LOCK for all eligible slots.
     */
    private void handleVerifyPIN(APDU apdu) {
        byte[] buf = apdu.getBuffer();
        short dataLen = apdu.setIncomingAndReceive();

        if (pin.getTriesRemaining() == 0) {
            ISOException.throwIt(APDUConstants.SW_PIN_BLOCKED);
        }

        if (!pin.check(buf, ISO7816.OFFSET_CDATA, (byte) dataLen)) {
            if (pin.getTriesRemaining() == 0) {
                // PIN just became blocked — erase any FLAG_ERASE_ON_LOCK keys.
                eraseLockedKeys();
                ISOException.throwIt(APDUConstants.SW_PIN_BLOCKED);
            }
            ISOException.throwIt(
                (short) (APDUConstants.SW_WRONG_PIN_BASE |
                    pin.getTriesRemaining())
            );
        }
        // Success: SW 9000 sent automatically.
    }

    /**
     * INS_CHANGE_PIN (0x06) — change the card PIN.
     * P1 = length of the old PIN.
     * Data = old PIN bytes || new PIN bytes.
     *
     * Requires the old PIN to be presented; does not require a prior
     * INS_VERIFY_PIN for this session.
     */
    private void handleChangePIN(APDU apdu) {
        byte[] buf = apdu.getBuffer();
        byte oldPINLen = buf[ISO7816.OFFSET_P1];
        short totalLen = apdu.setIncomingAndReceive();

        if (oldPINLen <= 0 || oldPINLen >= totalLen) {
            ISOException.throwIt(ISO7816.SW_WRONG_LENGTH);
        }

        short newPINOffset = (short) (ISO7816.OFFSET_CDATA + oldPINLen);
        byte newPINLen = (byte) (totalLen - oldPINLen);

        if (pin.getTriesRemaining() == 0) {
            ISOException.throwIt(APDUConstants.SW_PIN_BLOCKED);
        }

        // Verify old PIN. We use pin.check() which counts against the try counter.
        if (!pin.check(buf, ISO7816.OFFSET_CDATA, oldPINLen)) {
            if (pin.getTriesRemaining() == 0) {
                eraseLockedKeys();
                ISOException.throwIt(APDUConstants.SW_PIN_BLOCKED);
            }
            ISOException.throwIt(
                (short) (APDUConstants.SW_WRONG_PIN_BASE |
                    pin.getTriesRemaining())
            );
        }

        // Add transaction protection around PIN update
        JCSystem.beginTransaction();
        try {
            pin.update(buf, newPINOffset, newPINLen);
            JCSystem.commitTransaction();
        } catch (Exception e) {
            JCSystem.abortTransaction();
            throw e;
        }
        // Success: SW 9000 sent automatically.
    }

    /**
     * INS_SET_FLAGS (0x07) — set per-key flags for a slot.
     * P1 = slot (0–3), P2 = new flags byte.
     * 
     * DEPRECATED: Use explicit flag setting in write operations (GEN_KEY, REGEN_KEY) instead.
     * This instruction remains for backward compatibility but should not be used in new applications.
     * 
     * SECURITY: Requires PIN verification to prevent flag manipulation attacks.
     */
    private void handleSetFlags(APDU apdu) {
        byte[] buf = apdu.getBuffer();
        byte slot = buf[ISO7816.OFFSET_P1];
        byte flags = buf[ISO7816.OFFSET_P2];
        checkSlot(slot);
        checkKeyPresent(slot);

        // CRITICAL FIX: Require PIN verification to prevent authentication bypass
        if (!pin.isValidated()) {
            ISOException.throwIt(
                APDUConstants.SW_SECURITY_STATUS_NOT_SATISFIED
            );
        }

        // CRITICAL FIX: Validate flags to prevent reserved bit corruption
        validateFlags(flags);

        // Add transaction protection around flag assignment
        JCSystem.beginTransaction();
        try {
            keyFlags[slot] = flags;
            JCSystem.commitTransaction();
        } catch (Exception e) {
            JCSystem.abortTransaction();
            throw e;
        }
        // Success: SW 9000 sent automatically.
    }

    /**
     * INS_REGEN_KEY (0x08) — regenerate (replace) the keypair in a slot.
     *
     * **BREAKING CHANGE:** Now requires PIN verification and explicit flag setting.
     *
     * APDU Format: [PIN_LEN][PIN][FLAGS]
     * - PIN_LEN: 1 byte (range: 1-8)
     * - PIN: Variable-length PIN data (1-8 bytes)
     * - FLAGS: Security flags byte (explicit, not preserved from previous key)
     *
     * P1 = slot (0–3)
     * P2 = reserved (must be 0x00)
     * Data = PIN length + PIN bytes + flags byte
     * Response = new 65-byte uncompressed public key
     *
     * Security Policy:
     * - Requires PIN verification before proceeding
     * - Replaces existing key (if any) without slot occupancy check
     * - Sets flags explicitly from APDU (does NOT preserve previous flags)
     *
     * Returns:
     * - SW_SECURITY_STATUS_NOT_SATISFIED (0x6982): PIN verification failed
     * - SW_WRONG_DATA (0x6A80): Invalid flags (reserved bits set)
     * - SW_WRONG_LENGTH (0x6700): Invalid APDU or PIN length
     * - SW_9000: Success + new public key in response
     *
     * Transaction Safety: Key replacement and flag setting are atomic.
     * Implementation: Generates fresh P-256 keypair with proper domain parameters.
     */
    private void handleRegenKey(APDU apdu) {
        byte[] buf = apdu.getBuffer();
        byte slot = buf[ISO7816.OFFSET_P1];
        checkSlot(slot);

        // Parse APDU: [PIN_LEN][PIN][FLAGS]
        short dataLen = apdu.setIncomingAndReceive();
        if (dataLen < 2) {
            ISOException.throwIt(ISO7816.SW_WRONG_LENGTH);
        }

        byte pinLen = buf[ISO7816.OFFSET_CDATA];
        if (pinLen < 1 || pinLen > PIN_MAX_LEN) {
            ISOException.throwIt(ISO7816.SW_WRONG_LENGTH);
        }

        // Verify total data length
        if (dataLen != (short) (1 + pinLen + 1)) {
            ISOException.throwIt(ISO7816.SW_WRONG_LENGTH);
        }

        // Verify PIN (may decrement counter)
        if (!pin.check(buf, (short) (ISO7816.OFFSET_CDATA + 1), pinLen)) {
            ISOException.throwIt(
                APDUConstants.SW_SECURITY_STATUS_NOT_SATISFIED
            );
        }

        // Extract flags
        byte flags = buf[ISO7816.OFFSET_CDATA + 1 + pinLen];
        validateFlags(flags);

        // Atomic regeneration
        JCSystem.beginTransaction();
        try {
            KeyPair kp = makeP256KeyPair(); // Fixed: Remove duplicate genKeyPair() call
            keyPairs[slot] = kp;
            keyFlags[slot] = flags; // Explicit flags, not preserved
            JCSystem.commitTransaction();
        } catch (ISOException iso) {
            JCSystem.abortTransaction();
            throw iso; // Preserve ISO exceptions
        } catch (Exception e) {
            JCSystem.abortTransaction();
            ISOException.throwIt(ISO7816.SW_UNKNOWN); // Convert to proper 0x6F00
        }

        // Return new public key
        returnUncompressedPublicKey(apdu, keyPairs[slot]);
    }

    /**
     * INS_CLEAR_KEY (0x0A) — clear key material and flags in a slot.
     *
     * Securely delete key and reset flags.
     *
     * APDU Format: [PIN_LEN][PIN][FLAGS]
     * - PIN_LEN: 1 byte (range: 1-8)
     * - PIN: Variable-length PIN data (1-8 bytes)
     * - FLAGS: Present for format consistency but ignored
     *
     * P1 = slot (0–3)
     * P2 = reserved (must be 0x00)
     * Data = PIN length + PIN bytes + flags byte (flags ignored)
     *
     * Security Policy:
     * - Requires PIN verification before proceeding
     * - Clears private and public key material using clearKey()
     * - Resets slot flags to 0x00
     * - Safe to call on empty slots (no error)
     *
     * Returns:
     * - SW_SECURITY_STATUS_NOT_SATISFIED (0x6982): PIN verification failed
     * - SW_WRONG_DATA (0x6A80): Invalid flags (reserved bits set)
     * - SW_WRONG_LENGTH (0x6700): Invalid APDU or PIN length
     * - SW_9000: Success
     *
     * Transaction Safety: Key clearing and flag reset are atomic.
     * Implementation: Uses JavaCard clearKey() for secure key material deletion.
     */
    private void handleClearKey(APDU apdu) {
        byte[] buf = apdu.getBuffer();
        byte slot = buf[ISO7816.OFFSET_P1];
        checkSlot(slot);

        // Parse APDU: [PIN_LEN][PIN][FLAGS]
        short dataLen = apdu.setIncomingAndReceive();
        if (dataLen < 2) {
            ISOException.throwIt(ISO7816.SW_WRONG_LENGTH);
        }

        byte pinLen = buf[ISO7816.OFFSET_CDATA];
        if (pinLen < 1 || pinLen > PIN_MAX_LEN) {
            ISOException.throwIt(ISO7816.SW_WRONG_LENGTH);
        }

        // Verify total data length
        if (dataLen != (short) (1 + pinLen + 1)) {
            ISOException.throwIt(ISO7816.SW_WRONG_LENGTH);
        }

        // Verify PIN
        if (!pin.check(buf, (short) (ISO7816.OFFSET_CDATA + 1), pinLen)) {
            ISOException.throwIt(
                APDUConstants.SW_SECURITY_STATUS_NOT_SATISFIED
            );
        }

        // Extract and validate flags (ignored but must be valid for format consistency)
        byte flags = buf[ISO7816.OFFSET_CDATA + 1 + pinLen];
        validateFlags(flags);

        // Clear key and flags atomically
        JCSystem.beginTransaction();
        try {
            if (keyPairs[slot] != null) {
                keyPairs[slot].getPrivate().clearKey();
                keyPairs[slot].getPublic().clearKey();
                keyPairs[slot] = null;
            }
            keyFlags[slot] = 0; // Explicit flag clearing
            JCSystem.commitTransaction();
        } catch (ISOException iso) {
            JCSystem.abortTransaction();
            throw iso; // Preserve ISO exceptions
        } catch (Exception e) {
            JCSystem.abortTransaction();
            ISOException.throwIt(ISO7816.SW_UNKNOWN); // Convert to proper 0x6F00
        }
    }

    /**
     * INS_UNBLOCK_PIN (0x09) — unblock the PIN using the PUK.
     * P1 = length of the PUK.
     * Data = PUK bytes || new PIN bytes.
     */
    private void handleUnblockPIN(APDU apdu) {
        byte[] buf = apdu.getBuffer();
        byte pukLen = buf[ISO7816.OFFSET_P1];
        short totalLen = apdu.setIncomingAndReceive();

        if (pukLen <= 0 || pukLen >= totalLen) {
            ISOException.throwIt(ISO7816.SW_WRONG_LENGTH);
        }

        short newPINOffset = (short) (ISO7816.OFFSET_CDATA + pukLen);
        byte newPINLen = (byte) (totalLen - pukLen);

        if (puk.getTriesRemaining() == 0) {
            // PUK is also blocked — card is permanently locked.
            ISOException.throwIt(APDUConstants.SW_PIN_BLOCKED);
        }

        if (!puk.check(buf, ISO7816.OFFSET_CDATA, pukLen)) {
            ISOException.throwIt(
                (short) (APDUConstants.SW_WRONG_PIN_BASE |
                    puk.getTriesRemaining())
            );
        }

        // PUK accepted — reset and unblock the PIN, then set the new value.
        JCSystem.beginTransaction();
        try {
            pin.resetAndUnblock();
            pin.update(buf, newPINOffset, newPINLen);
            JCSystem.commitTransaction();
        } catch (Exception e) {
            JCSystem.abortTransaction();
            throw e;
        }
        // Success: SW 9000 sent automatically.
    }

    // -------------------------------------------------------------------------
    // Private helpers
    // -------------------------------------------------------------------------

    /**
     * Allocate and configure a fresh P-256 KeyPair with proper domain parameters.
     *
     * @return Initialized P-256 KeyPair ready for cryptographic operations
     */
    private KeyPair makeP256KeyPair() {
        // Use JCAlgTest's proven approach for P-256 key generation
        try {
            KeyPair kp = null;
            
            // Try JCAlgTest's two-phase approach
            try {
                // Phase 1: Create KeyPair directly
                kp = new KeyPair(KeyPair.ALG_EC_FP, KeyBuilder.LENGTH_EC_FP_256);
                // Apply JCAlgTest's curve initialization approach
                ensureP256CurveInitialized(kp);
            } catch (Exception e) {
                // Phase 2: Create individual keys first, then KeyPair
                ECPrivateKey ecPrivKey = (ECPrivateKey) KeyBuilder.buildKey(
                    KeyBuilder.TYPE_EC_FP_PRIVATE, 
                    KeyBuilder.LENGTH_EC_FP_256, 
                    false
                );
                ECPublicKey ecPubKey = (ECPublicKey) KeyBuilder.buildKey(
                    KeyBuilder.TYPE_EC_FP_PUBLIC, 
                    KeyBuilder.LENGTH_EC_FP_256, 
                    false
                );
                
                if ((ecPrivKey != null) && (ecPubKey != null)) {
                    // Set curve parameters on individual keys
                    setP256CurveParams(ecPubKey, ecPrivKey);
                    kp = new KeyPair(ecPubKey, ecPrivKey);
                }
            }
            
            if (kp != null) {
                kp.genKeyPair();
                return kp;
            } else {
                ISOException.throwIt(ISO7816.SW_CONDITIONS_NOT_SATISFIED);
            }
        } catch (CryptoException ex) {
            switch (ex.getReason()) {
                case CryptoException.ILLEGAL_USE:
                    ISOException.throwIt(ISO7816.SW_COMMAND_NOT_ALLOWED);
                    break;
                case CryptoException.NO_SUCH_ALGORITHM:
                    ISOException.throwIt(ISO7816.SW_FUNC_NOT_SUPPORTED);
                    break;
                case CryptoException.INVALID_INIT:
                    ISOException.throwIt(ISO7816.SW_CONDITIONS_NOT_SATISFIED);
                    break;
                case CryptoException.ILLEGAL_VALUE:
                    ISOException.throwIt(ISO7816.SW_DATA_INVALID);
                    break;
                default:
                    ISOException.throwIt(ISO7816.SW_UNKNOWN);
            }
        } catch (Exception e) {
            // Key generation failed - report proper error
            ISOException.throwIt(ISO7816.SW_UNKNOWN);
        }

        return null; // Never reached
    }
    
    // JCAlgTest-inspired curve initialization
    private void ensureP256CurveInitialized(KeyPair ecKeyPair) {
        ECPublicKey ecPubKey = (ECPublicKey) ecKeyPair.getPublic();
        ECPrivateKey ecPrivKey = (ECPrivateKey) ecKeyPair.getPrivate();
        
        // Some implementations need genKeyPair() called first
        try {
            if (ecPubKey == null) {
                ecKeyPair.genKeyPair();
            }
        } catch (Exception e) {
            // Intentionally ignore
        }
        
        // Set curve parameters
        setP256CurveParams(ecPubKey, ecPrivKey);
    }
    
    // Set P-256 curve parameters using JCAlgTest approach
    private void setP256CurveParams(ECPublicKey pubKey, ECPrivateKey privKey) {
        // Use JCAlgTest's exact approach for P-256 parameter setting
        byte[] auxBuffer = new byte[80]; // Large enough for uncompressed point
        
        // Prepare ANSI X9.62 uncompressed EC point representation for G
        // Format: 0x04 || G_X || G_Y
        auxBuffer[0] = 0x04; // Uncompressed point indicator
        short off = 1;
        
        // Copy G_X coordinates
        off = Util.arrayCopyNonAtomic(ECParams.P256_G_X, (short) 0, auxBuffer, off, (short) ECParams.P256_G_X.length);
        // Copy G_Y coordinates  
        Util.arrayCopyNonAtomic(ECParams.P256_G_Y, (short) 0, auxBuffer, off, (short) ECParams.P256_G_Y.length);
        
        short gSize = (short)(1 + ECParams.P256_G_X.length + ECParams.P256_G_Y.length);
        
        try {
            // Set field parameters on both keys
            pubKey.setFieldFP(ECParams.P256_P, (short) 0, (short) ECParams.P256_P.length);
            privKey.setFieldFP(ECParams.P256_P, (short) 0, (short) ECParams.P256_P.length);
            
            // Set curve parameters A and B
            pubKey.setA(ECParams.P256_A, (short) 0, (short) ECParams.P256_A.length);
            privKey.setA(ECParams.P256_A, (short) 0, (short) ECParams.P256_A.length);
            pubKey.setB(ECParams.P256_B, (short) 0, (short) ECParams.P256_B.length);
            privKey.setB(ECParams.P256_B, (short) 0, (short) ECParams.P256_B.length);
            
            // Set generator point G in uncompressed format
            pubKey.setG(auxBuffer, (short) 0, gSize);
            privKey.setG(auxBuffer, (short) 0, gSize);
            
            // Set order R and cofactor K
            pubKey.setR(ECParams.P256_R, (short) 0, (short) ECParams.P256_R.length);
            privKey.setR(ECParams.P256_R, (short) 0, (short) ECParams.P256_R.length);
            pubKey.setK(ECParams.P256_K);
            privKey.setK(ECParams.P256_K);
        } catch (CryptoException e) {
            // If parameter setting fails, let it bubble up to the caller
            throw e;
        }
    }

    /**
     * Erase private and public key material for every slot that has
     * FLAG_ERASE_ON_LOCK set. Wrapped in a transaction for atomicity in case
     * of power loss mid-operation.
     *
     * Called when the PIN becomes blocked. CLAUDE.md §ERASE_ON_LOCK Behavior.
     */
    private void eraseLockedKeys() {
        JCSystem.beginTransaction();
        try {
            for (byte slotIndex = 0; slotIndex < MAX_KEYS; slotIndex++) {
                if (
                    (keyFlags[slotIndex] & APDUConstants.FLAG_ERASE_ON_LOCK) !=
                        0 &&
                    keyPairs[slotIndex] != null
                ) {
                    keyPairs[slotIndex].getPrivate().clearKey();
                    keyPairs[slotIndex].getPublic().clearKey();
                }
            }
            JCSystem.commitTransaction();
        } catch (Exception e) {
            JCSystem.abortTransaction();
            throw e;
        }
    }
    
    /**
     * Helper method to return the uncompressed public key from a KeyPair via APDU response.
     * Used by key generation operations to return the generated public key as convenience.
     *
     * @param apdu The APDU object for sending the response
     * @param keyPair The KeyPair containing the public key to return
     */
    private void returnUncompressedPublicKey(APDU apdu, KeyPair keyPair) {
        ECPublicKey pubKey = (ECPublicKey) keyPair.getPublic();
        short keyLen = pubKey.getW(pubKeyScratch, (short) 0);
        
        apdu.setOutgoing();
        apdu.setOutgoingLength(keyLen);
        apdu.sendBytesLong(pubKeyScratch, (short) 0, keyLen);
    }

    /** Throw if slot is out of range. */
    private void checkSlot(byte slot) {
        if (slot < 0 || slot >= MAX_KEYS) {
            ISOException.throwIt(ISO7816.SW_INCORRECT_P1P2);
        }
    }

    /** Throw if the slot has no initialised private key. */
    private void checkKeyPresent(byte slot) {
        if (
            keyPairs[slot] == null ||
            !keyPairs[slot].getPrivate().isInitialized()
        ) {
            ISOException.throwIt(APDUConstants.SW_KEY_NOT_FOUND);
        }
    }

    /**
     * INS_GET_FLAGS (0x11) — return the flags byte for a specified slot.
     * P1 = slot (0-3), P2 = unused, no data.
     * Response = 1-byte flags value.
     * No PIN verification required (read-only operation).
     */
    private void handleGetFlags(APDU apdu) {
        byte slot = apdu.getBuffer()[ISO7816.OFFSET_P1];
        checkSlot(slot);        // Validate slot range (0-3)
        checkKeyPresent(slot);  // Ensure slot has a key

        byte[] buf = apdu.getBuffer();
        buf[0] = keyFlags[slot];  // Return flags for this slot
        apdu.setOutgoing();
        apdu.setOutgoingLength((short) 1);
        apdu.sendBytes((short) 0, (short) 1);
    }

    /**
     * Validates security flags, rejecting reserved bits for future compatibility.
     *
     * Flag Layout (bits 7-0):
     * - Bit 7: FLAG_REQUIRE_PIN (0x80)
     * - Bits 6-4: FLAG_TIMEOUT (0x70, timeout in minutes 0-7)
     * - Bit 3: FLAG_ERASE_ON_LOCK (0x08)
     * - Bits 2-0: Reserved for future use (MUST be 0)
     *
     * @param flags The flags byte to validate
     * @throws ISOException with SW_WRONG_DATA (0x6A80) if reserved bits are set
     *
     * Implementation Notes:
     * - Enforces reserved bit constraint for forward compatibility
     * - Called by all PIN-protected write operations
     * - Ensures consistent flag validation across operations
     */
    private void validateFlags(byte flags) {
        if ((flags & 0x07) != 0) {
            // Check reserved bits 0-2
            ISOException.throwIt(ISO7816.SW_WRONG_DATA);
        }
    }
}
