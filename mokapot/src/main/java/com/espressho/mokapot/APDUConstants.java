package com.espressho.mokapot;

/**
 * APDUConstants — all instruction bytes, flag masks, and status words for the
 * Mokapot SSH-key applet.
 *
 * Keep every magic number here so the rest of the applet stays readable.
 */
public final class APDUConstants {

    private APDUConstants() {}

    // -------------------------------------------------------------------------
    // Instruction bytes (INS field of the APDU header)
    // -------------------------------------------------------------------------

    // === PIN-PROTECTED WRITE OPERATIONS ===
    // The following operations use a unified APDU format for consistency:
    // INS_GEN_KEY (0x01), INS_REGEN_KEY (0x08), INS_CLEAR_KEY (0x0A)
    //
    // APDU Format:
    // CLA INS P1  P2  Lc  Data
    // 00  XX  slot 00  N   [PIN_LEN][PIN][FLAGS]
    //
    // Where:
    // - CLA: 0x00 (standard ISO command class)
    // - INS: Operation instruction (0x01, 0x08, or 0x0A)
    // - P1: Key slot number (0-3)
    // - P2: Reserved, must be 0x00
    // - Lc: Length of data field (PIN_LEN + PIN length + 1 for FLAGS)
    // - PIN_LEN: PIN length (1 byte, valid range 1-8)
    // - PIN: Variable-length PIN data (1-8 bytes)
    // - FLAGS: Security flags byte (see FLAG_* constants below)
    //
    // Size Constraints:
    // - Minimum APDU: CLA+INS+P1+P2+Lc+PIN_LEN+PIN(1)+FLAGS = 8 bytes
    // - Maximum APDU: CLA+INS+P1+P2+Lc+PIN_LEN+PIN(8)+FLAGS = 15 bytes
    // - PIN length range: 1-8 bytes (enforced by PIN_LEN validation)
    //
    // Example APDU for GEN_KEY with 4-byte PIN "1234" and flags 0x80:
    // 00 01 00 00 06 04 31 32 33 34 80
    //    ^^ ^^ ^^ ^^ ^^ ^^  PIN data  ^^
    //    |  |  |  |  |  |             FLAGS
    //    |  |  |  |  |  PIN_LEN (4)
    //    |  |  |  |  Lc = 4 + 1 + 1 = 6
    //    |  |  |  P2 (reserved)
    //    |  |  P1 (slot 0)
    //    |  INS_GEN_KEY
    //    CLA
    //
    // Common Parsing Pattern for PIN-protected Operations:
    // ```java
    // byte slot = apdu.getBuffer()[ISO7816.OFFSET_P1];
    // short dataLen = apdu.setIncomingAndReceive();
    // byte[] buffer = apdu.getBuffer();
    // byte pinLen = buffer[ISO7816.OFFSET_CDATA];
    // 
    // // Validate PIN length
    // if (pinLen < 1 || pinLen > 8) {
    //     ISOException.throwIt(ISO7816.SW_WRONG_LENGTH);
    // }
    //
    // // Validate total data length
    // if (dataLen != (short)(1 + pinLen + 1)) {
    //     ISOException.throwIt(ISO7816.SW_WRONG_LENGTH);
    // }
    //
    // // Extract PIN (copy for safety)
    // byte[] pin = new byte[pinLen];
    // Util.arrayCopy(buffer, (short)(ISO7816.OFFSET_CDATA + 1), pin, (short)0, pinLen);
    //
    // // Extract flags
    // byte flags = buffer[ISO7816.OFFSET_CDATA + 1 + pinLen];
    // ```
    //
    // Error Responses:
    // - SW_SECURITY_STATUS_NOT_SATISFIED (0x6982): PIN verification failed
    // - SW_KEY_EXISTS (0x6985): Key slot occupied (GEN_KEY only)
    // - SW_KEY_NOT_FOUND (0x6A82): Key slot empty (CLEAR_KEY/REGEN_KEY only)
    // - SW_WRONG_LENGTH (0x6700): Invalid APDU or PIN length
    // - SW_SUCCESS (0x9000): Operation completed successfully

    /**
     * Generate a new EC P-256 keypair in a slot.
     * BREAKING CHANGE: Now requires PIN verification.
     * Uses unified PIN-protected APDU format (see above).
     */
    public static final byte INS_GEN_KEY = (byte) 0x01;

    /** Return the raw 65-byte uncompressed public key for a slot. P1 = slot. */
    public static final byte INS_GET_PUBKEY = (byte) 0x02;

    /**
     * Sign a pre-computed digest with the key in a slot.
     * P1 = slot, P2 = flags (see FLAG_* below), Data = 32-byte digest.
     * Response = DER-encoded ECDSA signature.
     *
     * The host computes the hash (e.g. SHA-256) before sending. The card calls
     * Signature.signPreComputedHash() so no re-hashing occurs on-card. This
     * keeps hash algorithm selection entirely on the host side.
     */
    public static final byte INS_SIGN = (byte) 0x03;

    /** Return a 1-byte bitmask of populated slots (bit N set → slot N has a key). */
    public static final byte INS_LIST_KEYS = (byte) 0x04;

    /** Verify the card PIN. Data = PIN bytes. */
    public static final byte INS_VERIFY_PIN = (byte) 0x05;

    /**
     * Change the card PIN.
     * P1 = length of the old PIN.
     * Data = old PIN bytes || new PIN bytes.
     */
    public static final byte INS_CHANGE_PIN = (byte) 0x06;

    /** 
     * Set per-key flags for a slot. P1 = slot, P2 = new flags byte.
     * DEPRECATED: Use explicit flag setting in write operations instead.
     */
    public static final byte INS_SET_FLAGS = (byte) 0x07;

    /**
     * Regenerate the keypair in a slot (replaces any existing key).
     * BREAKING CHANGE: Now requires PIN verification.
     * Uses unified PIN-protected APDU format (see above).
     */
    public static final byte INS_REGEN_KEY = (byte) 0x08;

    /**
     * Unblock a blocked PIN using the PUK.
     * P1 = length of the PUK.
     * Data = PUK bytes || new PIN bytes.
     */
    public static final byte INS_UNBLOCK_PIN = (byte) 0x09;

    /**
     * Clear (delete) a key from a slot.
     * Uses unified PIN-protected APDU format.
     * P1 = slot (0-3), Data = [PIN_LEN][PIN][FLAGS]
     */
    public static final byte INS_CLEAR_KEY = (byte) 0x0A;

    /**
     * Get the flags byte for a specified slot.
     * P1 = slot (0-3), P2 = unused, no data.
     * Response = 1-byte flags value.
     */
    public static final byte INS_GET_FLAGS = (byte) 0x11;

    // -------------------------------------------------------------------------
    // Per-key flag bits  (stored in keyFlags[], also used in P2 of INS_SIGN)
    //
    //  7       6  5  4    3        2  1  0
    // ┌───────┬──────────┬─────────┬──────┐
    // │ REQ   │ TIMEOUT  │ ERASE   │ RES  │
    // │ PIN   │ (0–7)    │ ON LOCK │      │
    // └───────┴──────────┴─────────┴──────┘
    // -------------------------------------------------------------------------

    /** Bit 7: require PIN validation before signing with this key. */
    public static final byte FLAG_REQUIRE_PIN = (byte) 0x80;

    /** Bits 6–4: PIN timeout in minutes (0 = session-scoped). */
    public static final byte FLAG_TIMEOUT_MASK = (byte) 0x70;

    /** Right-shift to extract the 3-bit timeout value from the flags byte. */
    public static final byte FLAG_TIMEOUT_SHIFT = (byte) 4;

    /** Bit 3: erase this key's material when the PIN becomes blocked. */
    public static final byte FLAG_ERASE_ON_LOCK = (byte) 0x08;

    // -------------------------------------------------------------------------
    // Status words (SW1 SW2)
    // -------------------------------------------------------------------------

    /** 0x9000 — command completed successfully. */
    public static final short SW_SUCCESS = (short) 0x9000;

    /** 0x6983 — PIN blocked; PUK required to unblock. */
    public static final short SW_PIN_BLOCKED = (short) 0x6983;

    /**
     * 0x63Cx — wrong PIN; the low nibble x carries the remaining try count.
     * Construct with: (short)(SW_WRONG_PIN_BASE | triesRemaining)
     */
    public static final short SW_WRONG_PIN_BASE = (short) 0x63C0;

    /** 0x6A82 — referenced key slot is empty. */
    public static final short SW_KEY_NOT_FOUND = (short) 0x6A82;

    /** 0x6982 — security status not satisfied (PIN required/verification failed). */
    public static final short SW_SECURITY_STATUS_NOT_SATISFIED = (short) 0x6982;

    /** 0x6985 — conditions of use not satisfied (e.g., key slot already occupied). */
    public static final short SW_KEY_EXISTS = (short) 0x6985;
}
