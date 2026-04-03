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

    /** Generate a new EC P-256 keypair in a slot. P1 = slot (0–3). */
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

    /** Set per-key flags for a slot. P1 = slot, P2 = new flags byte. */
    public static final byte INS_SET_FLAGS = (byte) 0x07;

    /**
     * Regenerate the keypair in a slot (replaces any existing key).
     * P1 = slot. Response = new 65-byte public key.
     */
    public static final byte INS_REGEN_KEY = (byte) 0x08;

    /**
     * Unblock a blocked PIN using the PUK.
     * P1 = length of the PUK.
     * Data = PUK bytes || new PIN bytes.
     */
    public static final byte INS_UNBLOCK_PIN = (byte) 0x09;

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
}
