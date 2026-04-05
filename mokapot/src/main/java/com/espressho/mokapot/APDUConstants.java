package com.espressho.mokapot;

/**
 * APDUConstants — all instruction bytes, flag masks, and status words for the
 * Mokapot SSH-key applet.
 *
 * Keep every magic number here so the rest of the applet stays readable.
 *
 * ## Instruction layout
 *
 * ### Low side (0x01–0x08): normal card operations
 *
 * These instructions are gated behind card initialization and require PIN
 * verification where noted.  The unified PIN-protected format used by write
 * operations is:
 *
 * ```
 * CLA INS P1   P2  Lc  Data
 * 00  XX  slot 00  N   [PIN_LEN][PIN][FLAGS]
 * ```
 *
 * - PIN_LEN : 1 byte (valid range 1–8)
 * - PIN     : variable-length PIN (1–8 bytes)
 * - FLAGS   : security flags byte (see FLAG_* constants)
 * - Minimum data field : PIN_LEN + PIN(1) + FLAGS = 3 bytes
 * - Maximum data field : PIN_LEN + PIN(8) + FLAGS = 10 bytes
 *
 * ### Admin block (0x7F–0x7B, counting downward): card lifecycle management
 *
 * These instructions occupy the top of the sub-128 INS space, counting down
 * from 0x7F.  This makes them easy to spot in traces and keeps them clearly
 * separated from normal operations.
 *
 * 0x70 is the hard floor: ISO 7816-4 MANAGE CHANNEL, intercepted by the JCRE
 * before process() is called.  Reaching 0x70 would mean we have added more
 * than 15 admin instructions — a signal to rethink the design.
 *
 * INS_CARD_INIT (0x7F) is the *only* instruction permitted on an
 * uninitialized card (besides SELECT).  All others require the card to have
 * been initialized first.
 */
public final class APDUConstants {

    private APDUConstants() {}

    // =========================================================================
    // Low-side instructions (0x01–0x08)
    // =========================================================================

    /**
     * Generate a new EC P-256 keypair in a slot.
     * P1 = slot (0–3).
     * Data = [PIN_LEN][PIN][FLAGS] — unified PIN-protected format.
     * Response = 65-byte uncompressed public key.
     * Fails with SW_KEY_EXISTS (0x6985) if the slot is already occupied;
     * use INS_REGEN_KEY to replace an existing key.
     */
    public static final byte INS_GEN_KEY = (byte) 0x01;

    /**
     * Return the raw 65-byte uncompressed public key for a slot.
     * P1 = slot (0–3).  No PIN required.
     */
    public static final byte INS_GET_PUBKEY = (byte) 0x02;

    /**
     * Sign a pre-computed digest with the key in a slot.
     * P1 = slot (0–3), P2 = flags (FLAG_REQUIRE_PIN forces re-validation).
     * Data = pre-computed hash digest (1–128 bytes; typically 32 for SHA-256).
     * Response = DER-encoded ECDSA signature (max 72 bytes for P-256).
     *
     * The host computes the hash before sending; the card calls
     * signPreComputedHash() and does NOT re-hash the input.
     */
    public static final byte INS_SIGN = (byte) 0x03;

    /**
     * Return a 1-byte bitmask of populated slots (bit N set → slot N has a key).
     * No PIN required.
     */
    public static final byte INS_LIST_KEYS = (byte) 0x04;

    /**
     * Verify the card PIN for this session.
     * Data = PIN bytes.
     * On exhaustion triggers FLAG_ERASE_ON_LOCK for all eligible slots.
     */
    public static final byte INS_VERIFY_PIN = (byte) 0x05;

    /**
     * Regenerate (replace) the keypair in a slot.
     * P1 = slot (0–3).
     * Data = [PIN_LEN][PIN][FLAGS] — unified PIN-protected format.
     * Response = new 65-byte uncompressed public key.
     * Does NOT check slot occupancy — use this to replace existing keys.
     * Flags are set explicitly from the APDU; previous flags are NOT preserved.
     */
    public static final byte INS_REGEN_KEY = (byte) 0x06;

    /**
     * Clear (delete) a key from a slot.
     * P1 = slot (0–3).
     * Data = [PIN_LEN][PIN][FLAGS] — unified format; FLAGS field is ignored.
     * Safe to call on an empty slot (no-op).
     */
    public static final byte INS_CLEAR_KEY = (byte) 0x07;

    /**
     * Return the flags byte for a slot.
     * P1 = slot (0–3).  No PIN required (read-only).
     * Response = 1-byte flags value.
     */
    public static final byte INS_GET_FLAGS = (byte) 0x08;

    // =========================================================================
    // Admin block (0x7F downward): card lifecycle
    // =========================================================================

    /**
     * One-time card initialization — sets the PIN and PUK.
     *
     * This is the ONLY instruction that works on an uninitialized card
     * (besides SELECT).  Calling it again after initialization returns
     * SW_SECURITY_STATUS_NOT_SATISFIED.
     *
     * APDU format:
     * ```
     * CLA INS P1       P2       Lc         Data
     * 00  7F  PIN_LEN  PUK_LEN  PIN+PUK    [PIN bytes] || [PUK bytes]
     * ```
     * - P1: PIN length in bytes (1–8)
     * - P2: PUK length in bytes (1–8)
     * - Lc: P1 + P2
     * - Data: PIN bytes immediately followed by PUK bytes
     *
     * Example — PIN "1234" (4 bytes), PUK "87654321" (8 bytes):
     * ```
     * 00 7F 04 08 0C 31 32 33 34 38 37 36 35 34 33 32 31
     * ```
     */
    public static final byte INS_CARD_INIT = (byte) 0x7F;

    /**
     * Change the card PIN.
     *
     * P1 = old PIN length in bytes.
     * Data = [old PIN bytes] || [new PIN bytes].
     * Requires the current PIN; does not require a prior INS_VERIFY_PIN.
     */
    public static final byte INS_SET_PIN = (byte) 0x7E;

    /**
     * Change the card PUK.
     *
     * P1 = old PUK length in bytes.
     * Data = [old PUK bytes] || [new PUK bytes].
     * Requires the current PUK.
     */
    public static final byte INS_SET_PUK = (byte) 0x7D;

    /**
     * Unblock a blocked PIN using the PUK and set a new PIN.
     *
     * P1 = PUK length in bytes.
     * Data = [PUK bytes] || [new PIN bytes].
     * On success the PIN try counter is reset and the new PIN is active.
     * If the PUK is permanently blocked (tries exhausted) this returns
     * SW_PIN_BLOCKED; the only recovery is INS_RESET_CARD.
     */
    public static final byte INS_UNBLOCK_CARD = (byte) 0x7C;

    /**
     * Factory reset — wipe all keys and credentials, return card to fresh
     * installed state (initialized = false).
     *
     * This is the "I forgot everything, blow it all away" escape hatch.
     * No PIN or PUK is required, making it usable even when locked out.
     * To prevent accidental resets the operation is two-phase:
     *
     * **Phase 1** — no data (Lc absent or 0):
     *   Card generates a 16-byte cryptographic nonce, stores it in transient
     *   memory (CLEAR_ON_DESELECT), and returns it.  If you deselect before
     *   completing Phase 2 the nonce is gone and you must restart.
     *
     * **Phase 2** — Data = the 16-byte nonce returned by Phase 1:
     *   Card verifies the nonce.  On match it atomically erases all key
     *   material, resets PIN/PUK counters, and sets initialized = false.
     *   On mismatch the nonce is immediately invalidated and
     *   SW_SECURITY_STATUS_NOT_SATISFIED is returned.
     *
     * After a successful reset INS_CARD_INIT must be called before any
     * other operation.
     */
    public static final byte INS_RESET_CARD = (byte) 0x7B;

    // =========================================================================
    // Per-key flag bits  (stored in keyFlags[], also used in P2 of INS_SIGN)
    //
    //  7       6  5  4    3        2  1  0
    // ┌───────┬──────────┬─────────┬──────┐
    // │ REQ   │ TIMEOUT  │ ERASE   │ RES  │
    // │ PIN   │ (0–7)    │ ON LOCK │      │
    // └───────┴──────────┴─────────┴──────┘
    // =========================================================================

    /** Bit 7: require PIN validation before signing with this key. */
    public static final byte FLAG_REQUIRE_PIN = (byte) 0x80;

    /** Bits 6–4: PIN timeout in minutes (0 = session-scoped). */
    public static final byte FLAG_TIMEOUT_MASK = (byte) 0x70;

    /** Right-shift to extract the 3-bit timeout value from the flags byte. */
    public static final byte FLAG_TIMEOUT_SHIFT = (byte) 4;

    /** Bit 3: erase this key's material when the PIN becomes blocked. */
    public static final byte FLAG_ERASE_ON_LOCK = (byte) 0x08;

    // =========================================================================
    // Status words (SW1 SW2)
    // =========================================================================

    /** 0x9000 — command completed successfully. */
    public static final short SW_SUCCESS = (short) 0x9000;

    /** 0x6983 — PIN blocked; PUK required to unblock, or use RESET_CARD. */
    public static final short SW_PIN_BLOCKED = (short) 0x6983;

    /**
     * 0x63Cx — wrong PIN/PUK; low nibble x carries the remaining try count.
     * Construct with: (short)(SW_WRONG_PIN_BASE | triesRemaining)
     */
    public static final short SW_WRONG_PIN_BASE = (short) 0x63C0;

    /** 0x6A82 — referenced key slot is empty. */
    public static final short SW_KEY_NOT_FOUND = (short) 0x6A82;

    /**
     * 0x6982 — security status not satisfied.
     * Used for: PIN required/failed, calling an instruction on an
     * uninitialized card, calling INS_CARD_INIT on an already-initialized
     * card, and wrong nonce in INS_RESET_CARD Phase 2.
     */
    public static final short SW_SECURITY_STATUS_NOT_SATISFIED = (short) 0x6982;

    /** 0x6985 — conditions not satisfied (e.g., key slot already occupied). */
    public static final short SW_KEY_EXISTS = (short) 0x6985;
}
