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
 * AID:
 *   Package : F0 00 00 00 00 01        (6 bytes)
 *   Applet  : F0 00 00 00 00 01 00     (7 bytes)
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
     * ALG_ECDSA_SHA_256: the card computes SHA-256 internally and then applies
     * ECDSA. The host sends the raw message; hashing happens on-card.
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
            default:
                ISOException.throwIt(ISO7816.SW_INS_NOT_SUPPORTED);
        }
    }

    // -------------------------------------------------------------------------
    // Instruction handlers
    // -------------------------------------------------------------------------

    /**
     * INS_GEN_KEY (0x01) — generate a new keypair in the specified slot.
     * P1 = slot (0–3). Any existing key in that slot is replaced.
     */
    private void handleGenKey(APDU apdu) {
        byte slot = apdu.getBuffer()[ISO7816.OFFSET_P1];
        checkSlot(slot);

        KeyPair kp = makeP256KeyPair();
        kp.genKeyPair();
        keyPairs[slot] = kp;
        keyFlags[slot] = 0;
        // SW 9000 is sent automatically by the JCRE when the method returns.
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

        pin.update(buf, newPINOffset, newPINLen);
        // Success: SW 9000 sent automatically.
    }

    /**
     * INS_SET_FLAGS (0x07) — set per-key flags for a slot.
     * P1 = slot (0–3), P2 = new flags byte.
     */
    private void handleSetFlags(APDU apdu) {
        byte[] buf = apdu.getBuffer();
        byte slot = buf[ISO7816.OFFSET_P1];
        byte flags = buf[ISO7816.OFFSET_P2];
        checkSlot(slot);
        checkKeyPresent(slot);
        keyFlags[slot] = flags;
        // Success: SW 9000 sent automatically.
    }

    /**
     * INS_REGEN_KEY (0x08) — regenerate (replace) the keypair in a slot.
     * P1 = slot (0–3).
     * Response = new 65-byte uncompressed public key.
     */
    private void handleRegenKey(APDU apdu) {
        byte slot = apdu.getBuffer()[ISO7816.OFFSET_P1];
        checkSlot(slot);

        KeyPair kp = makeP256KeyPair();
        kp.genKeyPair();
        keyPairs[slot] = kp;
        // Retain existing flags so regeneration doesn't change policy.

        ECPublicKey pubKey = (ECPublicKey) kp.getPublic();
        short keyLen = pubKey.getW(pubKeyScratch, (short) 0);

        apdu.setOutgoing();
        apdu.setOutgoingLength(keyLen);
        apdu.sendBytesLong(pubKeyScratch, (short) 0, keyLen);
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
        pin.resetAndUnblock();
        pin.update(buf, newPINOffset, newPINLen);
        // Success: SW 9000 sent automatically.
    }

    // -------------------------------------------------------------------------
    // Private helpers
    // -------------------------------------------------------------------------

    /** Allocate and configure a fresh P-256 KeyPair with domain parameters. */
    private KeyPair makeP256KeyPair() {
        KeyPair kp = new KeyPair(
            KeyPair.ALG_EC_FP,
            KeyBuilder.LENGTH_EC_FP_256
        );
        ECParams.setP256Params((ECPublicKey) kp.getPublic());
        ECParams.setP256Params((ECPrivateKey) kp.getPrivate());
        return kp;
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
        for (byte slotIndex = 0; slotIndex < MAX_KEYS; slotIndex++) {
            if (
                (keyFlags[slotIndex] & APDUConstants.FLAG_ERASE_ON_LOCK) != 0 &&
                keyPairs[slotIndex] != null
            ) {
                keyPairs[slotIndex].getPrivate().clearKey();
                keyPairs[slotIndex].getPublic().clearKey();
            }
        }
        JCSystem.commitTransaction();
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
}
