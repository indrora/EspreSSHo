package com.espressho.mokapot;

import javacard.security.ECKey;
import javacard.security.ECPrivateKey;
import javacard.security.ECPublicKey;

/**
 * ECParams — NIST P-256 (secp256r1) curve parameter constants.
 *
 * All values are taken verbatim from NIST SP 800-186 / SEC 2 §2.4.2.
 * Call setP256Params() on any freshly-created ECKey before use.
 *
 * These are declared as static final byte arrays so they live in ROM on
 * a typical JavaCard platform and are never allocated in EEPROM.
 */
public final class ECParams {

    private ECParams() {}

    // -------------------------------------------------------------------------
    // Field prime p
    // p = 2^256 − 2^224 + 2^192 + 2^96 − 1
    // -------------------------------------------------------------------------
    private static final byte[] FP = {
        (byte) 0xFF,
        (byte) 0xFF,
        (byte) 0xFF,
        (byte) 0xFF,
        (byte) 0x00,
        (byte) 0x00,
        (byte) 0x00,
        (byte) 0x01,
        (byte) 0x00,
        (byte) 0x00,
        (byte) 0x00,
        (byte) 0x00,
        (byte) 0x00,
        (byte) 0x00,
        (byte) 0x00,
        (byte) 0x00,
        (byte) 0x00,
        (byte) 0x00,
        (byte) 0x00,
        (byte) 0x00,
        (byte) 0xFF,
        (byte) 0xFF,
        (byte) 0xFF,
        (byte) 0xFF,
        (byte) 0xFF,
        (byte) 0xFF,
        (byte) 0xFF,
        (byte) 0xFF,
        (byte) 0xFF,
        (byte) 0xFF,
        (byte) 0xFF,
        (byte) 0xFF,
    };

    // -------------------------------------------------------------------------
    // Curve coefficient a = p − 3
    // -------------------------------------------------------------------------
    private static final byte[] A = {
        (byte) 0xFF,
        (byte) 0xFF,
        (byte) 0xFF,
        (byte) 0xFF,
        (byte) 0x00,
        (byte) 0x00,
        (byte) 0x00,
        (byte) 0x01,
        (byte) 0x00,
        (byte) 0x00,
        (byte) 0x00,
        (byte) 0x00,
        (byte) 0x00,
        (byte) 0x00,
        (byte) 0x00,
        (byte) 0x00,
        (byte) 0x00,
        (byte) 0x00,
        (byte) 0x00,
        (byte) 0x00,
        (byte) 0xFF,
        (byte) 0xFF,
        (byte) 0xFF,
        (byte) 0xFF,
        (byte) 0xFF,
        (byte) 0xFF,
        (byte) 0xFF,
        (byte) 0xFF,
        (byte) 0xFF,
        (byte) 0xFF,
        (byte) 0xFF,
        (byte) 0xFC,
    };

    // -------------------------------------------------------------------------
    // Curve coefficient b
    // -------------------------------------------------------------------------
    private static final byte[] B = {
        (byte) 0x5A,
        (byte) 0xC6,
        (byte) 0x35,
        (byte) 0xD8,
        (byte) 0xAA,
        (byte) 0x3A,
        (byte) 0x93,
        (byte) 0xE7,
        (byte) 0xB3,
        (byte) 0xEB,
        (byte) 0xBD,
        (byte) 0x55,
        (byte) 0x76,
        (byte) 0x98,
        (byte) 0x86,
        (byte) 0xBC,
        (byte) 0x65,
        (byte) 0x1D,
        (byte) 0x06,
        (byte) 0xB0,
        (byte) 0xCC,
        (byte) 0x53,
        (byte) 0xB0,
        (byte) 0xF6,
        (byte) 0x3B,
        (byte) 0xCE,
        (byte) 0x3C,
        (byte) 0x3E,
        (byte) 0x27,
        (byte) 0xD2,
        (byte) 0x60,
        (byte) 0x4B,
    };

    // -------------------------------------------------------------------------
    // Base point G (uncompressed, 04 || Gx || Gy)
    // -------------------------------------------------------------------------
    private static final byte[] G = {
        (byte) 0x04,
        // Gx
        (byte) 0x6B,
        (byte) 0x17,
        (byte) 0xD1,
        (byte) 0xF2,
        (byte) 0xE1,
        (byte) 0x2C,
        (byte) 0x42,
        (byte) 0x47,
        (byte) 0xF8,
        (byte) 0xBC,
        (byte) 0xE6,
        (byte) 0xE5,
        (byte) 0x63,
        (byte) 0xA4,
        (byte) 0x40,
        (byte) 0xF2,
        (byte) 0x77,
        (byte) 0x03,
        (byte) 0x7D,
        (byte) 0x81,
        (byte) 0x2D,
        (byte) 0xEB,
        (byte) 0x33,
        (byte) 0xA0,
        (byte) 0xF4,
        (byte) 0xA1,
        (byte) 0x39,
        (byte) 0x45,
        (byte) 0xD8,
        (byte) 0x98,
        (byte) 0xC2,
        (byte) 0x96,
        // Gy
        (byte) 0x4F,
        (byte) 0xE3,
        (byte) 0x42,
        (byte) 0xE2,
        (byte) 0xFE,
        (byte) 0x1A,
        (byte) 0x7F,
        (byte) 0x9B,
        (byte) 0x4F,
        (byte) 0xBC,
        (byte) 0x28,
        (byte) 0x07,
        (byte) 0x03,
        (byte) 0x22,
        (byte) 0x5D,
        (byte) 0x11,
        (byte) 0x7C,
        (byte) 0xB1,
        (byte) 0xA5,
        (byte) 0x90,
        (byte) 0x32,
        (byte) 0x27,
        (byte) 0xCC,
        (byte) 0x55,
        (byte) 0x07,
        (byte) 0xB5,
        (byte) 0xA7,
        (byte) 0x31,
        (byte) 0x67,
        (byte) 0x85,
        (byte) 0x2F,
        (byte) 0x9F,
    };

    // -------------------------------------------------------------------------
    // Subgroup order n
    // -------------------------------------------------------------------------
    private static final byte[] N = {
        (byte) 0xFF,
        (byte) 0xFF,
        (byte) 0xFF,
        (byte) 0xFF,
        (byte) 0x00,
        (byte) 0x00,
        (byte) 0x00,
        (byte) 0x00,
        (byte) 0xFF,
        (byte) 0xFF,
        (byte) 0xFF,
        (byte) 0xFF,
        (byte) 0xFF,
        (byte) 0xFF,
        (byte) 0xFF,
        (byte) 0xFF,
        (byte) 0xBC,
        (byte) 0xE6,
        (byte) 0xFA,
        (byte) 0xAD,
        (byte) 0xA7,
        (byte) 0x17,
        (byte) 0x9E,
        (byte) 0x84,
        (byte) 0xF3,
        (byte) 0xB9,
        (byte) 0xCA,
        (byte) 0xC2,
        (byte) 0xFC,
        (byte) 0x63,
        (byte) 0x25,
        (byte) 0x51,
    };

    // Cofactor h = 1
    private static final byte H = (byte) 1;

    // -------------------------------------------------------------------------
    // Public helpers
    // -------------------------------------------------------------------------

    /**
     * Apply all P-256 domain parameters to an ECKey (works for both
     * ECPublicKey and ECPrivateKey since both implement ECKey).
     *
     * Must be called on any key object before it is used for generation
     * or signing — JavaCard does not pre-populate curve parameters.
     */
    public static void setP256Params(ECKey key) {
        key.setFieldFP(FP, (short) 0, (short) FP.length);
        key.setA(A, (short) 0, (short) A.length);
        key.setB(B, (short) 0, (short) B.length);
        key.setG(G, (short) 0, (short) G.length);
        key.setR(N, (short) 0, (short) N.length);
        key.setK(H);
    }

    /** Convenience overload that accepts an ECPublicKey explicitly. */
    public static void setP256Params(ECPublicKey key) {
        setP256Params((ECKey) key);
    }

    /** Convenience overload that accepts an ECPrivateKey explicitly. */
    public static void setP256Params(ECPrivateKey key) {
        setP256Params((ECKey) key);
    }
}
