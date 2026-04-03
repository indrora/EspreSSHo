package com.espressho.mokapot;

import pro.javacard.engine.core.JavaCardEngine;
import com.licel.jcardsim.base.Simulator;
import com.licel.jcardsim.base.SimulatorSession;
import com.licel.jcardsim.utils.AIDUtil;
import javacard.framework.AID;
import org.junit.Before;
import org.junit.After;
import org.junit.Test;

import static org.junit.Assert.*;

/**
 * Focused edge case validation tests that work within jCardSim limitations.
 * Tests APDU parsing, input validation, and error handling without requiring 
 * crypto operations that are limited in the simulator.
 */
public class FocusedEdgeCaseTest {
    
    private static final byte[] APPLET_AID = AIDUtil.bytes(AIDUtil.create("CAFE4D6F6B61000100000000000000"));
    private JavaCardEngine sim;
    private SimulatorSession session;

    @Before
    public void setUp() throws Exception {
        sim = new Simulator();
        AID aid = AIDUtil.create("CAFE4D6F6B61000100000000000000");
        sim.installApplet(aid, SSHKeyApplet.class, new byte[0]);
        session = sim.connect("T=CL");
        selectApplet(APPLET_AID);
    }

    @After
    public void tearDown() {
        if (session != null && !session.isClosed()) {
            try {
                session.close(false);
            } catch (Exception e) {
                // Ignore cleanup errors
            }
        }
    }

    private void selectApplet(byte[] aid) {
        byte[] selectCmd = new byte[5 + aid.length];
        selectCmd[0] = 0x00; // CLA
        selectCmd[1] = (byte) 0xA4; // INS_SELECT
        selectCmd[2] = 0x04; // P1 - select by name
        selectCmd[3] = 0x00; // P2
        selectCmd[4] = (byte) aid.length; // LC
        System.arraycopy(aid, 0, selectCmd, 5, aid.length);
        
        byte[] response = session.transmitCommand(selectCmd);
        int sw = ((response[response.length - 2] & 0xFF) << 8) | (response[response.length - 1] & 0xFF);
        assertEquals("Applet selection failed", 0x9000, sw);
    }

    private byte[] buildGenKeyAPDU(byte slot, byte[] pin, byte flags) {
        int cmdLen = 5 + 1 + pin.length + 1;
        byte[] cmd = new byte[cmdLen];
        cmd[0] = (byte) 0x00;   // CLA
        cmd[1] = (byte) 0x01;   // INS_GEN_KEY
        cmd[2] = slot;          // P1 (slot)
        cmd[3] = (byte) 0x00;   // P2
        cmd[4] = (byte)(1 + pin.length + 1); // LC
        cmd[5] = (byte) pin.length;          // PIN_LEN
        System.arraycopy(pin, 0, cmd, 6, pin.length);
        cmd[6 + pin.length] = flags;
        return cmd;
    }

    private int getSW(byte[] response) {
        if (response.length < 2) return 0x0000;
        return ((response[response.length - 2] & 0xFF) << 8) | (response[response.length - 1] & 0xFF);
    }

    // =========================================================================
    // CLA VALIDATION TESTS
    // =========================================================================
    
    @Test
    public void testWrongCLAValidation() {
        byte[] pin = {'1', '2', '3', '4'};
        byte[] cmd = buildGenKeyAPDU((byte) 0x00, pin, (byte) 0x00);
        cmd[0] = (byte) 0x80; // Wrong CLA
        
        byte[] response = session.transmitCommand(cmd);
        assertEquals("Wrong CLA should return CLA_NOT_SUPPORTED", 0x6E00, getSW(response));
    }

    // =========================================================================
    // INSTRUCTION VALIDATION TESTS  
    // =========================================================================
    
    @Test
    public void testUnsupportedInstructions() {
        byte[] unsupported = {(byte) 0x20, (byte) 0x30, (byte) 0xFF, (byte) 0x0B};
        
        for (byte ins : unsupported) {
            byte[] cmd = {(byte) 0x00, ins, (byte) 0x00, (byte) 0x00, (byte) 0x00};
            byte[] response = session.transmitCommand(cmd);
            assertEquals("Instruction 0x" + String.format("%02X", ins) + " should be unsupported", 
                        0x6D00, getSW(response));
        }
    }

    // =========================================================================
    // SLOT VALIDATION TESTS
    // =========================================================================
    
    @Test
    public void testInvalidSlotNumbers() {
        byte[] pin = {'1', '2', '3', '4'};
        
        // Test slot > 3 (MAX_KEYS = 4, so valid range is 0-3)
        byte[] cmd1 = buildGenKeyAPDU((byte) 0x04, pin, (byte) 0x00);
        assertEquals("Slot 4 should be invalid", 0x6A86, getSW(session.transmitCommand(cmd1)));
        
        // Test very high slot value
        byte[] cmd2 = buildGenKeyAPDU((byte) 0xFF, pin, (byte) 0x00);
        assertEquals("Slot 255 should be invalid", 0x6A86, getSW(session.transmitCommand(cmd2)));
        
        // Test valid boundary slots
        byte[] cmd3 = buildGenKeyAPDU((byte) 0x00, pin, (byte) 0x00);
        int sw3 = getSW(session.transmitCommand(cmd3));
        assertNotEquals("Slot 0 should be valid (not invalid slot)", 0x6A86, sw3);
        
        byte[] cmd4 = buildGenKeyAPDU((byte) 0x03, pin, (byte) 0x00);
        int sw4 = getSW(session.transmitCommand(cmd4));
        assertNotEquals("Slot 3 should be valid (not invalid slot)", 0x6A86, sw4);
    }

    // =========================================================================
    // FLAG VALIDATION TESTS  
    // =========================================================================
    
    @Test
    public void testReservedFlagBitValidation() {
        byte[] pin = {'1', '2', '3', '4'};
        
        // Test individual reserved bits (bits 0, 1, 2)
        byte[] reservedFlags = {(byte) 0x01, (byte) 0x02, (byte) 0x04, (byte) 0x07};
        
        for (byte flag : reservedFlags) {
            byte[] cmd = buildGenKeyAPDU((byte) 0x00, pin, flag);
            byte[] response = session.transmitCommand(cmd);
            assertEquals("Reserved flag bit 0x" + String.format("%02X", flag) + " should be rejected", 
                        0x6A80, getSW(response));
        }
    }
    
    @Test
    public void testValidFlagValues() {
        byte[] pin = {'1', '2', '3', '4'};
        
        // Test valid flag values (no reserved bits set)
        byte[] validFlags = {(byte) 0x00, (byte) 0x08, (byte) 0x80, (byte) 0x88, (byte) 0xF8};
        
        for (byte flag : validFlags) {
            byte[] cmd = buildGenKeyAPDU((byte) 0x00, pin, flag);
            byte[] response = session.transmitCommand(cmd);
            int sw = getSW(response);
            assertNotEquals("Valid flag 0x" + String.format("%02X", flag) + " should not be rejected for wrong data", 
                           0x6A80, sw);
        }
    }

    // =========================================================================
    // PIN LENGTH VALIDATION TESTS
    // =========================================================================
    
    @Test
    public void testPINLengthBoundaries() {
        // Test minimum PIN length (1 byte)
        byte[] minPin = {'1'};
        byte[] cmd1 = buildGenKeyAPDU((byte) 0x00, minPin, (byte) 0x00);
        int sw1 = getSW(session.transmitCommand(cmd1));
        assertNotEquals("1-byte PIN should not fail with wrong length", 0x6700, sw1);
        
        // Test maximum PIN length (8 bytes)
        byte[] maxPin = {'1', '2', '3', '4', '5', '6', '7', '8'};
        byte[] cmd2 = buildGenKeyAPDU((byte) 0x00, maxPin, (byte) 0x00);
        int sw2 = getSW(session.transmitCommand(cmd2));
        assertNotEquals("8-byte PIN should not fail with wrong length", 0x6700, sw2);
    }
    
    @Test
    public void testInvalidPINLengths() {
        // Test zero-length PIN using malformed APDU
        byte[] data1 = {(byte) 0x00, (byte) 0x00}; // PIN_LEN=0, FLAGS
        byte[] cmd1 = new byte[5 + data1.length];
        cmd1[0] = (byte) 0x00;
        cmd1[1] = (byte) 0x01;
        cmd1[2] = (byte) 0x00;
        cmd1[3] = (byte) 0x00;
        cmd1[4] = (byte) data1.length;
        System.arraycopy(data1, 0, cmd1, 5, data1.length);
        assertEquals("Zero-length PIN should fail", 0x6700, getSW(session.transmitCommand(cmd1)));
        
        // Test oversized PIN (9 bytes)
        byte[] data2 = {(byte) 0x09, '1','2','3','4','5','6','7','8','9', (byte) 0x00};
        byte[] cmd2 = new byte[5 + data2.length];
        cmd2[0] = (byte) 0x00;
        cmd2[1] = (byte) 0x01;
        cmd2[2] = (byte) 0x00;
        cmd2[3] = (byte) 0x00;
        cmd2[4] = (byte) data2.length;
        System.arraycopy(data2, 0, cmd2, 5, data2.length);
        assertEquals("Oversized PIN should fail", 0x6700, getSW(session.transmitCommand(cmd2)));
    }

    // =========================================================================
    // APDU FORMAT VALIDATION TESTS
    // =========================================================================
    
    @Test
    public void testMalformedAPDUs() {
        // Empty data
        byte[] cmd1 = {(byte) 0x00, (byte) 0x01, (byte) 0x00, (byte) 0x00, (byte) 0x00};
        assertEquals("Empty data should fail", 0x6700, getSW(session.transmitCommand(cmd1)));
        
        // Truncated data (missing flags)
        byte[] data2 = {(byte) 0x04, '1', '2', '3', '4'}; // PIN_LEN + PIN, no FLAGS
        byte[] cmd2 = new byte[5 + data2.length];
        cmd2[0] = (byte) 0x00;
        cmd2[1] = (byte) 0x01;
        cmd2[2] = (byte) 0x00;
        cmd2[3] = (byte) 0x00;
        cmd2[4] = (byte) data2.length;
        System.arraycopy(data2, 0, cmd2, 5, data2.length);
        assertEquals("Truncated data should fail", 0x6700, getSW(session.transmitCommand(cmd2)));
        
        // Length mismatch
        byte[] data3 = {(byte) 0x06, '1', '2', '3', '4', (byte) 0x00}; // Claims 6, provides 4
        byte[] cmd3 = new byte[5 + data3.length];
        cmd3[0] = (byte) 0x00;
        cmd3[1] = (byte) 0x01;
        cmd3[2] = (byte) 0x00;
        cmd3[3] = (byte) 0x00;
        cmd3[4] = (byte) data3.length;
        System.arraycopy(data3, 0, cmd3, 5, data3.length);
        assertEquals("Length mismatch should fail", 0x6700, getSW(session.transmitCommand(cmd3)));
    }

    // =========================================================================
    // OPERATIONS ON EMPTY SLOTS
    // =========================================================================
    
    @Test
    public void testOperationsOnEmptySlots() {
        // GET_PUBKEY on empty slot
        byte[] getPubCmd = {(byte) 0x00, (byte) 0x02, (byte) 0x00, (byte) 0x00, (byte) 0x00};
        assertEquals("GET_PUBKEY on empty slot should return key not found", 
                    0x6A82, getSW(session.transmitCommand(getPubCmd)));
        
        // SIGN on empty slot
        byte[] signData = "test".getBytes();
        byte[] signCmd = new byte[5 + signData.length];
        signCmd[0] = (byte) 0x00;   // CLA
        signCmd[1] = (byte) 0x03;   // INS_SIGN
        signCmd[2] = (byte) 0x00;   // P1 (slot)
        signCmd[3] = (byte) 0x00;   // P2
        signCmd[4] = (byte) signData.length;
        System.arraycopy(signData, 0, signCmd, 5, signData.length);
        
        assertEquals("SIGN on empty slot should return key not found", 
                    0x6A82, getSW(session.transmitCommand(signCmd)));
    }

    // =========================================================================
    // ERROR CONSISTENCY VALIDATION
    // =========================================================================
    
    @Test
    public void testErrorCodeConsistency() {
        byte[] pin = {'1', '2', '3', '4'};
        
        // Multiple invalid slot tests should return same error
        int sw1 = getSW(session.transmitCommand(buildGenKeyAPDU((byte) 0x04, pin, (byte) 0x00)));
        int sw2 = getSW(session.transmitCommand(buildGenKeyAPDU((byte) 0xFF, pin, (byte) 0x00)));
        assertEquals("Invalid slot errors should be consistent", sw1, sw2);
        assertEquals("Should return INCORRECT_P1P2", 0x6A86, sw1);
        
        // Multiple reserved flag tests should return same error
        int swFlag1 = getSW(session.transmitCommand(buildGenKeyAPDU((byte) 0x00, pin, (byte) 0x01)));
        int swFlag2 = getSW(session.transmitCommand(buildGenKeyAPDU((byte) 0x00, pin, (byte) 0x04)));
        assertEquals("Reserved flag errors should be consistent", swFlag1, swFlag2);
        assertEquals("Should return WRONG_DATA", 0x6A80, swFlag1);
    }

    // =========================================================================
    // READ-ONLY OPERATIONS (ALWAYS WORK)
    // =========================================================================
    
    @Test
    public void testReadOnlyOperations() {
        // LIST_KEYS should always work
        byte[] listCmd = {(byte) 0x00, (byte) 0x04, (byte) 0x00, (byte) 0x00, (byte) 0x00};
        byte[] listResponse = session.transmitCommand(listCmd);
        assertEquals("LIST_KEYS should succeed", 0x9000, getSW(listResponse));
        assertEquals("Should return 1 byte + SW", 3, listResponse.length);
        assertEquals("All slots should be empty initially", 0x00, listResponse[0]);
    }
}