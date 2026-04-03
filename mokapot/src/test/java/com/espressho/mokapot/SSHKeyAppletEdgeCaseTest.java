package com.espressho.mokapot;

import pro.javacard.engine.core.JavaCardEngine;
import com.licel.jcardsim.base.Simulator;
import com.licel.jcardsim.base.SimulatorSession;
import com.licel.jcardsim.utils.AIDUtil;
import javacard.framework.AID;
import javacard.framework.ISO7816;
import org.junit.Before;
import org.junit.After;
import org.junit.Test;

import javax.smartcardio.CommandAPDU;
import javax.smartcardio.ResponseAPDU;

import static org.junit.Assert.*;

/**
 * SSHKeyAppletEdgeCaseTest — Comprehensive edge case and boundary condition tests.
 * 
 * This test suite validates the robustness of the EspreSSHo JavaCard applet 
 * by testing boundary conditions, malformed APDUs, extreme values, and error
 * recovery scenarios to ensure graceful handling of all edge cases.
 * 
 * Edge Case Categories Tested:
 * 1. APDU Format Edge Cases - min/max lengths, malformed structure
 * 2. PIN Validation Edge Cases - boundary lengths, invalid content  
 * 3. Flag Validation Edge Cases - reserved bits, boundary values
 * 4. Slot Management Edge Cases - boundary slots, invalid ranges
 * 5. Transaction Error Recovery - failure scenarios, rollback
 * 6. Memory/Resource Edge Cases - buffer overflows, resource limits
 * 7. Error Response Validation - correct codes, consistency, information leakage
 * 
 * Each test verifies that the applet handles edge conditions gracefully without
 * compromising security or corrupting internal state.
 */
public class SSHKeyAppletEdgeCaseTest {
    
    private static final byte[] APPLET_AID = AIDUtil.bytes(AIDUtil.create("CAFE4D6F6B61000100000000000000"));
    private static final byte[] DEFAULT_PIN = {'1', '2', '3', '4'};
    
    // Test PIN values for boundary testing
    private static final byte[] MIN_PIN = {'1'};                                    // 1 byte (minimum)
    private static final byte[] MAX_PIN = {'1','2','3','4','5','6','7','8'};       // 8 bytes (maximum)
    private static final byte[] OVERSIZED_PIN = {'1','2','3','4','5','6','7','8','9'}; // 9 bytes (over limit)
    private static final byte[] EMPTY_PIN = {};                                     // 0 bytes (invalid)
    
    // Flag test values
    private static final byte FLAG_VALID_MIN = (byte) 0x00;    // All flags off
    private static final byte FLAG_VALID_MAX = (byte) 0xF8;    // All valid flags on
    private static final byte FLAG_RESERVED_1 = (byte) 0x01;   // Reserved bit 0
    private static final byte FLAG_RESERVED_2 = (byte) 0x02;   // Reserved bit 1  
    private static final byte FLAG_RESERVED_4 = (byte) 0x04;   // Reserved bit 2
    private static final byte FLAG_RESERVED_7 = (byte) 0x07;   // All reserved bits
    
    private JavaCardEngine sim;
    private SimulatorSession session;

    @Before
    public void setUp() throws Exception {
        sim = new Simulator();
        AID aid = AIDUtil.create("CAFE4D6F6B61000100000000000000");
        byte[] installParams = new byte[0];
        sim.installApplet(aid, SSHKeyApplet.class, installParams);
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
        assertTrue("Applet selection failed", response.length >= 2);
        
        int sw = ((response[response.length - 2] & 0xFF) << 8) | (response[response.length - 1] & 0xFF);
        assertEquals("Applet selection failed", 0x9000, sw);
    }

    private byte[] buildAPDU(byte ins, byte p1, byte p2, byte[] pin, byte flags) {
        int cmdLen = 5 + 1 + pin.length + 1; // Header + PIN_LEN + PIN + FLAGS
        byte[] cmd = new byte[cmdLen];
        
        cmd[0] = (byte) 0x00;   // CLA (corrected from 0x80)
        cmd[1] = ins;           // INS
        cmd[2] = p1;            // P1 (slot)
        cmd[3] = p2;            // P2
        cmd[4] = (byte)(1 + pin.length + 1); // LC = PIN_LEN + PIN + FLAGS
        cmd[5] = (byte) pin.length;          // PIN_LEN
        
        // Copy PIN
        System.arraycopy(pin, 0, cmd, 6, pin.length);
        cmd[6 + pin.length] = flags;         // FLAGS
        
        return cmd;
    }

    private byte[] buildMalformedAPDU(byte ins, byte p1, byte[] data) {
        byte[] cmd = new byte[5 + data.length];
        cmd[0] = (byte) 0x00;   // CLA (corrected from 0x80)
        cmd[1] = ins;           // INS
        cmd[2] = p1;            // P1
        cmd[3] = 0x00;          // P2
        cmd[4] = (byte) data.length; // LC
        System.arraycopy(data, 0, cmd, 5, data.length);
        return cmd;
    }

    private int getSW(byte[] response) {
        if (response.length < 2) return 0x0000;
        return ((response[response.length - 2] & 0xFF) << 8) | (response[response.length - 1] & 0xFF);
    }

    // =========================================================================
    // 1. APDU FORMAT EDGE CASES
    // =========================================================================
    
    @Test
    public void testMinimumValidAPDU() {
        // Test minimal valid APDU: 1-byte PIN + flags
        byte[] cmd = buildAPDU((byte) 0x01, (byte) 0x00, (byte) 0x00, MIN_PIN, FLAG_VALID_MIN);
        byte[] response = session.transmitCommand(cmd);
        
        // Should either succeed (9000) or fail with security error (not format error)
        int sw = getSW(response);
        assertNotEquals("Minimal valid APDU should not return wrong length", 0x6700, sw);
        assertTrue("Should return valid response", sw == 0x9000 || sw == 0x6982);
    }
    
    @Test  
    public void testMaximumValidAPDU() {
        // Test maximal valid APDU: 8-byte PIN + flags
        byte[] cmd = buildAPDU((byte) 0x20, (byte) 0x00, (byte) 0x00, MAX_PIN, FLAG_VALID_MAX);
        byte[] response = session.transmitCommand(cmd);
        
        int sw = getSW(response);
        assertNotEquals("Maximum valid APDU should not return wrong length", 0x6700, sw);
        assertTrue("Should return valid response", sw == 0x9000 || sw == 0x6982);
    }
    
    @Test
    public void testEmptyAPDU() {
        // Test APDU with no data
        byte[] cmd = {(byte) 0x00, (byte) 0x20, (byte) 0x00, (byte) 0x00, (byte) 0x00};
        byte[] response = session.transmitCommand(cmd);
        
        int sw = getSW(response);
        assertEquals("Empty APDU should return wrong length", 0x6700, sw);
    }
    
    @Test
    public void testTruncatedAPDU() {
        // Test APDU with incomplete data (missing flags)
        byte[] data = {(byte) 4, '1', '2', '3', '4'}; // PIN_LEN + PIN, no FLAGS
        byte[] cmd = buildMalformedAPDU((byte) 0x20, (byte) 0x00, data);
        byte[] response = session.transmitCommand(cmd);
        
        int sw = getSW(response);
        assertEquals("Truncated APDU should return wrong length", 0x6700, sw);
    }
    
    @Test
    public void testPINLengthMismatch() {
        // Test PIN_LEN claiming 4 bytes but only providing 2
        byte[] data = {(byte) 4, '1', '2', (byte) 0x00}; // Claims 4, provides 2
        byte[] cmd = buildMalformedAPDU((byte) 0x20, (byte) 0x00, data);
        byte[] response = session.transmitCommand(cmd);
        
        int sw = getSW(response);
        assertEquals("PIN length mismatch should return wrong length", 0x6700, sw);
    }

    // =========================================================================
    // 2. PIN VALIDATION EDGE CASES  
    // =========================================================================
    
    @Test
    public void testZeroLengthPIN() {
        // Test PIN_LEN = 0
        byte[] data = {(byte) 0, (byte) 0x00}; // PIN_LEN=0, FLAGS
        byte[] cmd = buildMalformedAPDU((byte) 0x20, (byte) 0x00, data);
        byte[] response = session.transmitCommand(cmd);
        
        int sw = getSW(response);
        assertEquals("Zero length PIN should return wrong length", 0x6700, sw);
    }
    
    @Test
    public void testOversizedPIN() {
        // Test PIN_LEN > 8 (maximum)
        byte[] data = {(byte) 9, '1','2','3','4','5','6','7','8','9', (byte) 0x00};
        byte[] cmd = buildMalformedAPDU((byte) 0x20, (byte) 0x00, data);
        byte[] response = session.transmitCommand(cmd);
        
        int sw = getSW(response);
        assertEquals("Oversized PIN should return wrong length", 0x6700, sw);
    }
    
    @Test
    public void testPINWithNullBytes() {
        // Test PIN containing null bytes
        byte[] pinWithNull = {'1', '2', 0x00, '4'};
        byte[] cmd = buildAPDU((byte) 0x20, (byte) 0x00, (byte) 0x00, pinWithNull, FLAG_VALID_MIN);
        byte[] response = session.transmitCommand(cmd);
        
        int sw = getSW(response);
        // Should either succeed or fail with security error, not format error
        assertTrue("PIN with null bytes should be handled gracefully", 
                  sw == 0x9000 || sw == 0x6982);
    }
    
    @Test 
    public void testPINBoundaryLengths() {
        // Test 1-byte PIN (minimum valid)
        byte[] cmd1 = buildAPDU((byte) 0x20, (byte) 0x00, (byte) 0x00, MIN_PIN, FLAG_VALID_MIN);
        byte[] response1 = session.transmitCommand(cmd1);
        int sw1 = getSW(response1);
        assertNotEquals("1-byte PIN should not return format error", 0x6700, sw1);
        
        // Test 8-byte PIN (maximum valid)
        byte[] cmd8 = buildAPDU((byte) 0x20, (byte) 0x00, (byte) 0x00, MAX_PIN, FLAG_VALID_MIN);
        byte[] response8 = session.transmitCommand(cmd8);
        int sw8 = getSW(response8);
        assertNotEquals("8-byte PIN should not return format error", 0x6700, sw8);
    }

    // =========================================================================
    // 3. FLAG VALIDATION EDGE CASES
    // =========================================================================
    
    @Test
    public void testValidFlagBoundaries() {
        // Test minimum valid flag value (0x00)
        byte[] cmd1 = buildAPDU((byte) 0x20, (byte) 0x00, (byte) 0x00, DEFAULT_PIN, FLAG_VALID_MIN);
        byte[] response1 = session.transmitCommand(cmd1);
        int sw1 = getSW(response1);
        assertTrue("Valid flag 0x00 should be accepted", sw1 == 0x9000 || sw1 == 0x6982);
        
        // Test maximum valid flag value (0xF8)
        byte[] cmd2 = buildAPDU((byte) 0x20, (byte) 0x00, (byte) 0x00, DEFAULT_PIN, FLAG_VALID_MAX);
        byte[] response2 = session.transmitCommand(cmd2);
        int sw2 = getSW(response2);
        assertTrue("Valid flag 0xF8 should be accepted", sw2 == 0x9000 || sw2 == 0x6982);
    }
    
    @Test
    public void testReservedFlagBits() {
        // Test each reserved bit individually
        
        // Reserved bit 0
        byte[] cmd1 = buildAPDU((byte) 0x20, (byte) 0x00, (byte) 0x00, DEFAULT_PIN, FLAG_RESERVED_1);
        byte[] response1 = session.transmitCommand(cmd1);
        int sw1 = getSW(response1);
        assertEquals("Reserved flag bit 0 should return wrong data", 0x6A80, sw1);
        
        // Reserved bit 1
        byte[] cmd2 = buildAPDU((byte) 0x20, (byte) 0x00, (byte) 0x00, DEFAULT_PIN, FLAG_RESERVED_2);
        byte[] response2 = session.transmitCommand(cmd2);
        int sw2 = getSW(response2);
        assertEquals("Reserved flag bit 1 should return wrong data", 0x6A80, sw2);
        
        // Reserved bit 2
        byte[] cmd3 = buildAPDU((byte) 0x20, (byte) 0x00, (byte) 0x00, DEFAULT_PIN, FLAG_RESERVED_4);
        byte[] response3 = session.transmitCommand(cmd3);
        int sw3 = getSW(response3);
        assertEquals("Reserved flag bit 2 should return wrong data", 0x6A80, sw3);
        
        // All reserved bits
        byte[] cmd4 = buildAPDU((byte) 0x20, (byte) 0x00, (byte) 0x00, DEFAULT_PIN, FLAG_RESERVED_7);
        byte[] response4 = session.transmitCommand(cmd4);
        int sw4 = getSW(response4);
        assertEquals("All reserved flag bits should return wrong data", 0x6A80, sw4);
    }

    // =========================================================================
    // 4. SLOT MANAGEMENT EDGE CASES
    // =========================================================================
    
    @Test
    public void testSlotBoundaryValues() {
        // Test valid boundary slots (0 and 3)
        byte[] cmd0 = buildAPDU((byte) 0x20, (byte) 0x00, (byte) 0x00, DEFAULT_PIN, FLAG_VALID_MIN);
        byte[] response0 = session.transmitCommand(cmd0);
        int sw0 = getSW(response0);
        assertTrue("Slot 0 should be valid", sw0 == 0x9000 || sw0 == 0x6982);
        
        byte[] cmd3 = buildAPDU((byte) 0x20, (byte) 0x03, (byte) 0x00, DEFAULT_PIN, FLAG_VALID_MIN);
        byte[] response3 = session.transmitCommand(cmd3);
        int sw3 = getSW(response3);
        assertTrue("Slot 3 should be valid", sw3 == 0x9000 || sw3 == 0x6982);
    }
    
    @Test
    public void testInvalidSlotNumbers() {
        // Test invalid slots (negative values handled as unsigned bytes)
        byte[] cmdNeg = buildAPDU((byte) 0x20, (byte) 0xFF, (byte) 0x00, DEFAULT_PIN, FLAG_VALID_MIN);
        byte[] responseNeg = session.transmitCommand(cmdNeg);
        int swNeg = getSW(responseNeg);
        assertEquals("Negative slot (-1 as 0xFF) should return incorrect P1P2", 0x6A86, swNeg);
        
        // Test slot >= 4
        byte[] cmd4 = buildAPDU((byte) 0x20, (byte) 0x04, (byte) 0x00, DEFAULT_PIN, FLAG_VALID_MIN);
        byte[] response4 = session.transmitCommand(cmd4);
        int sw4 = getSW(response4);
        assertEquals("Slot 4 should return incorrect P1P2", 0x6A86, sw4);
        
        // Test extremely high slot
        byte[] cmdHigh = buildAPDU((byte) 0x20, (byte) 0x7F, (byte) 0x00, DEFAULT_PIN, FLAG_VALID_MIN);
        byte[] responseHigh = session.transmitCommand(cmdHigh);
        int swHigh = getSW(responseHigh);
        assertEquals("High slot should return incorrect P1P2", 0x6A86, swHigh);
    }

    @Test
    public void testOperationsOnEmptySlots() {
        // Test GET_PUBKEY on empty slot
        byte[] getPubCmd = {(byte) 0x00, (byte) 0x21, (byte) 0x00, (byte) 0x00, (byte) 0x00};
        byte[] response = session.transmitCommand(getPubCmd);
        int sw = getSW(response);
        assertEquals("GET_PUBKEY on empty slot should return key not found", 0x6A88, sw);
        
        // Test SIGN on empty slot  
        byte[] signData = "test".getBytes();
        byte[] signCmd = new byte[5 + signData.length];
        signCmd[0] = (byte) 0x00;   // CLA (corrected)
        signCmd[1] = (byte) 0x22;   // INS_SIGN
        signCmd[2] = (byte) 0x00;   // P1 (slot)
        signCmd[3] = (byte) 0x00;   // P2
        signCmd[4] = (byte) signData.length; // LC
        System.arraycopy(signData, 0, signCmd, 5, signData.length);
        
        byte[] signResponse = session.transmitCommand(signCmd);
        int signSW = getSW(signResponse);
        assertEquals("SIGN on empty slot should return key not found", 0x6A88, signSW);
    }

    // =========================================================================
    // 5. ERROR RESPONSE VALIDATION
    // =========================================================================
    
    @Test
    public void testConsistentErrorCodes() {
        // Test that same errors return same codes consistently
        
        // Multiple invalid slot tests should all return 0x6A86
        byte[] cmd1 = buildAPDU((byte) 0x20, (byte) 0x04, (byte) 0x00, DEFAULT_PIN, FLAG_VALID_MIN);
        byte[] cmd2 = buildAPDU((byte) 0x20, (byte) 0xFF, (byte) 0x00, DEFAULT_PIN, FLAG_VALID_MIN);
        
        int sw1 = getSW(session.transmitCommand(cmd1));
        int sw2 = getSW(session.transmitCommand(cmd2));
        
        assertEquals("Invalid slot errors should be consistent", sw1, sw2);
        assertEquals("Invalid slots should return 0x6A86", 0x6A86, sw1);
        
        // Multiple reserved flag tests should all return 0x6A80
        byte[] flag1 = buildAPDU((byte) 0x20, (byte) 0x00, (byte) 0x00, DEFAULT_PIN, FLAG_RESERVED_1);
        byte[] flag2 = buildAPDU((byte) 0x20, (byte) 0x00, (byte) 0x00, DEFAULT_PIN, FLAG_RESERVED_4);
        
        int swFlag1 = getSW(session.transmitCommand(flag1));
        int swFlag2 = getSW(session.transmitCommand(flag2));
        
        assertEquals("Reserved flag errors should be consistent", swFlag1, swFlag2);
        assertEquals("Reserved flags should return 0x6A80", 0x6A80, swFlag1);
    }
    
    @Test
    public void testErrorInformationLeakage() {
        // Ensure error responses don't leak sensitive information
        
        // Wrong PIN should not indicate why it's wrong
        byte[] wrongPin = {'9', '9', '9', '9'};
        byte[] cmd = buildAPDU((byte) 0x20, (byte) 0x00, (byte) 0x00, wrongPin, FLAG_VALID_MIN);
        byte[] response = session.transmitCommand(cmd);
        
        int sw = getSW(response);
        assertEquals("Wrong PIN should return security status error", 0x6982, sw);
        assertEquals("Error response should contain no additional data", 2, response.length);
    }

    // =========================================================================
    // 6. BUFFER BOUNDARY AND OVERFLOW PROTECTION
    // =========================================================================
    
    @Test
    public void testAPDUBufferLimits() {
        // Test with maximum allowed APDU size (255 bytes data)
        // Build largest possible valid APDU: PIN_LEN + 8-byte PIN + FLAGS = 10 bytes
        // Add padding to reach limits
        byte[] largeData = new byte[255];
        largeData[0] = 8; // PIN_LEN
        System.arraycopy(MAX_PIN, 0, largeData, 1, 8);
        largeData[9] = FLAG_VALID_MIN; // FLAGS
        // Rest filled with zeros (padding)
        
        byte[] cmd = buildMalformedAPDU((byte) 0x20, (byte) 0x00, largeData);
        byte[] response = session.transmitCommand(cmd);
        
        int sw = getSW(response);
        // Should handle gracefully - either parse correctly or reject with proper error
        assertNotEquals("Large APDU should not cause crash", 0x0000, sw);
    }

    // =========================================================================
    // 7. TRANSACTION AND STATE VALIDATION
    // =========================================================================
    
    @Test
    public void testMultipleOperationsStateConsistency() {
        // Test that multiple operations don't interfere with each other
        
        // First operation - should fail due to wrong PIN
        byte[] wrongPin = {'9', '9', '9', '9'};
        byte[] cmd1 = buildAPDU((byte) 0x20, (byte) 0x00, (byte) 0x00, wrongPin, FLAG_VALID_MIN);
        byte[] response1 = session.transmitCommand(cmd1);
        assertEquals("First wrong PIN should fail", 0x6982, getSW(response1));
        
        // Second operation - different slot, still wrong PIN  
        byte[] cmd2 = buildAPDU((byte) 0x20, (byte) 0x01, (byte) 0x00, wrongPin, FLAG_VALID_MIN);
        byte[] response2 = session.transmitCommand(cmd2);
        assertEquals("Second wrong PIN should fail consistently", 0x6982, getSW(response2));
        
        // Third operation - back to first slot, still wrong PIN
        byte[] cmd3 = buildAPDU((byte) 0x20, (byte) 0x00, (byte) 0x00, wrongPin, FLAG_VALID_MIN);
        byte[] response3 = session.transmitCommand(cmd3);
        assertEquals("Third wrong PIN should fail consistently", 0x6982, getSW(response3));
    }
    
    @Test
    public void testSlotIndependence() {
        // Verify operations on one slot don't affect others
        
        // Check that all slots start empty
        for (int slot = 0; slot < 4; slot++) {
            byte[] getPubCmd = {(byte) 0x00, (byte) 0x21, (byte) slot, (byte) 0x00, (byte) 0x00};
            byte[] response = session.transmitCommand(getPubCmd);
            assertEquals("Slot " + slot + " should start empty", 0x6A88, getSW(response));
        }
        
        // Operations on invalid slots should not affect valid slots
        byte[] invalidCmd = buildAPDU((byte) 0x20, (byte) 0x99, (byte) 0x00, DEFAULT_PIN, FLAG_VALID_MIN);
        session.transmitCommand(invalidCmd); // Should fail
        
        // Valid slots should still be empty and unaffected
        for (int slot = 0; slot < 4; slot++) {
            byte[] getPubCmd = {(byte) 0x00, (byte) 0x21, (byte) slot, (byte) 0x00, (byte) 0x00};
            byte[] response = session.transmitCommand(getPubCmd);
            assertEquals("Slot " + slot + " should remain empty after invalid operation", 
                        0x6A88, getSW(response));
        }
    }

    // =========================================================================
    // 8. INSTRUCTION EDGE CASES
    // =========================================================================
    
    @Test
    public void testUnsupportedInstructions() {
        // Test various unsupported instruction codes
        byte[] unsupportedInstructions = {
            (byte) 0x00, (byte) 0x01, (byte) 0x10, (byte) 0x30, 
            (byte) 0x40, (byte) 0x50, (byte) 0x60, (byte) 0x70,
            (byte) 0x80, (byte) 0x90, (byte) 0xFF
        };
        
        for (byte ins : unsupportedInstructions) {
            if (ins == 0x20 || ins == 0x21 || ins == 0x22 || ins == 0x23 || ins == 0x24 || ins == 0x25 || ins == 0x30 || ins == 0x31) {
                continue; // Skip supported instructions
            }
            
            byte[] cmd = {(byte) 0x00, ins, (byte) 0x00, (byte) 0x00, (byte) 0x00};
            byte[] response = session.transmitCommand(cmd);
            int sw = getSW(response);
            assertEquals("Unsupported instruction 0x" + String.format("%02X", ins) + 
                        " should return INS_NOT_SUPPORTED", 0x6D00, sw);
        }
    }

    // =========================================================================
    // 9. PIN ATTEMPT EXHAUSTION (Commented - would block card)
    // =========================================================================
    
    // WARNING: These tests would permanently block the card in a real environment
    // Uncomment only for specific testing with disposable cards
    
    /*
    @Test
    public void testPINBlockingBehavior() {
        byte[] wrongPin = {'9', '9', '9', '9'};
        
        // Attempt 1
        byte[] cmd1 = buildAPDU((byte) 0x20, (byte) 0x00, (byte) 0x00, wrongPin, FLAG_VALID_MIN);
        assertEquals("First wrong PIN", 0x6982, getSW(session.transmitCommand(cmd1)));
        
        // Attempt 2  
        byte[] cmd2 = buildAPDU((byte) 0x20, (byte) 0x00, (byte) 0x00, wrongPin, FLAG_VALID_MIN);
        assertEquals("Second wrong PIN", 0x6982, getSW(session.transmitCommand(cmd2)));
        
        // Attempt 3 (should block PIN)
        byte[] cmd3 = buildAPDU((byte) 0x20, (byte) 0x00, (byte) 0x00, wrongPin, FLAG_VALID_MIN);
        int sw = getSW(session.transmitCommand(cmd3));
        assertTrue("Third wrong PIN should block", sw == 0x6983 || sw == 0x6982);
        
        // Further attempts should indicate blocked state
        byte[] cmd4 = buildAPDU((byte) 0x20, (byte) 0x00, (byte) 0x00, DEFAULT_PIN, FLAG_VALID_MIN);
        int sw4 = getSW(session.transmitCommand(cmd4));
        assertEquals("PIN should remain blocked even with correct PIN", 0x6983, sw4);
    }
    */

    // =========================================================================
    // 10. COMPREHENSIVE APDU STRUCTURE VALIDATION  
    // =========================================================================
    
    @Test
    public void testAPDUStructureValidation() {
        // Test various malformed APDU structures
        
        // Wrong CLA
        byte[] wrongCLA = buildAPDU((byte) 0x20, (byte) 0x00, (byte) 0x00, DEFAULT_PIN, FLAG_VALID_MIN);
        wrongCLA[0] = (byte) 0x80; // Should be 0x00
        assertEquals("Wrong CLA should be rejected", 0x6E00, getSW(session.transmitCommand(wrongCLA)));
        
        // Missing LC byte
        byte[] noLC = {(byte) 0x00, (byte) 0x20, (byte) 0x00, (byte) 0x00};
        int swNoLC = getSW(session.transmitCommand(noLC));
        assertTrue("Missing LC should be handled gracefully", swNoLC != 0x0000);
        
        // LC mismatch (claims more data than provided)
        byte[] shortData = {(byte) 0x00, (byte) 0x20, (byte) 0x00, (byte) 0x00, (byte) 0x10, (byte) 0x04};
        int swShort = getSW(session.transmitCommand(shortData));
        assertTrue("Short data should be handled gracefully", swShort != 0x0000);
    }
}