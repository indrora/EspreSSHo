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
 * Simple test to validate correct instruction codes and basic APDU format
 */
public class InstructionValidationTest {
    
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
        assertTrue("Applet selection failed", response.length >= 2);
        
        int sw = ((response[response.length - 2] & 0xFF) << 8) | (response[response.length - 1] & 0xFF);
        assertEquals("Applet selection failed", 0x9000, sw);
    }

    private int getSW(byte[] response) {
        if (response.length < 2) return 0x0000;
        return ((response[response.length - 2] & 0xFF) << 8) | (response[response.length - 1] & 0xFF);
    }

    @Test
    public void testSupportedInstructions() {
        // Test the basic supported instructions (from APDUConstants)
        byte[] supportedInstructions = {
            (byte) 0x01, // INS_GEN_KEY
            (byte) 0x02, // INS_GET_PUBKEY
            (byte) 0x03, // INS_SIGN
            (byte) 0x04, // INS_LIST_KEYS
            (byte) 0x05, // INS_VERIFY_PIN
            (byte) 0x06, // INS_CHANGE_PIN
            (byte) 0x07, // INS_SET_FLAGS
            (byte) 0x08, // INS_REGEN_KEY
            (byte) 0x09, // INS_UNBLOCK_PIN
            (byte) 0x0A  // INS_CLEAR_KEY
        };
        
        for (byte ins : supportedInstructions) {
            // Send minimal APDU for each instruction
            byte[] cmd = {(byte) 0x00, ins, (byte) 0x00, (byte) 0x00, (byte) 0x00};
            byte[] response = session.transmitCommand(cmd);
            int sw = getSW(response);
            
            System.out.println("Instruction 0x" + String.format("%02X", ins) + " -> SW: 0x" + String.format("%04X", sw));
            
            // Should NOT return INS_NOT_SUPPORTED (0x6D00)
            assertNotEquals("Instruction 0x" + String.format("%02X", ins) + " should be supported", 
                           0x6D00, sw);
        }
    }

    @Test
    public void testUnsupportedInstructions() {
        // Test clearly unsupported instructions
        byte[] unsupportedInstructions = {
            (byte) 0x00, (byte) 0x0B, (byte) 0x0C, (byte) 0x10, 
            (byte) 0x20, (byte) 0x30, (byte) 0xFF
        };
        
        for (byte ins : unsupportedInstructions) {
            byte[] cmd = {(byte) 0x00, ins, (byte) 0x00, (byte) 0x00, (byte) 0x00};
            byte[] response = session.transmitCommand(cmd);
            int sw = getSW(response);
            
            System.out.println("Unsupported instruction 0x" + String.format("%02X", ins) + " -> SW: 0x" + String.format("%04X", sw));
            
            // Should return INS_NOT_SUPPORTED (0x6D00)
            assertEquals("Instruction 0x" + String.format("%02X", ins) + " should be unsupported", 
                        0x6D00, sw);
        }
    }

    @Test 
    public void testListKeysBasic() {
        // Test LIST_KEYS which should work without any data
        byte[] cmd = {(byte) 0x00, (byte) 0x04, (byte) 0x00, (byte) 0x00, (byte) 0x00};
        byte[] response = session.transmitCommand(cmd);
        int sw = getSW(response);
        
        System.out.println("LIST_KEYS -> SW: 0x" + String.format("%04X", sw) + ", response length: " + response.length);
        
        // Should succeed (all slots empty = 0x00)
        assertEquals("LIST_KEYS should succeed", 0x9000, sw);
        assertEquals("Should return 1 byte of data + 2 SW bytes", 3, response.length);
        assertEquals("All slots should be empty", 0x00, response[0]);
    }

    @Test
    public void testGetPubKeyOnEmptySlot() {
        // Test GET_PUBKEY on empty slot - should return proper error
        byte[] cmd = {(byte) 0x00, (byte) 0x02, (byte) 0x00, (byte) 0x00, (byte) 0x00};
        byte[] response = session.transmitCommand(cmd);
        int sw = getSW(response);
        
        System.out.println("GET_PUBKEY(empty slot) -> SW: 0x" + String.format("%04X", sw));
        
        // Should return key not found (0x6A88 based on APDUConstants.SW_KEY_NOT_FOUND = 0x6A82, but let's see actual)
        assertTrue("Should return key not found error", sw == 0x6A82 || sw == 0x6A88);
    }
}