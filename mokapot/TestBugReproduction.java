package com.espressho.mokapot;

import pro.javacard.engine.core.JavaCardEngine;
import com.licel.jcardsim.base.Simulator;
import com.licel.jcardsim.base.SimulatorSession;
import com.licel.jcardsim.utils.AIDUtil;
import javacard.framework.AID;

/**
 * Quick test to reproduce the slot management bug
 */
public class TestBugReproduction {
    public static void main(String[] args) {
        try {
            // Create simulator and install applet
            Simulator simulator = JavaCardEngine.getEngine();
            byte[] aidBytes = {(byte) 0xA0, (byte) 0x00, (byte) 0x00, (byte) 0x06, 
                              (byte) 0x17, (byte) 0x00, (byte) 0x4D, (byte) 0x4F, (byte) 0x4B};
            AID aid = AIDUtil.create(aidBytes);
            
            simulator.installApplet(aid, SSHKeyApplet.class);
            SimulatorSession session = simulator.openSessionWith(aid);
            
            // Test GEN_KEY (0x01) with PIN "1234" and flags 0x00
            // APDU format: [CLA] [INS] [P1=slot] [P2=flags] [LC] [PIN_LEN] [PIN] [FLAGS]
            byte[] genKeyCmd = {(byte) 0x00, (byte) 0x01, (byte) 0x00, (byte) 0x00, 
                               (byte) 0x06, // LC = 6 (1 + 4 + 1)
                               (byte) 0x04, // PIN_LEN = 4
                               (byte) '1', (byte) '2', (byte) '3', (byte) '4', // PIN
                               (byte) 0x00}; // FLAGS
            
            System.out.println("Sending GEN_KEY command...");
            byte[] genResponse = session.transmitCommand(genKeyCmd);
            int genSW = getSW(genResponse);
            System.out.println("GEN_KEY response SW: 0x" + String.format("%04X", genSW));
            
            // Test LIST_KEYS (0x04) 
            byte[] listCmd = {(byte) 0x00, (byte) 0x04, (byte) 0x00, (byte) 0x00, (byte) 0x00};
            System.out.println("\nSending LIST_KEYS command...");
            byte[] listResponse = session.transmitCommand(listCmd);
            int listSW = getSW(listResponse);
            System.out.println("LIST_KEYS response SW: 0x" + String.format("%04X", listSW));
            System.out.println("LIST_KEYS data length: " + (listResponse.length - 2));
            if (listResponse.length > 2) {
                System.out.println("LIST_KEYS mask: 0x" + String.format("%02X", listResponse[0]));
                System.out.println("Slot 0 occupied: " + ((listResponse[0] & 0x01) != 0));
            }
            
            // Test GET_PUBKEY (0x02) for slot 0
            byte[] getPubCmd = {(byte) 0x00, (byte) 0x02, (byte) 0x00, (byte) 0x00, (byte) 0x00};
            System.out.println("\nSending GET_PUBKEY for slot 0...");
            byte[] pubResponse = session.transmitCommand(getPubCmd);
            int pubSW = getSW(pubResponse);
            System.out.println("GET_PUBKEY response SW: 0x" + String.format("%04X", pubSW));
            
        } catch (Exception e) {
            System.out.println("Exception: " + e.getClass().getSimpleName() + ": " + e.getMessage());
            e.printStackTrace();
        }
    }
    
    private static int getSW(byte[] response) {
        if (response.length < 2) return 0;
        return ((response[response.length - 2] & 0xFF) << 8) | 
               (response[response.length - 1] & 0xFF);
    }
}
