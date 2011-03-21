/*
 * Copyright 2007-2008 Sun Microsystems, Inc. All Rights Reserved.
 * DO NOT ALTER OR REMOVE COPYRIGHT NOTICES OR THIS FILE HEADER
 * 
 * This code is free software; you can redistribute it and/or modify
 * it under the terms of the GNU General Public License version 2
 * only, as published by the Free Software Foundation.
 * 
 * This code is distributed in the hope that it will be useful, but
 * WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE. See the GNU
 * General Public License version 2 for more details (a copy is
 * included in the LICENSE file that accompanied this code).
 * 
 * You should have received a copy of the GNU General Public License
 * version 2 along with this work; if not, write to the Free Software
 * Foundation, Inc., 51 Franklin St, Fifth Floor, Boston, MA
 * 02110-1301 USA
 * 
 * Please contact Sun Microsystems, Inc., 16 Network Circle, Menlo
 * Park, CA 94025 or visit www.sun.com if you need additional
 * information or have any questions.
 */

package com.sun.spot.peripheral.ota;

import com.sun.midp.pki.SpotCertStore;
import com.sun.midp.pki.X509Certificate;
import com.sun.spot.util.Utils;
import java.io.ByteArrayOutputStream;
import java.io.DataInputStream;
import java.io.DataOutputStream;
import java.io.IOException;
import com.sun.spot.peripheral.TrustManager;

/**
 *
 * @author vgupta
 */
public class CryptoCommand implements IOTACommand {
    private static final int MAJOR_VERSION     = 1;
    private static final int MINOR_VERSION     = 0;
    
    
    // NOTE: This choice needs to be coordinated with other commands, e.g.
    // look at com.sun.spot.peripheral.ota.OTADefaultCommands.java and
    // any other extensions,
    // e.g. com.sun.spot.peripheral.ota.SpotWorldCommand 
    public static final String GENERATE_SPOT_KEYS_CMD        = "CR-GSK";
    public static final String SET_SPOT_CERT_CMD             = "CR-SSC";
    public static final String DELETE_SPOT_CERT_AND_KEYS_CMD = "CR-DCK";
    public static final String ADD_TRUSTED_KEY_CMD           = "CR-ATK";
    public static final String DELETE_TRUSTED_KEY_CMD        = "CR-DTK";
    public static final String LIST_TRUSTED_KEY_CMD          = "CR-LTK";
    public static final String LIST_TRUSTED_KEYS_CMD         = "CR-LKS";
    public static final String CLEAR_TRUSTED_KEYS_CMD        = "CR-CTK";
    
    /**
     * Security levels: see OTACommandProcessor. Level 2 implies only the
     * SPOT owner can execute this command.
     */
    private static final int SECURITY_LEVEL_REQUIRE_OWNERSHIP = 2;
        
    /** Creates a new instance of CryptoCommand */
    public CryptoCommand() {
    }

    public int getSecurityLevelFor(String command) {
        return SECURITY_LEVEL_REQUIRE_OWNERSHIP;
    }
    
    public boolean processCommand(String command, DataInputStream params,
            IOTACommandHelper helper) throws IOException {
        boolean result = false;
        byte[] encodedResponse = null;
        int idx = 0;
        String failureMsg = null;
        
        if (command.equals(GENERATE_SPOT_KEYS_CMD)) {
            TrustManager tm = TrustManager.getTrustManager();
            
            //generate spot key pair
            byte[] spotPublicKey = null;
            try {
                System.out.println("generating spot keys");
                spotPublicKey = tm.generateSpotKeyPair();
                System.out.println("Flashing ...");
                tm.flashTrustManager();
            } catch (Exception e) {
                System.err.println("generatespotkeys caught " + e);
                e.printStackTrace();
//                helper.sendErrorDetails("Failed: " +
//                        "generatespotkeys caught " + e);
                failureMsg = "Failed: generatespotkeys caught " + 
                        e.getMessage();
            }
        
//            failureMsg = "Failed: " +
//                        "generatespotkeys caught simulated failure.";

            ByteArrayOutputStream baos = new ByteArrayOutputStream();
            DataOutputStream dos = new DataOutputStream(baos);
            
            if (failureMsg != null) {
                System.out.println("Sending failure message: " +
                        failureMsg);
                dos.writeUTF(failureMsg);
                encodedResponse = baos.toByteArray();
                helper.sendData(encodedResponse, 0, 
                        encodedResponse.length);
                helper.sendPrompt();
                result = true;
                return result;
            }
                
            //prepend ieee address used for subject name
            //TODO: support Certificate Signing Requests
            String subjectName = System.getProperty("IEEE_ADDRESS");
            dos.writeUTF(subjectName);
            dos.writeShort(spotPublicKey.length);
            dos.write(spotPublicKey);
            encodedResponse = baos.toByteArray();
            
            helper.sendData(encodedResponse, 0, encodedResponse.length);
            helper.sendPrompt();
            result = true; // command was recognized
        }
        
        if (command.equals(SET_SPOT_CERT_CMD)) {
            try {
                byte[] cert = new byte[params.readShort()];
                
                params.readFully(cert);
                setSpotCert(cert);
            } catch (Exception e) {
                System.err.println("setspotcert caught " + e);
                e.printStackTrace();
//                helper.sendErrorDetails("Failed: " +
//                        "setspotcert caught " + e);
                failureMsg = "Failed: setspotcert caught " + e.getMessage();
            }
            
//            failureMsg = "Failed: setspotcert caught simulated failure.";
            
            if (failureMsg == null)
                failureMsg = "OK";
            
            encodedResponse = createResponse(failureMsg);
            helper.sendData(encodedResponse, 0, encodedResponse.length);
            helper.sendPrompt();
            result = true;
        }
        
        if (command.equals(DELETE_SPOT_CERT_AND_KEYS_CMD)) {
            try {
                deleteSpotCertAndKeys();
            } catch (Exception e) {
                System.err.println("deletespotcertandkeys caught " + e);
                e.printStackTrace();
//                helper.sendErrorDetails("Failed: " +
//                        "deletespotcertandkeys caught " + e);
                failureMsg = "Failed: deletespotcertandkeys caught " +
                        e.getMessage();
            }

//            failureMsg = "Failed: deletespotcertandkeys caught simulated " +
//                    "failure.";
            if (failureMsg == null)
                failureMsg = "OK";
            
            encodedResponse = createResponse(failureMsg);
            helper.sendData(encodedResponse, 0, encodedResponse.length);            
            helper.sendPrompt();
            result = true;
        }
        
        if (command.equals(ADD_TRUSTED_KEY_CMD)) {
            try {
                byte[] certBytes = new byte[params.readShort()];
                params.readFully(certBytes);
                String nick = params.readUTF();
                String flags = params.readUTF();
                addTrustedKey(certBytes, nick, flags);
            } catch (Exception e) {
                System.err.println("addtrustedkey caught " + e);
                e.printStackTrace();
//                helper.sendErrorDetails("Failed: " +
//                        "addtrustedkey caught " + e);
                failureMsg = "Failed: addtrustedkey caught " + e.getMessage();
            }
            
//            failureMsg = "Failed: addtrustedkey caught simulated failure.";            
            if (failureMsg == null)
                failureMsg = "OK";
            
            encodedResponse = createResponse(failureMsg);
            helper.sendData(encodedResponse, 0, encodedResponse.length);            
            helper.sendPrompt();
            result = true;
        }
        
        if (command.equals(DELETE_TRUSTED_KEY_CMD)) {
            try {
                String name = params.readUTF();
                if (!deleteTrustedKey(name)) 
                    failureMsg = "Failed: no key found for " + name;
            } catch (Exception e) {
                System.err.println("deletetrustedkey caught " + e);
                e.printStackTrace();
//                helper.sendErrorDetails("Failed: " +
//                        "deletetrustedkey caught " + e);
                failureMsg = "Failed: deletetrustedkey caught " + 
                        e.getMessage();
            }
            
//            failureMsg = "Failed: deletetrustedkey caught simulated failure.";            
            if (failureMsg == null)
                failureMsg = "OK";
            
            encodedResponse = createResponse(failureMsg);
            helper.sendData(encodedResponse, 0, encodedResponse.length);            
            helper.sendPrompt();
            result = true;
        }
        
        if (command.equals(LIST_TRUSTED_KEYS_CMD)) {
            String TMString = null;
            
            try {
                 TMString = TrustManager.getTrustManager().
                         getCertStore().toString();
            } catch (Exception e) {
                System.err.println("listtrustedkeys caught " + e);
                e.printStackTrace();
//                helper.sendErrorDetails("Failed: " +
//                        "deletetrustedkey caught " + e);
                failureMsg = "Failed: listtrustedkeys caught " + 
                        e.getMessage();                
            }

//            failureMsg = "Failed: listtrustedkeys caught simulated failure.";
            if (failureMsg != null) {
                encodedResponse = createResponse(failureMsg);
            } else {                
                encodedResponse = createResponse(TMString);
            }
            
            helper.sendData(encodedResponse, 0, encodedResponse.length);
            helper.sendPrompt();
            result = true;
        }
        
        if (command.equals(LIST_TRUSTED_KEY_CMD)) {            
            String nickname = params.readUTF();
            X509Certificate cert = TrustManager.getTrustManager().
                    getCertStore().getCertByNickname(nickname);
            if (cert == null) {
                encodedResponse = createResponse("Failed: No key " +
                        "found for " + nickname);
            } else {
                encodedResponse = createResponse(cert.toString());
            }    
            
            helper.sendData(encodedResponse, 0, encodedResponse.length);
            helper.sendPrompt();
            result = true;
        }
        
        if (command.equals(CLEAR_TRUSTED_KEYS_CMD)) {
            try {
                TrustManager trustManager = TrustManager.getTrustManager();
                trustManager.getCertStore().clear();
                trustManager.flashTrustManager();
            } catch (Exception e) {
                System.err.println("cleartrustedkeys caught " + e);
                e.printStackTrace();
//                helper.sendErrorDetails("Failed: " +
//                        "cleartrustedkeys caught " + e);
                failureMsg = "Failed: cleartrustedkeys caught " + e.getMessage();
            }

//            failureMsg = "Failed: cleartrustedkeys caught simulated failure.";
            if (failureMsg == null)
                failureMsg = "OK";
            
            encodedResponse = createResponse(failureMsg);
            helper.sendData(encodedResponse, 0, encodedResponse.length);            
            helper.sendPrompt();
            result = true;
        }
        
        return result;
    }
    
    private void setSpotCert(byte[] spotCert) throws IOException {
        TrustManager tm = TrustManager.getTrustManager();
        try {
            tm.setSpotCertificate(spotCert);
        } catch (IOException ex) {
            System.err.println("Could not parse certificate");
            throw ex;
        }
        tm.flashTrustManager();
    }
    
    private void deleteSpotCertAndKeys() {
        TrustManager trustManager = TrustManager.getTrustManager();
        trustManager.deleteSpotCert();
        trustManager.deleteSpotKeys();
        trustManager.flashTrustManager();
    }
    
    private void addTrustedKey(byte[] cert, String nickname, String flags)
    throws IOException {
        TrustManager trustManager = TrustManager.getTrustManager();
        SpotCertStore ss = trustManager.getCertStore();
        try {
            ss.addCert(nickname, flags,
                    X509Certificate.generateCertificate(
                    cert, 0, cert.length));
            trustManager.flashTrustManager();
        } catch (Exception e) {
            throw new IOException(e.getMessage());
        }        
    }
    
    private boolean deleteTrustedKey(String nickname) {
        boolean found = false;
        
        TrustManager trustManager = TrustManager.getTrustManager();
        SpotCertStore ss = trustManager.getCertStore();
        found = ss.removeCert(nickname);
        // if not found, no need to reflash trust manager
        if (found)
            trustManager.flashTrustManager();
        
        return found;
    }

    // Creates a byte array containing the version (2 bytes), length (2 bytes),
    // and a string
    private byte[] createResponse(String str) {
        if (str == null) str = "";
        byte[] strbytes = str.getBytes();
        byte[] val = new byte[2 + 2 + strbytes.length];
        int idx = 0;
        
        val[idx++] = MAJOR_VERSION;
        val[idx++] = MINOR_VERSION;
        
        Utils.writeBigEndShort(val, idx, (short) strbytes.length);
        idx += 2;
        System.arraycopy(strbytes, 0, val, idx, strbytes.length);
        idx += strbytes.length;

        return val;       
    }
}
