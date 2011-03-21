/*
 * Copyright 2006-2008 Sun Microsystems, Inc. All Rights Reserved.
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

package com.sun.spot.client.command.crypto;

import java.io.ByteArrayInputStream;
import java.io.ByteArrayOutputStream;
import java.io.DataInputStream;
import java.io.IOException;

import com.sun.midp.pki.KeySerializer;
import com.sun.spot.security.implementation.ECPublicKeyImpl;
import com.sun.squawk.security.ECPublicKey;
import com.sun.squawk.security.signing.SigningService;

import com.sun.spot.client.IAdminTarget;
import com.sun.spot.client.ISpotClientCommandHelper;
import com.sun.spot.client.command.AbstractClientCommand;
import java.io.DataOutputStream;



public class GenSpotKeysNCertCommand extends AbstractClientCommand {
    public GenSpotKeysNCertCommand() {
    }
    
    public Object execute(ISpotClientCommandHelper helper) 
            throws IOException {
        byte[] responseBytes = null;
        IAdminTarget at = helper.getAdminTarget();
        Object retVal = null;
        
        at.sendAdminCommand(SpotClientCryptoExtension.GENERATE_SPOT_KEYS_CMD);
        int responseLength = at.getDataInputStream().readInt();
        responseBytes = new byte[responseLength];
        at.getDataInputStream().readFully(responseBytes, 0, responseLength);
        
        // parse the IEEE address and raw key from the response
        DataInputStream dis = new DataInputStream(new 
                ByteArrayInputStream(responseBytes));
        String ieeeAddr = dis.readUTF();
        
        if (ieeeAddr.startsWith("Fail"))
            throw new IOException("GenSpotKeysNCertCommand " + ieeeAddr);
        
        int len = dis.readShort();
        byte[] rawSpotPublicKey = new byte[len];
        dis.readFully(rawSpotPublicKey);
        at.checkResponse();
        
        ECPublicKeyImpl pubKey;
        byte[] w = new byte[len]; // w should be less than the raw key length
        try {
            pubKey = (ECPublicKeyImpl) KeySerializer.deserialize(
                    rawSpotPublicKey, 0);
            len = pubKey.getW(w, 0);
        } catch (Exception e) {
            e.printStackTrace();
            throw new IOException("GenSpotKeysNCertCommand encountered " +
                    "problems receiving the SPOT's public key. " + 
                    e.getMessage());
        }
        
        ECPublicKey pub = new ECPublicKey();
        pub.setW(w, 0, len);
        byte[] spotCert;
        try {
            spotCert = SigningService.getInstance().
                    mkECCertBytes(ieeeAddr, pub);
        } catch (Exception e) {
            e.printStackTrace();
            throw new IOException("GenSpotKeysNCertCommand could not create" +
                    " and ECC certificate. " + e.getMessage());
        }
        
        ByteArrayOutputStream baos = new ByteArrayOutputStream();
        DataOutputStream dos = new DataOutputStream(baos);
        dos.writeShort(spotCert.length);
        dos.write(spotCert, 0, spotCert.length);
        at.sendAdminCommand(SpotClientCryptoExtension.
                SET_SPOT_CERT_CMD, baos.toByteArray());
        
        responseLength = at.getDataInputStream().readInt();
        responseBytes = new byte[responseLength];
        at.getDataInputStream().readFully(responseBytes, 0, responseLength);
        at.checkResponse();
        try {
            retVal = SpotClientCryptoExtension.parseString(responseBytes);
        } catch(Exception ex) {
            throw new IOException("GenSpotKeysNCertCommand: could not parse " +
                    "response (" + ex + ")\n" +
                    "Response (" + responseBytes.length + 
                    " bytes): " + new String(responseBytes));
        }
        
        if (((String) retVal).startsWith("Fail"))
            throw new IOException("GenSpotKeysNCertCommand " + retVal);
        
        return retVal;
    }

    public int getSignature() {
        return SIGNATURE_NOTHING;
    }

    public String getName() {
        return "genspotkeysncert";
    }
    
    public String getUsage() {
        return "genspotkeysncert -- generate spot-specific key pair and " +
                "install a certificate signed by the owner";             
    }
}
