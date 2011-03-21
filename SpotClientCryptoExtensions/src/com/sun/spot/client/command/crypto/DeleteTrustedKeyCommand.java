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

import java.io.ByteArrayOutputStream;
import java.io.IOException;

import com.sun.spot.client.IAdminTarget;
import com.sun.spot.client.ISpotClientCommandHelper;
import com.sun.spot.client.command.AbstractClientCommand;
import com.sun.midp.pki.SpotCertStore;
import java.io.DataOutputStream;

public class DeleteTrustedKeyCommand extends AbstractClientCommand {
    public DeleteTrustedKeyCommand() {
    }
    
    public Object execute(ISpotClientCommandHelper helper, String nickname) 
            throws IOException {
        byte responseBytes[] = null;
        Object retVal = null;
        IAdminTarget at = helper.getAdminTarget();

        if (nickname.equals(SpotCertStore.PERSONAL_CERT_NICKNAME)) {
            throw new IOException("The nickname <" +
                    SpotCertStore.PERSONAL_CERT_NICKNAME + 
                    "> is reserved. Use the deletespotkeysncert command to " +
                    "delete the SPOT's key-pair and certificate.");
        }

        ByteArrayOutputStream baos = new ByteArrayOutputStream();
        DataOutputStream dos = new DataOutputStream(baos);
        dos.writeUTF(nickname);
        at.sendAdminCommand(SpotClientCryptoExtension.
                DELETE_TRUSTED_KEY_CMD, baos.toByteArray());
        int responseLength = at.getDataInputStream().readInt();
        responseBytes = new byte[responseLength];
        at.getDataInputStream().readFully(responseBytes, 0, responseLength);
        at.checkResponse();
        try {
            retVal = SpotClientCryptoExtension.parseString(responseBytes);
        } catch(Exception ex) {
            throw new IOException("DeleteTrustedKeyCommand: could not parse " +
                    "response (" + ex + ")\n" +
                    "Response (" + responseBytes.length +
                    " bytes): " + new String(responseBytes));
        }
        
        if (((String) retVal).startsWith("Fail"))
            throw new IOException("DeleteTrustedKeyCommand " + retVal);
        
        return retVal;        
    }

    public int getSignature() {
        return SIGNATURE_STRING;
    }

    public String getName() {
        return "deletetrustedkey";
    }
    
    public String getUsage() {
        return "deletetrustedkey nickname -- remove the trusted key " +
                "identified by the nickname from the SPOT's keystore";
    }                       
}
