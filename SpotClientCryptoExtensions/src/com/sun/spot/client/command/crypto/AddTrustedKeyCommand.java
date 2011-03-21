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
import java.io.File;
import java.io.FileInputStream;
import java.io.IOException;
import java.io.InputStream;

import com.sun.spot.client.IAdminTarget;
import com.sun.spot.client.ISpotClientCommandHelper;
import com.sun.spot.client.command.AbstractClientCommand;
import com.sun.midp.pki.SpotCertStore;
import java.io.DataOutputStream;

public class AddTrustedKeyCommand extends AbstractClientCommand {
    public AddTrustedKeyCommand() {
    }
    
    public Object execute(ISpotClientCommandHelper helper, 
            String certPath, String nickname, String trustFlags) 
            throws IOException {
        Object retVal = null;
                
        if (nickname.equals(SpotCertStore.PERSONAL_CERT_NICKNAME)) {
            throw new IOException("The nickname <" +
                    SpotCertStore.PERSONAL_CERT_NICKNAME + "> is reserved.");
        }
        File file = new File(certPath);
        InputStream in = new FileInputStream(file);
        byte[] certBytes = new byte[(int)file.length()];
        in.read(certBytes);        
        retVal = execute(helper, certBytes, nickname, trustFlags);
       
        return retVal;
    }
 
    public Object execute(ISpotClientCommandHelper helper,
            byte[] certBytes, String nickname, String trustFlags)
            throws IOException {
        byte responseBytes[] = null;
        IAdminTarget at = helper.getAdminTarget();
        Object retVal = null;
        
        ByteArrayOutputStream baos = new ByteArrayOutputStream();
        DataOutputStream dos = new DataOutputStream(baos);
        dos.writeShort(certBytes.length);
        dos.write(certBytes, 0, certBytes.length);
        dos.writeUTF(nickname);
        dos.writeUTF(trustFlags);
        at.sendAdminCommand(SpotClientCryptoExtension.ADD_TRUSTED_KEY_CMD, baos.toByteArray());

        int responseLength = at.getDataInputStream().readInt();
        responseBytes = new byte[responseLength];
        at.getDataInputStream().readFully(responseBytes, 0, responseLength);
        at.checkResponse();
        try {
            retVal = SpotClientCryptoExtension.parseString(responseBytes);
        } catch (Exception ex) {
            throw new IOException("AddTrustedKeyCommand: could not parse " +
                    "response (" + ex + ")\n" +
                    "Response (" + responseBytes.length +
                    " bytes): " + new String(responseBytes));
        }

        if (((String) retVal).startsWith("Fail")) {
            throw new IOException("AddTrustedKeyCommand " + retVal);
        }
        return retVal;
    }

    public int getSignature() {
        return SIGNATURE_THREE_STRINGS;
    }

    public String getName() {
        return "addtrustedkey";
    }
    
    public String getUsage() {
        return "addtrustedkey certpath nickname trustflags  -- add the given key to the SPOTs keystore";
    }
}
