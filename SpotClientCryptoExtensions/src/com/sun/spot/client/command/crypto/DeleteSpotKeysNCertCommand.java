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

import java.io.IOException;

import com.sun.spot.client.IAdminTarget;
import com.sun.spot.client.ISpotClientCommandHelper;
import com.sun.spot.client.command.AbstractClientCommand;

    
public class DeleteSpotKeysNCertCommand extends AbstractClientCommand {
    public DeleteSpotKeysNCertCommand() {
    }
    
    public Object execute(ISpotClientCommandHelper helper) throws IOException {
        byte responseBytes[] = null;
        Object retVal = null;
        IAdminTarget at = helper.getAdminTarget();
        // Utils.log("Executing deletespotkeysncert");
        at.sendAdminCommand(SpotClientCryptoExtension.DELETE_SPOT_CERT_AND_KEYS_CMD);
        int responseLength = at.getDataInputStream().readInt();
        responseBytes = new byte[responseLength];
        at.getDataInputStream().readFully(responseBytes, 0, responseLength);
        at.checkResponse();
        try {
            retVal = SpotClientCryptoExtension.parseString(responseBytes);
        } catch(Exception ex) {
            throw new IOException("DeleteSpotKeysNCertCommand: could not parse " +
                    "response (" + ex + ")\n" +
                    "Response (" + responseBytes.length +
                    " bytes): " + new String(responseBytes));
        }
        
        if (((String) retVal).startsWith("Fail"))
            throw new IOException("DeleteSpotKeysNCertCommand " + retVal);
        
        return retVal;
    }
    
    public int getSignature() {
        return SIGNATURE_NOTHING;
    }
    
    public String getName() {
        return "deletespotkeysncert";
    }
    
    public String getUsage() {
        return "deletespotkeysncert -- delete the SPOT's key-pair and " +
                "certificate";
    }
}
