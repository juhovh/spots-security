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

package com.sun.spot.client.command.crypto;

import java.io.IOException;
import com.sun.spot.client.ISpotClientCommandHelper;
import com.sun.spot.client.command.DeletePublicKeyCommand;

/**
 * DeletePublicKeyCommandForCrypto
 *
 */
public class DeletePublicKeyCommandForCrypto extends DeletePublicKeyCommand {

    public Object execute(ISpotClientCommandHelper helper) throws IOException {
        /* Delete the SPOT's key pair, its own cert and the cert
         * of the "owner" SDK.
         * Since this command is normally called when there is a change
         * in the device ownership, we clear all of the trustedkeys.
         * XXX: This migh be another reason to revisit what happens on upgrade.
         * Perhaps we should not delete the owner key then and have a new 
         * command called restore.
         */
        ClearTrustedKeysCommand clrTrustedKeysCommand =
                (ClearTrustedKeysCommand) helper.getCommand("cleartrustedkeys");
        try {
            clrTrustedKeysCommand.execute(helper);
        } catch (Exception e) {
           System.out.println("Caught " + e.getMessage() + " when executing" +
                   " cleartrustedkeys"); 
        }
        
        DeleteSpotKeysNCertCommand dskcCmd = (DeleteSpotKeysNCertCommand) 
                helper.getCommand("deletespotkeysncert");
        try {
            dskcCmd.execute(helper);
        } catch (Exception e) {
           System.out.println("Caught " + e.getMessage() + " when executing" +
                   " deletespotkeysncert"); 
        }

        // finally do what we would have done in the absence of the crypto 
        // extensions
        return super.execute(helper);
    }

}

