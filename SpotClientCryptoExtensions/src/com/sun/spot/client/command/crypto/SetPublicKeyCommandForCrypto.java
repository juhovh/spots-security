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
import com.sun.spot.client.SpotClientFailureException;
import com.sun.spot.client.command.SetPublicKeyCommand;
import com.sun.squawk.security.signing.SigningService;
import com.sun.squawk.security.signing.SigningServiceException;

/**
 * SetPublicKeyCommandForCrypto
 *
 */
public class SetPublicKeyCommandForCrypto extends SetPublicKeyCommand {

    public Object execute(ISpotClientCommandHelper helper) throws IOException {
        // do what we already do for setpublickey
        super.execute(helper);

        /* 
         * Nov 29, 2007: genSpotKeysNCert and addTrustedKey work over the
         * air and over a USB connection.
         */
        // in addition, force the SPOT to generate its own key pair
        // (this also gives the SPOT a certificate signed by the "owner" SDK
        GenSpotKeysNCertCommand gskcCmd = 
                (GenSpotKeysNCertCommand) helper.getCommand("genspotkeysncert");
        gskcCmd.execute(helper);
        // ... and add the certificate belonging to the "owner" SDK to the
        // trusted keys store
        AddTrustedKeyCommand addTrustedKeyCommand = 
                (AddTrustedKeyCommand) helper.getCommand("addtrustedkey");
        try {
            addTrustedKeyCommand.execute(helper, 
                    SigningService.getInstance().getCertBytes(), "owner", "o");
        } catch (SigningServiceException e) {
            throw new SpotClientFailureException(e.getMessage());
        }

        return null;
    }
}

