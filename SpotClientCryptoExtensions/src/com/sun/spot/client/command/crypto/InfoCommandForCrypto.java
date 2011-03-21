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
import com.sun.spot.client.ui.InfoCommand;
import com.sun.squawk.security.signing.SigningServiceException;

/**
 * InfoCommandForCrypto
 *
 */
public class InfoCommandForCrypto extends InfoCommand {

    public Object execute(ISpotClientCommandHelper helper) throws IOException {
        super.execute(helper);

        helper.info("");
        helper.info("Keystore:");
        try {
            if (ownerKeysMatch(helper)) {
                try {
                    ListTrustedKeysCommand listTrustedKeysComand = 
                            (ListTrustedKeysCommand) helper.getCommand("listtrustedkeys");
                    String result = (String) listTrustedKeysComand.execute(helper);
                    helper.info("   " + result.replace("\n", "\n   "));
                } catch (IOException e) {
                    helper.info("   Could not get list of trusted keys from SPOT");
                }
            } else {
                helper.info("   Only the owner may view the trusted key store");
            }
        } catch (SigningServiceException e) {
            helper.info("   Error reading host owner key");
        }

        return null;
    }
}
