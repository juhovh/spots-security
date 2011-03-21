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

import com.sun.spot.util.Utils;
import com.sun.spot.client.ISpotClientExtension;
import com.sun.spot.client.SpotClientCommands;

/**
 * SpotClientCryptoExtension
 *
 *
 * @author vgupta
 */
public class SpotClientCryptoExtension implements ISpotClientExtension {
    static final int LOWEST_SUPPORTED_MAJOR_VERSION = 1;
    static final int HIGHEST_SUPPORTED_MAJOR_VERSION = 1;

    public static final String GENERATE_SPOT_KEYS_CMD        = "CR-GSK";
    public static final String SET_SPOT_CERT_CMD             = "CR-SSC";
    public static final String DELETE_SPOT_CERT_AND_KEYS_CMD = "CR-DCK";
    public static final String ADD_TRUSTED_KEY_CMD           = "CR-ATK";
    public static final String DELETE_TRUSTED_KEY_CMD        = "CR-DTK";
    public static final String LIST_TRUSTED_KEY_CMD          = "CR-LTK";
    public static final String LIST_TRUSTED_KEYS_CMD         = "CR-LKS";
    public static final String CLEAR_TRUSTED_KEYS_CMD        = "CR-CTK";
    
    public void editCommandRepository(SpotClientCommands commandRepository) {         
        // additions
        commandRepository.addCommand(new GenSpotKeysNCertCommand());
        commandRepository.addCommand(new DeleteSpotKeysNCertCommand());
        commandRepository.addCommand(new AddTrustedKeyCommand());
        commandRepository.addCommand(new DeleteTrustedKeyCommand());
        commandRepository.addCommand(new ClearTrustedKeysCommand());
        commandRepository.addCommand(new ListTrustedKeysCommand());
        commandRepository.addCommand(new ListTrustedKeyCommand());
        
        // replacements
        commandRepository.addCommand(new SetPublicKeyCommandForCrypto());
        commandRepository.addCommand(new DeletePublicKeyCommandForCrypto());
        commandRepository.addCommand(new InfoCommandForCrypto());
    }

    
    static String parseString(byte[] responseBytes) throws Exception {
        if (responseBytes.length < 3) {
            throw new Exception("Response too short");
        }
        
        // first two bytes have version
        int idx = 0;
        int majVer = responseBytes[idx++] & 0xff;
        int minVer = responseBytes[idx++] & 0xff;

        if (majVer < LOWEST_SUPPORTED_MAJOR_VERSION ||
                majVer > HIGHEST_SUPPORTED_MAJOR_VERSION)
            throw new Exception("Unsupported version " + majVer +
                    "." + minVer);
        
        int strlen = 0xffff & Utils.readBigEndShort(responseBytes, idx);
        idx += 2;
        byte[] strbytes = new byte[strlen];
        System.arraycopy(responseBytes, idx, strbytes, 0, strbytes.length);
        idx += strbytes.length;
        
        return new String(strbytes);
    }
}

