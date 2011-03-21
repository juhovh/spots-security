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

package com.sun.spot.peripheral.ota;


public class CryptoCommandProcessorExtension implements IOTACommandProcessorExtension {
    public void configureCommands(IOTACommandRepository repository) {
        IOTACommand cryptocmd = new CryptoCommand();

        repository.addCommand(CryptoCommand.GENERATE_SPOT_KEYS_CMD, cryptocmd);
        repository.addCommand(CryptoCommand.SET_SPOT_CERT_CMD, cryptocmd);
        repository.addCommand(CryptoCommand.DELETE_SPOT_CERT_AND_KEYS_CMD, cryptocmd);
        repository.addCommand(CryptoCommand.ADD_TRUSTED_KEY_CMD, cryptocmd);
        repository.addCommand(CryptoCommand.DELETE_TRUSTED_KEY_CMD, cryptocmd);
        repository.addCommand(CryptoCommand.LIST_TRUSTED_KEY_CMD, cryptocmd);
        repository.addCommand(CryptoCommand.LIST_TRUSTED_KEYS_CMD, cryptocmd);
        repository.addCommand(CryptoCommand.CLEAR_TRUSTED_KEYS_CMD, cryptocmd);
    }
}
