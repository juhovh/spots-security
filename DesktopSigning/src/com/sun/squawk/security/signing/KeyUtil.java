/*
 * Copyright 2000-2008 Sun Microsystems, Inc. All Rights Reserved.
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

package com.sun.squawk.security.signing;

import com.sun.squawk.security.CryptoException;
import com.sun.squawk.security.ECPublicKey;
import com.sun.squawk.security.HexEncoding;

/**
 * The KeyUtil class provides functions to encode and decode ECPublicKeys in the
 * X9.62 encoding.
 * 
 * @author Christian Pühringer
 */
public class KeyUtil {

    /**
         * Encodes a public key using X9.62
         * 
         * @param publicKey
         * @return the public key encoded using X9.62
         * @throws CryptoException
         */
    public static byte[] encodePublicECKeyInX962(ECPublicKey publicKey)
	    throws CryptoException {
	byte[] buffer = new byte[41];
	publicKey.getW(buffer, 0);
	return buffer;
    }

    /**
     * Gets the ECPublicKey from the X9.62 encoding in a byte array
     * 
     * @param publicKeyBA
     *                byte array containing the EC public key in X9.62 
     *                encoding.
     * @param offset  Offset in the byte array where the key starts.
     * @param length  Length of the encoded key. 
     * 
     * @return ECPublicKey the Elliptic curve public key, or null if
     *         publicKeyS is not a valid key
     */
    public static ECPublicKey getPublicECKeyFromX962Encoding(
	    byte[] publicKeyBA, int offset, int length) throws CryptoException {
	ECPublicKey publicKey = new ECPublicKey();
	if (Debug.ENABLED)
	    System.out.println("getPublicECKeyFromX962Encoding:"
		    + HexEncoding.hexEncode(publicKeyBA, publicKeyBA.length));
	publicKey.setW(publicKeyBA, offset, length);
	if (Debug.ENABLED) {
	    byte[] buf = new byte[length];
	    publicKey.getW(buf, 0);
	    System.out.println("getPublicECKeyFromX962Encoding from point:"
		    + HexEncoding.hexEncode(buf, buf.length));
	}

	return publicKey;
    }

    /**
     * Gets the ECPublicKey from the X962 encoding in a byte array
     * 
     * @param publicKeyBA
     *                byte array containing EC public key in X962 encoding.
     * @return ECPublicKey the Elliptic curve public key, or null if
     *         publicKeyS is not a valid key
     */
    public static ECPublicKey getPublicECKeyFromX962Encoding(byte[] publicKeyBA)
	    throws CryptoException {
	return getPublicECKeyFromX962Encoding(publicKeyBA, 0,
		publicKeyBA.length);
    }

    /**
         * gets the ECPublicKey from the X962 encoding in a String
         * 
         * @param publicKeyS
         *                EC public key in X962 encoding. Must be a SEC160r key.
         * @return ECPublicKey the Elliptic curve public key, or null if
         *         publicKeyS is not a valid key
         */
    public static ECPublicKey getPublicECKeyFromX962Encoding(String publicKeyS)
	    throws CryptoException {
	return KeyUtil.getPublicECKeyFromX962Encoding(HexEncoding
		.hexDecode(publicKeyS));
    }

}
