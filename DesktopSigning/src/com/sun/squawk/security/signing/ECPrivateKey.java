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

import java.security.Signature;

import javax.crypto.KeyAgreement;

import com.sun.squawk.security.CryptoException;
import com.sun.squawk.security.ECPublicKey;
import com.sun.squawk.security.ecc.ECCurveFp;
import com.sun.squawk.security.ecc.FFA;

/**
 * The <code>ECPrivateKey</code> interface is used to generate signatures on
 * data using the ECDSA (Elliptic Curve Digital Signature Algorithm) and to
 * generate shared secrets using the ECDH (Elliptic Curve Diffie-Hellman)
 * algorithm. An implementation of <code>ECPrivateKey</code> interface must
 * also implement the <code>ECKey</code> interface methods.
 * <p>
 * When the component of the key (S) is set, the key is initialized and ready
 * for use.
 * <p>
 * The notation used to describe parameters specific to the EC algorithm is
 * based on the naming conventions established in [IEEE P1363].
 * 
 * @see ECPublicKey
 * @see Signature
 * @see KeyAgreement
 */
public final class ECPrivateKey {
    /**
         * <code>Key</code> object which implements the interface type
         * <code>ECPrivateKey</code> for EC operations over large prime
         * fields.
         */

    /** Key size in bits */
    protected int bitsize;

    protected int bytesize;

    /** Flag indicating if the key has been initialized. */
    protected boolean initOk;

    protected ECCurveFp curve;

    protected FFA ffa;

    protected int[] keyData;

    protected int keyLength; // actual length of the key (current data)

    public ECPrivateKey() {
	curve = ECCurveFp.getInstance();
	ffa = curve.getOrder().getFFA();
	bitsize = ffa.getBitSize();
	bytesize = (bitsize + 7) >>> 3;
	keyData = ffa.acquireVar();
    }

    /**
         * Sets the value of the secret key. The plain text data format is
         * big-endian and right-aligned (the least significant bit is the least
         * significant bit of last byte). Input parameter data is copied into
         * the internal representation.
         * 
         * @param buffer
         *                the input buffer
         * @param offset
         *                the offset into the input buffer at which the secret
         *                value is to begin
         * @param length
         *                the byte length of the secret value
         * @throws javacard.security.CryptoException
         *                 with the following reason code:
         *                 <ul>
         *                 <li><code>CryptoException.ILLEGAL_VALUE</code> if
         *                 the input key data is inconsistent with the elliptic
         *                 curve.</li>
         *                 </ul>
         */
    public void setS(byte[] buffer, int offset, int length)
	    throws CryptoException {
	initOk = false;
	ffa.from(keyData, buffer, offset, length);
	if ((ffa.is(keyData, 0))
		|| (ffa.cmp(keyData, curve.getOrder().getP()) >= 0)) {
	    CryptoException.throwIt(CryptoException.ILLEGAL_VALUE);
	}
	keyLength = (ffa.bitLength(keyData) + 7) >>> 3;
	initOk = true;
    }

    /**
         * Returns the point of the curve comprising the public key in plain
         * text form. The point is represented as an octet string in compressed
         * or uncompressed forms as per ANSI X9.62. The data format is
         * big-endian and right-aligned (the least significant bit is the least
         * significant bit of last byte).
         * 
         * @param buffer
         *                the output buffer
         * @param offset
         *                the offset into the output buffer at which the point
         *                specification data is to begin
         * @return the byte length of the point specificiation
         * @throws com.sun.squawk.security.signing.CryptoException
         *                 with the following reason code:
         *                 <ul>
         *                 <li><code>CryptoException.UNINITIALIZED_KEY</code>
         *                 if the point of the curve comprising the public key
         *                 has not been successfully initialized since the time
         *                 the initialized state of the key was set to false.</li>
         *                 </ul>
         */
    public int getS(byte[] buffer, int offset) throws CryptoException {
	if (!initOk) {
	    CryptoException.throwIt(CryptoException.UNINITIALIZED_KEY);
	}
	ffa.toByteArray(buffer, offset, keyLength, keyData);
	return keyLength;
    }

    /**
         * Clears the key
         */
    public void clearKey() {
	initOk = false;
	for (int i = keyData.length - 1; i >= 0; i--) {
	    keyData[i] = 0;
	}
    }

    /**
         * @return true if the key is initialized
         */
    public boolean isInitialized() {
	return initOk;
    }

    /**
         * @return the curve associated with the key
         */
    public ECCurveFp getCurve() {
	return curve;
    }

    /**
         * @return internal representation of the key
         */
    public int[] getKeyData() {
	return keyData;
    }

    /**
         * @return Size of the key in bits
         */
    public int getSize() {
	return bitsize;
    }
}
