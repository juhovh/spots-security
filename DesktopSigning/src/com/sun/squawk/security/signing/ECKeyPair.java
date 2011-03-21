/*
 * Copyright 2005-2008 Sun Microsystems, Inc. All Rights Reserved.
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

import java.security.PrivateKey;
import java.security.PublicKey;
import java.security.Signature;

import com.sun.squawk.security.ECPublicKey;
import com.sun.squawk.security.ecc.ECCurveFp;
import com.sun.squawk.security.ecc.FFA;

/**
 * This class is a container for a key pair (a public key and a private key). It
 * does not enforce any security, and, when initialized, should be treated like
 * a <code>PrivateKey</code>.
 * <p>
 * In addition, this class features a key generation method.
 * 
 * @see PublicKey
 * @see PrivateKey
 */
public final class ECKeyPair {

    /**
         * <code>KeyPair</code> object containing an EC key pair for EC
         * operations over large prime fields.
         */
    public static final byte ALG_EC_FP = 5;

    private ECPublicKey publicKey;

    private ECPrivateKey privateKey;

    private static int[] mask =
	    { 0x01, 0x03, 0x07, 0x0F, 0x1F, 0x3F, 0x7F, 0xFF };

    /**
         * Constructs a <code>KeyPair</code> instance for the specified
         * algorithm and key length; the encapsulated keys are uninitialized. To
         * initialize the <code>KeyPair</code> instance use the
         * <code>genKeyPair()</code> method.
         * <p>
         * The encapsulated key objects implement the appropriate Key interface
         * associated with the specified algorithm (example -
         * <code>ECPublicKey</code> interface for the public key and
         * <code>ECPrivateKey</code> interface for the private key within an
         * <code>ALG_EC_FP</code> key pair). 
         * 
         * @see Signature
         */

    public ECKeyPair() {
	publicKey = new ECPublicKey();
	privateKey = new ECPrivateKey();

    }

    /**
         * Constructs a new <code>KeyPair</code> object containing the
         * specified public key and private key.
         * <p>
         * Note that this constructor only stores references to the public and
         * private key components in the generated <code>KeyPair</code>
         * object. It does not throw an exception if the key parameter objects
         * are uninitialized.
         * 
         * @param publicKey
         *                the public key
         * @param privateKey
         *                the private key
         */
    public ECKeyPair(ECPublicKey publicKey, ECPrivateKey privateKey) {
	this.publicKey = publicKey;
	this.privateKey = privateKey;
    }

    /**
         * (Re)Initializes the key objects encapsulated in this
         * <code>KeyPair</code> instance with new key values. The initialized
         * public and private key objects encapsulated in this instance will
         * then be suitable for use with the <code>Signature</code>,
         * <code>Cipher</code> and <code>KeyAgreement</code> objects. An
         * internal secure random number generator is used during new key pair
         * generation.
         * 
         */
    public void genKeyPair() {

	// both keys must be initialized with the same curve
	// => as we only support one curve this is always the case

	ECCurveFp curve = privateKey.curve;
	FFA ffa = curve.getOrder().getFFA();
	publicKey.clearKey();
	privateKey.clearKey();

	// generate a random number in the range: 0 < x < field.prime
	PseudoRand random = new PseudoRand();
	int lastBit = curve.getOrder().getBitSize() - 1;
	byte[] priv = new byte[(lastBit >> 3) + 1];

	do {
	    random.generateData(priv, 0, priv.length);
	    priv[0] &= (byte) mask[lastBit % 8];
	    // now 'priv' contains our random number, where bit positions
	    // beginning at the bit length of the prime are masked out.
	    ffa.from(privateKey.keyData, priv, 0, priv.length);
	    // loop until the generated random number is in the desired
	    // range. The worst case probability that this loops is 50%
	} while ((ffa.cmp(privateKey.keyData, curve.getN()) >= 0)
		|| (ffa.is(privateKey.keyData, 0)));

	// generate the public key
	curve.copy(publicKey.getKeyData(), curve.getGenerator());
	curve.multiply(publicKey.getKeyData(), privateKey.keyData);
	privateKey.keyLength = (ffa.bitLength(privateKey.keyData) + 7) >>> 3;

	// both keys are initialized by now
	privateKey.initOk = true;
	publicKey.initOk = true;
    }

    /**
         * Returns a reference to the public key component of this
         * <code>KeyPair</code> object.
         * 
         * @return a reference to the public key
         */
    public ECPublicKey getPublic() {
	return publicKey;
    }

    /**
         * Returns a reference to the private key component of this
         * <code>KeyPair</code> object.
         * 
         * @return a reference to the private key
         */
    public ECPrivateKey getPrivate() {
	return privateKey;
    }

}
