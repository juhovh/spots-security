/*
 * Copyright 2004-2008 Sun Microsystems, Inc. All Rights Reserved.
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

package test;

import java.math.BigInteger;
import java.security.SecureRandom;
import java.util.Random;

import junit.framework.TestCase;

import com.sun.spot.security.Signature;
import com.sun.spot.security.implementation.RSAPrivateKey;
import com.sun.spot.security.implementation.RSAPublicKey;
import com.sun.spot.security.implementation.Util;
import com.sun.spot.security.implementation.ecc.FFA;
import com.sun.spotx.crypto.Cipher;

/*
 * The main method of this class is called by the bootstrap to start the
 * application.
 * 
 * Edit the main method to start your application.
 * 
 */

public class RSATest extends TestCase {

    private RSAPrivateKey privateKey;

    private RSAPublicKey publicKey;

    public void testSigSHA1() throws Exception {
        System.out.println("Testing SHA1withRSA .... ");
	testSig(1024, "SHA1withRSA");	
    }
    
    public void testExportRestriction() throws Exception {
        System.out.println("Testing export restriction .... ");
	try {
	    testSig(4096, "SHA1withRSA");
	    assertTrue("4096 key should fail", false);
	} catch (RuntimeException ex) {

	}
	try {
	    testSig(1025, "SHA1withRSA");
	    assertTrue("1025 key should fail", false);
	} catch (RuntimeException ex) {

	}
    }

    public void testSigMD5() throws Exception {
        System.out.println("Testing MD5withRSA .... ");
	testSig(1024, "MD5withRSA");
    }

    private void testSig(int bits, String algorithm) throws Exception {

	byte[] message = "Hello World!".getBytes();
	byte[] message2 = "Hello World?".getBytes();
	byte[] signature = new byte[bits / 8/* +200 */];
	boolean match;
	long startTime;
	long endTime;

    System.out.println("Testing RSA signing/verification .... ");
	debug("Creating Key Objects");
	generateKeyPair(bits); // new

	debug("Creating Signature Object");
	startTime = System.currentTimeMillis();
	Signature sig = Signature.getInstance(algorithm);
	sig.initSign(privateKey);
	endTime = System.currentTimeMillis();
	System.out.println("Creating Signature object: "
		+ (endTime - startTime) + " ms.");

	debug("Signing");
	startTime = System.currentTimeMillis();
	sig.update(message, 0, message.length);
	int sigLen = sig.sign(signature, 0, signature.length);
	endTime = System.currentTimeMillis();
	debug("signature: " + Util.hexEncode(signature, sigLen));
	System.out.println("Signing: " + (endTime - startTime) + " ms.");

	sig.initVerify(publicKey);

	debug("Verifying with modified Message");
	sig.update(message2, 0, message2.length);
	match = sig.verify(signature, 0, sigLen);
	assertFalse(match);
	debug("Match: " + match);

	debug("Verifying");
	startTime = System.currentTimeMillis();
	sig.update(message, 0, message.length);
	match = sig.verify(signature, 0, sigLen);
	endTime = System.currentTimeMillis();
	System.out.println("Verification: " + (endTime - startTime) + " ms.");

	assertTrue(match);

	debug("Match: " + match);
    }

    public void generateKeyPair(int bits) {

	Random sr = new SecureRandom();
	BigInteger p = BigInteger.probablePrime(bits / 2, sr);
	BigInteger q = BigInteger.probablePrime(bits / 2, sr);
	BigInteger N = p.multiply(q);
	BigInteger phi =
		(p.subtract(BigInteger.ONE)).multiply(q
			.subtract(BigInteger.ONE));
	BigInteger e;
	do {
	    e = new BigInteger(bits, sr); 
	    // number < phi
	} while ((e.compareTo(phi) >= 0)
		|| (!e.gcd(phi).equals(BigInteger.ONE)));

	BigInteger d = e.modInverse(phi);

	FFA ffa = new FFA(bits);
	byte[] mByte = new byte[ffa.getByteSize()];
	int[] mFFA = ffa.from(N.toString(16));
	ffa.toByteArray(mByte, 0, mByte.length, mFFA);

	byte[] eByte = new byte[ffa.getByteSize()];
	int[] eFFA = ffa.from(e.toString(16));
	ffa.toByteArray(eByte, 0, eByte.length, eFFA);

	publicKey = new RSAPublicKey(mByte, eByte);

	byte[] dByte = new byte[ffa.getByteSize()];
	int[] dFFA = ffa.from(d.toString(16));
	ffa.toByteArray(dByte, 0, dByte.length, dFFA);

	privateKey = new RSAPrivateKey(mByte, dByte);

    }

    public void testRSACipher() throws Exception {

	generateKeyPair(1024);
	byte[] plaintext = "This is just an example".getBytes();
	byte[] ciphertext = new byte[128];
	byte[] result = new byte[plaintext.length];

    System.out.println("Testing RSA encryption/decryption .... ");
	Cipher cipher = Cipher.getInstance("RSA");
	cipher.init(Cipher.ENCRYPT_MODE, publicKey);
	int count =
		cipher.doFinal(plaintext, 0, plaintext.length, ciphertext, 0);

	cipher.init(Cipher.DECRYPT_MODE, privateKey);
	count = cipher.doFinal(ciphertext, 0, ciphertext.length, result, 0);
	for (int j = 0; j < plaintext.length; j++) {
	    assertEquals(result[j], plaintext[j]);
	}
	assertEquals(count, plaintext.length);

	try {
	    ciphertext[1] = (byte) (ciphertext[1] + 1);
	    count = cipher.doFinal(ciphertext, 0, ciphertext.length, result, 0);
	    boolean equals = true;
	    for (int j = 0; j < plaintext.length; j++) {
		if (result[j] != plaintext[j]) {
		    equals = false;
		}
	    }
	    assertFalse(equals);
	    assertEquals(count, plaintext.length);
	} catch (Exception e) {
	}

    }

    private static void debug(String s) {
	System.out.println(s);
    }

}
