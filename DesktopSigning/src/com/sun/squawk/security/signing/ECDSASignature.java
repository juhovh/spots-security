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
import com.sun.squawk.security.ecc.ECCurveFp;
import com.sun.squawk.security.ecc.ECPoint;
import com.sun.squawk.security.ecc.FFA;
import com.sun.squawk.security.ecc.PrimeField;

/**
 * Signature algorithm <code>ALG_ECDSA_SHA</code> generates a 20-byte SHA
 * digest and signs/verifies the digest using ECDSA. The signature is encoded as
 * an ASN.1 sequence of two INTEGER values, r and s, in that order:<br>
 * <code>SEQUENCE ::= { r INTEGER, s INTEGER }</code>
 */
public class ECDSASignature {

    private SHA digest;

    private ECPrivateKey signKey;

    private ECPublicKey verifyKey;

    private byte[] digestBuf;

    private PrimeField keyCurveOrder = null;

    // Some ASN.1 Syntax and Encoding Info:
    // ECDSA-Sig-Value ::= SEQUENCE {
    // r INTEGER,
    // s INTEGER
    // }
    // Sequence and Integer are encoded as follows:
    // <type id><encoded length><data>
    // type id: single byte for primitives (eg. ASN_INTEGER)
    // encoded length (let b = first byte):
    // if b < 0x80: actual length
    // if b = 0x80: undefined length
    // if b > 0x80: (b & 0x7f) is the number of bytes to follow, that
    // specify the actual length

    private static final byte ASN_CONSTRUCTED = 0x20;

    private static final byte ASN_INTEGER = 2;

    private static final byte ASN_SEQUENCE = 16;

    public ECDSASignature() throws CryptoException {
	digest = new SHA();
	digestBuf = new byte[digest.getLength()];
    }

    /**
         * Returns the byte length of the signature data.
         * 
         * @return the byte length of the signature data
         * 
         * @throws CryptoException
         *                 with the following reason codes:
         *                 <ul>
         *                 <li><code>CryptoException.INVALID_INIT</code> if
         *                 this Signature object is not initialized.</li>
         *                 <li><code>CryptoException.UNINITIALIZED_KEY</code>
         *                 if key not initialized.</li>
         *                 </ul>
         */
    public int getLength() throws CryptoException {
	if (keyCurveOrder == null) {
	    CryptoException.throwIt(CryptoException.INVALID_INIT);
	}

	// The following is save for n smaller than 488 bits.
	// The sequence and both integers have a 2 byte header (type, length)
	int bytelen = (keyCurveOrder.getFFA().getBitSize() >> 3) + 1;
	return 6 + 2 * bytelen;
    }

    /**
         * Initializes the <code>Signature</code> object with the appropriate
         * <code>privateKey</code> in preparation for digital signing.
         * 
         * @param privateKey
         *                the privateKey object to use for signing
         * 
         * @throws CryptoException
         *                 with the following reason codes:
         *                 <ul>
         *                 <li><code>CryptoException.UNINITIALIZED_KEY</code>
         *                 if <code>privateKey</code> instance is uninitialized.</li>
         *                 </ul>
         */
    public void init(ECPrivateKey privateKey) throws CryptoException {
	if (!privateKey.isInitialized()) {
	    CryptoException.throwIt(CryptoException.UNINITIALIZED_KEY);
	}
	signKey = privateKey;
	verifyKey = null;
	keyCurveOrder = privateKey.getCurve().getOrder();

    }

    /**
     * Initializes the <code>Signature</code> object with the appropriate
     * <code>publicKey</code> in preparation for digital signature verification.
     * 
     * @param publicKey
     *                the publicKey object to use for verification
     * 
     * @throws CryptoException
     *                 with the following reason codes:
     *                 <ul>
     *                 <li><code>CryptoException.UNINITIALIZED_KEY</code>
     *                 if <code>publicKey</code> instance is uninitialized.</li>
     *                 </ul>
     */
    public void init(ECPublicKey publicKey) throws CryptoException {
	if (publicKey.initOk == false) {
	    CryptoException.throwIt(CryptoException.UNINITIALIZED_KEY);
	}
	verifyKey = publicKey;
	signKey = null;
	keyCurveOrder = publicKey.getCurve().getOrder();
    }

    /**
         * Generates the signature of all/last input data.
         * <p>
         * A call to this method also resets this <code>Signature</code>
         * object to the state it was in when previously initialized via a call
         * to <code>init()</code>. That is, the object is reset and available
         * to sign another message.
         * <p>
         * Note:
         * <ul>
         * <li>The input and output buffer data may overlap.</li>
         * </ul>
         * 
         * @param inBuff
         *                the input buffer of data to be signed
         * @param inOffset
         *                the offset into the input buffer at which to begin
         *                signature generation
         * @param inLength
         *                the byte length to sign
         * @param sigBuff
         *                the output buffer to store signature data
         * @param sigOffset
         *                the offset into <code>sigBuff</code> at which to
         *                begin signature data
         * 
         * @return number of bytes of signature output in <code>sigBuff</code>
         * 
         * @throws CryptoException
         *                 with the following reason codes:
         *                 <ul>
         *                 <li><code>CryptoException.UNINITIALIZED_KEY</code>
         *                 if key not initialized.</li>
         *                 <li><code>CryptoException.INVALID_INIT</code> if
         *                 this <code>Signature</code> object is not
         *                 initialized or initialized for signature verify mode.</li>
         *                 </ul>
         */
    public int sign(byte[] inBuff, int inOffset, int inLength, byte[] sigBuff,
	    int sigOffset) throws CryptoException {

	// See: ANSI X9.62-1998, 5.3 Signature Generation

	if (signKey == null) {
	    CryptoException.throwIt(CryptoException.INVALID_INIT);
	}
	if (!signKey.isInitialized()) {
	    CryptoException.throwIt(CryptoException.UNINITIALIZED_KEY);
	}

	digest.doFinal(inBuff, inOffset, inLength, digestBuf, 0);

	// We can use the PrimeField class to do all the (mod n) computations
	PrimeField field = signKey.getCurve().getOrder();
	FFA ffa = field.getFFA();

	ECKeyPair keys = new ECKeyPair();

	int[] r = ffa.acquireVar();
	int[] s = ffa.acquireVar();

	int[] e = ffa.acquireVar();
	int[] tmp, k, d;

	do {
	    // Generate a key pair to get the random number 'k' (private
	    // key)
	    // and the x-coordinate of k*G (public key)
	    keys.genKeyPair();

	    tmp = ((ECPublicKey) keys.getPublic()).getKeyData().x;
	    field.trim(r, tmp); // r = x1 mod n

	    tmp = ffa.from(ffa.acquireVar(digestBuf.length * 8), digestBuf, 0,
		    digestBuf.length);
	    field.trim(e, tmp); // e = e mod n

	    k = ffa.adjustLength(((ECPrivateKey) keys.getPrivate())
		    .getKeyData());
	    d = ffa.adjustLength(signKey.getKeyData());

	    field.multiply(s, d, r); // s = d*r (mod n)
	    field.add(s, s, e); // s = e + d*r (mod n)
	    field.invert(k, k);
	    field.multiply(s, s, k); // s = k^-1 * (e + d*r) (mod n)
	    // don't panic: this is so unlikely - it will never loop
	} while (ffa.is(r, 0) || ffa.is(s, 0));

	// System.out.println("e = " + ffa.toString(e));
	// System.out.println("r = " + ffa.toString(r));
	// System.out.println("s = " + ffa.toString(s));

	int rLen = (ffa.bitLength(r) >> 3) + 1;
	int sLen = (ffa.bitLength(s) >> 3) + 1;
	int sequenceLen = 4 + rLen + sLen;

	// TODO: Improve the encoding of lengths to support sequences longer
	// than 127 bytes (save as long as bitLength(n) < 488).
	// See also: getLength()

	// Write sequence header.
	sigBuff[sigOffset++] = ASN_CONSTRUCTED | ASN_SEQUENCE;
	sigBuff[sigOffset++] = (byte) (sequenceLen);

	// Write first integer 'r'
	sigBuff[sigOffset++] = ASN_INTEGER;
	sigBuff[sigOffset++] = (byte) (rLen);
	ffa.toByteArray(sigBuff, sigOffset, rLen, r);
	sigOffset += rLen;

	// Write second integer 's'
	sigBuff[sigOffset++] = ASN_INTEGER;
	sigBuff[sigOffset++] = (byte) (sLen);
	ffa.toByteArray(sigBuff, sigOffset, sLen, s);

	ffa.releaseVar(r);
	ffa.releaseVar(s);
	ffa.releaseVar(e);

	return (sequenceLen + 2);
    }

    /**
         * Accumulates a signature of the input data. This method requires
         * temporary storage of intermediate results. In addition, if the input
         * data length is not block aligned (multiple of block size) then
         * additional internal storage may be allocated at this time to store a
         * partial input data block. This may result in additional resource
         * consumption and/or slow performance. This method should only be used
         * if all the input data required for signing/verifying is not available
         * in one byte array. If all of the input data required for
         * signing/verifying is located in a single byte array, use of the
         * <code>sign()</code> or <code>verify()</code> method is
         * recommended. The <code>sign()</code> or <code>verify()</code>
         * method must be called to complete processing of input data
         * accumulated by one or more calls to the <code>update()</code>
         * method.
         * <p>
         * Note:
         * <ul>
         * <li>If <code>inLength</code> is 0 this method does nothing.</li>
         * </ul>
         * 
         * @param inBuff
         *                the input buffer of data to be signed/verified
         * @param inOffset
         *                the offset into the input buffer at which to begin
         *                signature generation/verification
         * @param inLength
         *                the byte length to sign
         * 
         * @throws CryptoException
         *                 with the following reason codes:
         *                 <ul>
         *                 <li><code>CryptoException.UNINITIALIZED_KEY</code>
         *                 if key not initialized.</li>
         *                 <li><code>CryptoException.INVALID_INIT</code> if
         *                 this <code>Signature</code> object is not
         *                 initialized.</li>
         *                 </ul>
         * 
         * @see #sign(byte[], int, int, byte[], int)
         * @see #verify(byte[], int, int, byte[], int, int)
         */
    public void update(byte[] inBuff, int inOffset, int inLength)
	    throws CryptoException {

	digest.update(inBuff, inOffset, inLength);
    }

    /**
         * Verifies the signature of all/last input data against the passed in
         * signature.
         * <p>
         * A call to this method also resets this <code>Signature</code>
         * object to the state it was in when previously initialized via a call
         * to <code>init()</code>. That is, the object is reset and available
         * to verify another message. In addition, note that the initial
         * vector(IV) used in AES and DES algorithms in CBC mode will be reset
         * to 0.
         * <p>
         * Note:
         * <ul>
         * <li>AES, DES, and triple DES algorithms in CBC mode reset the
         * initial vector(IV) to 0. The initial vector(IV) can be re-initialized
         * using the <code>init(Key, byte, byte[], short, short)</code>
         * method.</li>
         * </ul>
         * 
         * @param inBuff
         *                the input buffer of data to be verified
         * @param inOffset
         *                the offset into the input buffer at which to begin
         *                signature generation
         * @param inLength
         *                the byte length to sign
         * @param sigBuff
         *                the input buffer containing signature data
         * @param sigOffset
         *                the offset into <code>sigBuff</code> where signature
         *                data begins
         * @param sigLength
         *                the byte length of the signature data
         * 
         * @return <code>true</code> if the signature verifies,
         *         <code>false</code> otherwise. Note, if
         *         <code>sigLength</code> is inconsistent with this
         *         <code>Signature</code> algorithm, <code>false</code> is
         *         returned.
         * 
         * @throws CryptoException
         *                 with the following reason codes:
         *                 <ul>
         *                 <li><code>CryptoException.UNINITIALIZED_KEY</code>
         *                 if key not initialized.</li>
         *                 <li><code>CryptoException.INVALID_INIT</code> if
         *                 this <code>Signature</code> object is not
         *                 initialized or initialized for signature sign mode.</li>
         *                 <li><code>CryptoException.ILLEGAL_USE</code> if
         *                 one of the following conditions is met:
         *                 <ul>
         *                 <li>if this <code>Signature</code> algorithm does
         *                 not pad the message and the message is not block
         *                 aligned.</li>
         *                 <li>if this <code>Signature</code> algorithm does
         *                 not pad the message and no input data has been
         *                 provided in <code>inBuff</code> or via the
         *                 <code>update()</code> method.</li>
         *                 </ul>
         *                 </li>
         *                 </ul>
         */
    public boolean verify(byte[] inBuff, int inOffset, int inLength,
	    byte[] sigBuff, int sigOffset, int sigLength)
	    throws CryptoException {

	digest.doFinal(inBuff, inOffset, inLength, digestBuf, 0);
	return verifyMessageDigest(digestBuf, sigBuff, sigOffset, sigLength);

    }

    /**
         * Verifies the signature with an externally computed sha1 hash.
         * 
         * <p>
         * A call to this method also resets this <code>Signature</code>
         * object to the state it was in when previously initialized via a call
         * to <code>init()</code>. That is, the object is reset and available
         * to verify another message. In addition, note that the initial
         * vector(IV) used in AES and DES algorithms in CBC mode will be reset
         * to 0.
         * <p>
         * To use this method Signature.init has to be called before to
         * initialize the key, while calling Signature.update does not have any
         * effect on the result.
         * 
         * <p>
         * Note:
         * <ul>
         * <li>AES, DES, and triple DES algorithms in CBC mode reset the
         * initial vector(IV) to 0. The initial vector(IV) can be re-initialized
         * using the <code>init(Key, byte, byte[], short, short)</code>
         * method.</li>
         * </ul>
         * <p>
         * 
         * @param digestBuf
         *                The externally compute sha1 hash to be verified
         * @param sigBuff
         *                the input buffer containing signature data
         * @param sigOffset
         *                the offset into <code>sigBuff</code> where signature
         *                data begins
         * @param sigLength
         *                the byte length of the signature data
         * 
         * @return <code>true</code> if the signature verifies,
         *         <code>false</code> otherwise. Note, if
         *         <code>sigLength</code> is inconsistent with this
         *         <code>Signature</code> algorithm, <code>false</code> is
         *         returned.
         * 
         * @throws CryptoException
         *                 with the following reason codes:
         *                 <ul>
         *                 <li><code>CryptoException.UNINITIALIZED_KEY</code>
         *                 if key not initialized.</li>
         *                 <li><code>CryptoException.INVALID_INIT</code> if
         *                 this <code>Signature</code> object is not
         *                 initialized or initialized for signature sign mode.</li>
         *                 </ul>
         */
    public boolean verifyMessageDigest(byte[] digestBuf, byte[] sigBuff,
	    int sigOffset, int sigLength) throws CryptoException {

	// See: ANSI X9.62-1998, 5.4 Signature Verification

	if (verifyKey == null) {
	    CryptoException.throwIt(CryptoException.INVALID_INIT);
	}
	if (verifyKey.initOk == false) {
	    CryptoException.throwIt(CryptoException.UNINITIALIZED_KEY);
	}

	// We can use the PrimeField class to do all the (mod n) computations
	ECCurveFp curve = verifyKey.getCurve();
	PrimeField field = curve.getOrder();
	FFA ffa = field.getFFA();

	// check the sequence header
	if ((sigLength < 6)
		|| (sigBuff[sigOffset++] != (ASN_CONSTRUCTED | ASN_SEQUENCE)))
	    return false;
	int sequenceLen = (int) sigBuff[sigOffset++];
	if ((sequenceLen != sigLength - 2) || (sequenceLen < 4))
	    return false;

	// read the first integer: 'r'
	if (sigBuff[sigOffset++] != ASN_INTEGER)
	    return false;
	int len = (int) sigBuff[sigOffset++];
	sequenceLen -= (2 + len);
	if (sequenceLen < 2)
	    return false;
	int[] r = ffa.from(sigBuff, sigOffset, len);
	sigOffset += len;

	// read the second integer: 's'
	if (sigBuff[sigOffset++] != ASN_INTEGER)
	    return false;
	len = (int) sigBuff[sigOffset++];
	sequenceLen -= (2 + len);
	if (sequenceLen != 0)
	    return false;
	int[] s = ffa.from(sigBuff, sigOffset, len);

	// 'r' and 's' must be in the interval [1..n-1]
	int[] n = field.getP();
	if (ffa.is(r, 0) || ffa.is(s, 0) || (ffa.cmp(r, n) >= 0)
		|| (ffa.cmp(s, n) >= 0)) {
	    return false;
	}

	int[] u1 = ffa.acquireVar();
	int[] u2 = ffa.acquireVar();

	int[] tmp = ffa.from(ffa.acquireVar(digestBuf.length * 8), digestBuf,
		0, digestBuf.length);
	field.trim(u1, tmp); // u1 = e mod n

	// System.out.println("e = " + ffa.toString(u1));
	// System.out.println("r = " + ffa.toString(r));
	// System.out.println("s = " + ffa.toString(s));

	field.invert(s, s);
	field.multiply(u1, u1, s); // u1 = (e * s^-1) mod n
	field.multiply(u2, r, s); // u2 = (r * s^-1) mod n

	ECPoint G = curve.getGenerator().clonePoint();
	ECPoint Q = verifyKey.getKeyData().clonePoint();

	curve.multiplySum(G, u1, Q, u2); // G = u1 * G + u2 * Q;

	field.trim(s, G.x); // s = x1 mod n

	boolean verified = (ffa.cmp(r, s) == 0);

	ffa.releaseVar(r);
	ffa.releaseVar(s);
	ffa.releaseVar(u1);
	ffa.releaseVar(u2);
	G.release();
	Q.release();

	return verified;
    }

}
