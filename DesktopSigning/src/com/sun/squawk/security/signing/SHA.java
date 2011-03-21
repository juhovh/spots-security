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

/*
 * This is a simple port of Steve Reid's SHA-1 code into Java.
 */
public final class SHA {

    /**
         * Message Digest algorithm SHA.
         */
    public static final byte ALG_SHA = 1;

    /*
         * The following array forms the basis for the transform buffer. Update
         * puts bytes into this buffer and then transform adds it into the state
         * of the digest.
         */
    private byte[] buffer = new byte[64];

    private int[] block = new int[16];

    private int index;

    private int[] state = new int[5];

    private long count;

    public SHA() {
	reset();
    }

    /**
         * Gets the message digest algorithm.
         * 
         * @return the algorithm code defined above
         */
    public byte getAlgorithm() {
	return ALG_SHA;
    }

    /**
         * Returns the byte length of the hash.
         * 
         * @return hash length
         */
    public byte getLength() {
	return 20;
    }

    /**
         * Resets the <code>MessageDigest</code> to the initial state for
         * further use.
         */
    public void reset() {
	/* SHA1 initialization constants */
	state[0] = 0x67452301;
	state[1] = 0xEFCDAB89;
	state[2] = 0x98BADCFE;
	state[3] = 0x10325476;
	state[4] = 0xC3D2E1F0;
	count = 0;
	index = 0;
	/* overwrite sensitive data */
	for (int i = 63; i >= 0; i--)
	    buffer[i] = (byte) 0;
	for (int i = 15; i >= 0; i--)
	    block[i] = 0;
    }

    /*
         * Steve's original code and comments :
         * 
         * blk0() and blk() perform the initial expand. I got the idea of
         * expanding during the round function from SSLeay
         * 
         * #define blk0(i) buffer->l[i] #define blk(i) (buffer->l[i&15] =
         * rol(buffer->l[(i+13)&15]^buffer->l[(i+8)&15] \
         * ^buffer->l[(i+2)&15]^buffer->l[i&15],1))
         * 
         * (R0+R1), R2, R3, R4 are the different operations used in SHA1 #define
         * R0(v,w,x,y,z,i)
         * z+=((w&(x^y))^y)+blk0(i)+0x5A827999+rol(v,5);w=rol(w,30); #define
         * R1(v,w,x,y,z,i)
         * z+=((w&(x^y))^y)+blk(i)+0x5A827999+rol(v,5);w=rol(w,30); #define
         * R2(v,w,x,y,z,i) z+=(w^x^y)+blk(i)+0x6ED9EBA1+rol(v,5);w=rol(w,30);
         * #define R3(v,w,x,y,z,i)
         * z+=(((w|x)&y)|(w&x))+blk(i)+0x8F1BBCDC+rol(v,5);w=rol(w,30); #define
         * R4(v,w,x,y,z,i) z+=(w^x^y)+blk(i)+0xCA62C1D6+rol(v,5);w=rol(w,30);
         */

    private final int expand(int i) {
	if (i < 16) {
	    return block[i];
	} else {
	    int tmp =
		    block[(i + 13) & 15] ^ block[(i + 8) & 15]
			    ^ block[(i + 2) & 15] ^ block[i & 15];
	    tmp = (tmp << 1) | (tmp >>> 31);
	    block[i & 15] = tmp;
	    return tmp;
	}
    }

    /**
         * Hash a single 512-bit buffer. This is the core of the algorithm.
         * 
         * Note that working with arrays is very inefficent in Java as it does a
         * class cast check each time you store into the array.
         * 
         */
    private void transform(byte[] bblock, int offset) {
	int i, j;
	int tmp;

	for (i = 0, j = offset; j < offset + 64; i++, j += 4) {
	    block[i] =
		    ((bblock[j] & 0xff) << 24) | ((bblock[j + 1] & 0xff) << 16)
			    | ((bblock[j + 2] & 0xff) << 8)
			    | ((bblock[j + 3] & 0xff));
	}

	/* Copy context->state[] to working vars */
	int v = state[0];
	int w = state[1];
	int x = state[2];
	int y = state[3];
	int z = state[4];

	/* 4 rounds of 20 operations each. */
	i = 0;
	for (; i < 20; i++) {
	    z +=
		    ((w & (x ^ y)) ^ y) + expand(i) + 0x5A827999
			    + ((v << 5) | (v >>> 27));
	    tmp = z;
	    z = y;
	    y = x;
	    x = (w << 30) | (w >>> 2);
	    w = v;
	    v = tmp;
	}
	for (; i < 40; i++) {
	    z += (w ^ x ^ y) + expand(i) + 0x6ED9EBA1 + ((v << 5) | (v >>> 27));
	    tmp = z;
	    z = y;
	    y = x;
	    x = (w << 30) | (w >>> 2);
	    w = v;
	    v = tmp;
	}
	for (; i < 60; i++) {
	    z +=
		    (((w | x) & y) | (w & x)) + expand(i) + 0x8F1BBCDC
			    + ((v << 5) | (v >>> 27));
	    tmp = z;
	    z = y;
	    y = x;
	    x = (w << 30) | (w >>> 2);
	    w = v;
	    v = tmp;
	}
	for (; i < 80; i++) {
	    z += (w ^ x ^ y) + expand(i) + 0xCA62C1D6 + ((v << 5) | (v >>> 27));
	    tmp = z;
	    z = y;
	    y = x;
	    x = (w << 30) | (w >>> 2);
	    w = v;
	    v = tmp;
	}

	/* Add the working vars back into context.state[] */
	state[0] += v;
	state[1] += w;
	state[2] += x;
	state[3] += y;
	state[4] += z;
    }

    /**
         * Accumulates a hash of the input data. This method requires temporary
         * storage of intermediate results. In addition, if the input data
         * length is not block aligned (multiple of block size) then additional
         * internal storage may be allocated at this time to store a partial
         * input data block. This may result in additional resource consumption
         * and/or slow performance. This method should only be used if all the
         * input data required for the hash is not available in one byte array.
         * If all of the input data required for the hash is located in a single
         * byte array, use of the <code>doFinal()</code> method is
         * recommended. The <code>doFinal()</code> method must be called to
         * complete processing of input data accumulated by one or more calls to
         * the <code>update()</code> method.
         * <p>
         * Note:
         * <ul>
         * <li>If <code>inLength</code> is 0 this method does nothing.</li>
         * </ul>
         * 
         * @param input
         *                the input buffer of data to be hashed
         * @param offset
         *                the offset into the input buffer at which to begin
         *                hash generation
         * @param length
         *                the byte length to hash
         * 
         * @see #doFinal(byte[], int, int, byte[], int)
         */

    public void update(byte[] input, int offset, int len) {
	int partLen;

	// Update number of bits
	count += (len << 3);

	// If there is already something in the buffer, append the new data.
	if (index > 0) {
	    partLen = 64 - index;
	    if (partLen > len)
		partLen = len;
	    System.arraycopy(input, offset, buffer, index, partLen);
	    offset += partLen;
	    len -= partLen;
	    index += partLen;
	    if (index == 64) {
		transform(buffer, 0);
		index = 0;
	    }
	}

	// Process complete blocks directly from the input-array as long as
	// possible.
	while (len >= 64) {
	    transform(input, offset);
	    offset += 64;
	    len -= 64;
	}

	// If there is some unprocessed data left, copy it to the buffer.
	if (len > 0) {
	    System.arraycopy(input, offset, buffer, 0, len);
	    index = len;
	}
    }

    /**
         * Generates a hash of all/last input data. Completes and returns the
         * hash computation after performing final operations such as padding.
         * The <code>MessageDigest</code> object is reset to the initial state
         * after this call is made.
         * <p>
         * The input and output buffer data may overlap.
         * 
         * @param inBuf
         *                the input buffer of data to be hashed
         * @param inOff
         *                the offset into the input buffer at which to begin
         *                hash generation
         * @param inLen
         *                the byte length to hash
         * @param outBuf
         *                the output buffer, may be the same as the input buffer
         * @param outOff
         *                the offset into the output buffer where the resulting
         *                hash value begins
         * 
         * @return number of bytes of hash output in <code>outBuff</code>
         */
    public int doFinal(byte[] inBuf, int inOff, int inLen, byte[] outBuf,
	    int outOff) {
	update(inBuf, inOff, inLen);
	int cnt = (outBuf.length > outOff) ? (outBuf.length - outOff) : 0;
	if (cnt == 0)
	    return 0;
	if (cnt > 20)
	    cnt = 20;
	digest(outBuf, outOff, cnt);
	reset();
	return cnt;
    }

    /**
         * Complete processing on the message digest.
         */
    private void digest(byte[] outBuf, int outOff, int len) {
	int shift;
	int i = index;

	buffer[i++] = (byte) 128;

	if (i > 56) {
	    while (i < 64) {
		buffer[i++] = (byte) 0;
	    }
	    transform(buffer, 0);
	    i = 0;
	}
	while (i < 56) {
	    buffer[i++] = (byte) 0;
	}
	buffer[56] = (byte) (count >>> 56);
	buffer[57] = (byte) (count >>> 48);
	buffer[58] = (byte) (count >>> 40);
	buffer[59] = (byte) (count >>> 32);
	buffer[60] = (byte) (count >>> 24);
	buffer[61] = (byte) (count >>> 16);
	buffer[62] = (byte) (count >>> 8);
	buffer[63] = (byte) (count);
	transform(buffer, 0);

	shift = 24;
	for (i = 0; i < len; i++) {
	    outBuf[outOff++] = (byte) (state[i >> 2] >> shift);
	    if ((shift -= 8) < 0) {
		shift = 24;
	    }
	}
    }

}
