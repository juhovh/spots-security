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

package com.sun.spot.security.implementation.ecc;


/**
 * This NIST256PrimeField class implements efficient reduction for
 * the prime field with NIST 256-bit reduction modulus. It is used
 * in the SECP256R1 elliptic curve.
 *
 */
public final class NIST224PrimeField extends PrimeField {

    private static final int BMASK = 0x0fffffff;

    private static final int[] p_const =
	{0xFFFFFFFF, 0xFFFFFFFF, 0xFFFFFFFF, 0xFFFFFFFF, 0x00000000, 0x00000000, 0x00000001};



    public NIST224PrimeField(FFA ffa) {
        super(ffa, ffa.from(p_const));
    }

    /**
     * Note that this function is FFA implementation specific and expects
     * that only the 28 LS-bits of each integer are used.
     * p = 2^224 - 2^96 + 1
     */
    protected void reduce(int[] r, int[] a) {
        int m;
        int h0, h1, h2, h3;
        int s3, s4, s5, s6, s7, s8, s9, s10, s11;

        for (int i=0; i<r.length; i++) r[i] = 0;

        // align hi << 96
        s11 =                            (a[15] >> 16);
        s10 = ((a[15] <<  12) & BMASK) | (a[14] >> 16);
        s9 =  ((a[14] <<  12) & BMASK) | (a[13] >> 16);
        s8 =  ((a[13] <<  12) & BMASK) | (a[12] >> 16);
        s7 =  ((a[12] <<  12) & BMASK) | (a[11] >> 16);
        s6 =  ((a[11] <<  12) & BMASK) | (a[10] >> 16);
        s5 =  ((a[10] <<  12) & BMASK) | (a[9]  >> 16);
        s4 =  ((a[9]  <<  12) & BMASK) | (a[8]  >> 16);
        s3 =   (a[8]  <<  12) & BMASK;

        // hi << 64 is in s11..s3
        // hi is in a[15..8]
        // lo is in a[7..0]

        // lo = lo - hi + (hi << 96)
        m = 1;
        m += a[0] + (a[8]  ^ BMASK);      r[0] = m & BMASK; m >>>= 28;
        m += a[1] + (a[9]  ^ BMASK);      r[1] = m & BMASK; m >>>= 28;
        m += a[2] + (a[10] ^ BMASK);      r[2] = m & BMASK; m >>>= 28;
        m += a[3] + (a[11] ^ BMASK) + s3; r[3] = m & BMASK; m >>>= 28;
        m += a[4] + (a[12] ^ BMASK) + s4; r[4] = m & BMASK; m >>>= 28;
        m += a[5] + (a[13] ^ BMASK) + s5; r[5] = m & BMASK; m >>>= 28;
        m += a[6] + (a[14] ^ BMASK) + s6; r[6] = m & BMASK; m >>>= 28;
        m += a[7] + (a[15] ^ BMASK) + s7; r[7] = m & BMASK; m >>>= 28;
        m += BMASK + s8;  h0 = m & BMASK; m >>>= 28;
        m += BMASK + s9;  h1 = m & BMASK; m >>>= 28;
        m += BMASK + s10; h2 = m & BMASK; m >>>= 28;
        m += BMASK + s11; h3 = m & BMASK;

        // re-align hi << 96
        s6 =  ((h3 << 12) & BMASK) | (h2 >> 16);
        s5 =  ((h2 << 12) & BMASK) | (h1 >> 16);
        s4 =  ((h1 << 12) & BMASK) | (h0 >> 16);
        s3 =   (h0 << 12) & BMASK;

        // finished the first iteration. here the intermediate result
        // is in s6:s3, h3:h0 and r[7..0]

        // lo = lo - hi + (hi << 96);
        m = 1;
        m += r[0] + (h0 ^ BMASK);      r[0] = m & BMASK; m >>>= 28;
        m += r[1] + (h1 ^ BMASK);      r[1] = m & BMASK; m >>>= 28;
        m += r[2] + (h2 ^ BMASK);      r[2] = m & BMASK; m >>>= 28;
        m += r[3] + (h3 ^ BMASK) + s3; r[3] = m & BMASK; m >>>= 28;
        m += r[4] + BMASK + s4;        r[4] = m & BMASK; m >>>= 28;
        m += r[5] + BMASK + s5;        r[5] = m & BMASK; m >>>= 28;
        m += r[6] + BMASK + s6;        r[6] = m & BMASK; m >>>= 28;
        m += r[7] + BMASK;             r[7] = m & BMASK;
        
        if (ffa.cmp(r, p) >= 0) {
            int[] tmp2 = ffa.acquireVar();
            System.arraycopy(r, 0, tmp2, 0, r.length);
            ffa.sub(r, tmp2, p);
        }
    }
}