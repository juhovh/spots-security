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
public final class NIST192PrimeField extends PrimeField {
    
    private static final int BMASK = 0x0fffffff;
    
    private static final int[] p_const =
	{0xFFFFFFFF, 0xFFFFFFFF, 0xFFFFFFFF, 0xFFFFFFFE, 0xFFFFFFFF, 0xFFFFFFFF};
    
    
    
    public NIST192PrimeField(FFA ffa) {
        super(ffa, ffa.from(p_const));
    }
    
    /**
     * Note that this function is FFA implementation specific and expects
     * that only the 28 LS-bits of each integer are used.
     * p = 2^192 - 2^64 - 1
     */
    protected void reduce(int[] r, int[] a) {
        int m;
        int h0, h1, h2, h3, h4, h5, h6;
        int s2, s3, s4, s5, s6, s7, s8, s9;
        
        // align hi
        h6 = ((a[13] << 4) & BMASK) | (a[12] >> 24);
        h5 = ((a[12] << 4) & BMASK) | (a[11] >> 24);
        h4 = ((a[11] << 4) & BMASK) | (a[10] >> 24);
        h3 = ((a[10] << 4) & BMASK) | (a[9]  >> 24);
        h2 = ((a[9]  << 4) & BMASK) | (a[8]  >> 24);
        h1 = ((a[8]  << 4) & BMASK) | (a[7]  >> 24);
        h0 = ((a[7]  << 4) & BMASK) | (a[6]  >> 24);

        // align hi << 64
        s9 =  (h6 >> 20);
        s8 = ((h6 <<  8) & BMASK) | (h5 >> 20);
        s7 = ((h5 <<  8) & BMASK) | (h4 >> 20);
        s6 = ((h4 <<  8) & BMASK) | (h3 >> 20);
        s5 = ((h3 <<  8) & BMASK) | (h2 >> 20);
        s4 = ((h2 <<  8) & BMASK) | (h1 >> 20);
        s3 = ((h1 <<  8) & BMASK) | (h0 >> 20);
        s2 =  (h0 <<  8) & BMASK;

        // hi << 64 is in s9..s2
        // hi is in h6..h0
        // lo is in a[6..0]

        // lo = lo + hi + (hi << 64);
        m  = a[0] + h0;      r[0] = m & BMASK; m >>>= 28;
        m += a[1] + h1;      r[1] = m & BMASK; m >>>= 28;
        m += a[2] + h2 + s2; r[2] = m & BMASK; m >>>= 28;
        m += a[3] + h3 + s3; r[3] = m & BMASK; m >>>= 28;
        m += a[4] + h4 + s4; r[4] = m & BMASK; m >>>= 28;
        m += a[5] + h5 + s5; r[5] = m & BMASK; m >>>= 28;
        m += (a[6] & 0x00ffffff) + h6 + s6; r[6] = m & 0x00ffffff; m >>>= 24;
        m += ((s7 << 4) & BMASK);              h0 = m & BMASK; m >>>= 28;
        m += ((s8 << 4) & BMASK) | (s7 >> 24); h1 = m & BMASK; m >>>= 28;
        m += ((s9 << 4) & BMASK) | (s8 >> 24); h2 = m & BMASK;

        // re-align hi << 64
        s4 = ((h2 <<  8) + (h1 >> 20)) & BMASK;
        s3 = ((h1 <<  8) + (h0 >> 20)) & BMASK;
        s2 =  (h0 <<  8)               & BMASK;

        // finished the first iteration. here the intermediate result
        // is in s4:s2, h3:h0 and r[6..0]

        // lo = lo + hi + (hi << 64);
        m  = r[0] + h0;      r[0] = m & BMASK; m >>>= 28;
        m += r[1] + h1;      r[1] = m & BMASK; m >>>= 28;
        m += r[2] + h2 + s2; r[2] = m & BMASK; m >>>= 28;
        m += r[3] + s3;      r[3] = m & BMASK; m >>>= 28;
        m += r[4] + s4;      r[4] = m & BMASK; m >>>= 28;
        if (m > 0) {
            m += r[5]; r[5] = m & BMASK; m >>>= 28;
            r[6] += m;
        }

        // if r >= prime then r -= prime
        if (ffa.cmp(r, p) >= 0) {
            m  = r[0] + 0x00000001; r[0] = m & BMASK; m >>= 28;
            m += r[1] + 0x00000000; r[1] = m & BMASK; m >>= 28;
            m += r[2] + 0x00000100; r[2] = m & BMASK; m >>= 28;
            if (m > 0) {
                m += r[3]; r[3] = m & BMASK; m >>= 28;
                m += r[4]; r[4] = m & BMASK; m >>= 28;
                m += r[5]; r[5] = m & BMASK; m >>= 28;
                m += r[6]; r[6] = m & 0x00ffffff;
            }
        }
    }
}
