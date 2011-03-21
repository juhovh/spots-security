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

import junit.framework.TestCase;

import com.sun.spot.security.implementation.ecc.FFA;

/*
 * The main method of this class is called by the bootstrap to start the
 * application.
 * 
 * Edit the main method to start your application.
 * 
 */

public class FFATest extends TestCase {

    public void testSquare() throws Exception {
	testSquare(161, 100);
	testSquare(1024, 100);
    }

    public void testMod() throws Exception {
	int n = 1000;
	int m = 1;
	for (int i = 0; i < n; i++) {
	    testMod(161, m);
	    testMod(1024, m);
	}
	testModPow(1024, m);
    }

    private void testModPow(int bits, int n) throws Exception {

	FFA ffa = new FFA(bits);
	for (int i = 0; i < n; i++) {
	    SecureRandom se = new SecureRandom();
	    BigInteger a = new BigInteger(bits, se);
	    BigInteger m = new BigInteger(bits, se);
	    BigInteger e = new BigInteger(bits, se);

	    int[] aFFA = ffa.from(a.toString(16));

	    int[] mFFA = ffa.from(m.toString(16));
	    int[] eFFA = ffa.from(e.toString(16));

	    int[] rFFA = ffa.acquireVar();
	    long startTime = System.currentTimeMillis();
	    ffa.modPow(rFFA, aFFA, eFFA, mFFA);
	    long time = System.currentTimeMillis() - startTime;
	    BigInteger resultFFA =
		    new BigInteger(ffa.toString(rFFA), 16).mod(m);
	    BigInteger result = a.modPow(e, m);
	    assertEquals("testModPow (bits=" + bits + ") failed \n" + "\t"
		    + a.toString(16) + "^" + e.toString(16) + " mod "
		    + m.toString(16) + " \n" + "\texpected: "
		    + result.toString(16) + "\n" + "\tffaResult: "
		    + resultFFA.toString(16), resultFFA, result);
	    System.out.println("Time for modPow: (" + bits + "):" + time
		    + " ms");
	    ffa.releaseVar(aFFA);
	    ffa.releaseVar(mFFA);
	}
    }

    private void testMod(int bits, int n) throws Exception {

	FFA ffa = new FFA(bits);
	for (int i = 0; i < n; i++) {
	    SecureRandom se = new SecureRandom();
	    BigInteger a = new BigInteger(bits, se);
	    BigInteger m = new BigInteger(bits, se);

	    int[] aFFA = ffa.from(a.toString(16));

	    int[] mFFA = ffa.from(m.toString(16));

	    ffa.mod(aFFA, mFFA);

	    BigInteger resultFFA = new BigInteger(ffa.toString(aFFA), 16);
	    BigInteger result = a.mod(m);
	    assertEquals("testMod (bits=" + bits + ") failed \n" + "\t"
		    + a.toString(16) + " mod " + m.toString(16) + " \n"
		    + "\texpected: " + result.toString(16) + "\n"
		    + "\tffaResult: " + resultFFA.toString(16), resultFFA,
		    result);

	    ffa.releaseVar(aFFA);
	    ffa.releaseVar(mFFA);
	}
    }

    private void testSquare(int bits, int n) throws Exception {

	FFA ffa = new FFA(bits);
	for (int i = 0; i < n; i++) {
	    SecureRandom se = new SecureRandom();
	    BigInteger a = new BigInteger(bits, se);

	    int[] aFFA = ffa.from(a.toString(16));
	    int[] rFFA = ffa.acquireDoubleVar();

	    ffa.sqr(rFFA, aFFA);

	    BigInteger resultFFA = new BigInteger(ffa.toString(rFFA), 16);
	    BigInteger result = a.multiply(a);
	    assertEquals("testSquare (bits=" + bits + ") failed \n" + "\t"
		    + a.toString(16) + " ^2 \n" + "\texpected: "
		    + result.toString(16) + "\n" + "\tffaResult: "
		    + resultFFA.toString(16), resultFFA, result);

	    ffa.releaseVar(aFFA);
	    ffa.releaseVar(rFFA);
	}
    }
}
