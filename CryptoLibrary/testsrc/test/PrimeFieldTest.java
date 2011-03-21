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
import com.sun.spot.security.implementation.ecc.PrimeField;

/*
 * The main method of this class is called by the bootstrap to start the
 * application.
 * 
 * Edit the main method to start your application.
 * 
 */

public class PrimeFieldTest extends TestCase {

    public void testSquare() throws Exception {
	testSquare(161, 100);
	testSquare(1024, 100);
	// testSquareReuseArray(1024, 1000);
    }

    public void testPow() throws Exception {
	long start = System.currentTimeMillis();
	int n = 1;
	int m = 1;
	for (int i = 0; i < n; i++) {
	    testPow(1024, m);
	}
	long time = System.currentTimeMillis() - start;
	System.out
		.println("time for "+n*m+" pow operations. (variable reuse for each m operations), "
			+ time / 1000.0 + " s");
    }

    public void testMul() throws Exception {
	long start = System.currentTimeMillis();
	int n = 1000;
	int m = 1;
	for (int i = 0; i < n; i++) {
	    testMul(1024, m);
	}
	long time = System.currentTimeMillis() - start;
	System.out
		.println("time for (n*m) mul operations. (variable reuse for each m operations), "
			+ time / 1000.0 + " s");
    }


    private void testMul(int bits, int n) throws Exception {
	FFA ffa = new FFA(bits);
	for (int i = 0; i < n; i++) {
	    SecureRandom se = new SecureRandom();
	    BigInteger a = new BigInteger(bits, se);
	    BigInteger m = new BigInteger(bits, se);
	    BigInteger b = new BigInteger(bits, se);

	    int[] mFFA = ffa.from(m.toString(16));
	    int[] aFFA = ffa.from(a.toString(16));
	    int[] bFFA = ffa.from(b.toString(16));
	    int[] rFFA = ffa.acquireVar();

	    PrimeField primeField = new PrimeField(ffa, mFFA);

	    primeField.multiply(rFFA, aFFA, bFFA);

	    BigInteger resultFFA = new BigInteger(ffa.toString(rFFA), 16);
	    BigInteger result = a.multiply(b).mod(m);
	    assertEquals("testMul (bits=" + bits + ") failed \n" + "\t"
		    + a.toString(16) + "*" + b.toString(16) + " mod "
		    + m.toString(16) + " \n" + "\texpected: "
		    + result.toString(16) + "\n" + "\tffaResult: "
		    + resultFFA.toString(16), resultFFA, result);

	    ffa.releaseVar(aFFA);
	    ffa.releaseVar(bFFA);
	    ffa.releaseVar(mFFA);

	}
    }

    private void testPow(int bits, int n) throws Exception {

	FFA ffa = new FFA(bits);

	for (int i = 0; i < n; i++) {
	    SecureRandom se = new SecureRandom();
	    BigInteger a = new BigInteger(bits, se);
	    BigInteger m = new BigInteger(bits, se);
	    BigInteger e = new BigInteger(bits, se);

	    int[] aFFA = ffa.from(a.toString(16));

	    int[] mFFA = ffa.from(m.toString(16));
	    int[] rFFA = ffa.acquireVar();
	    int[] eFFA = ffa.from(e.toString(16));

	    PrimeField primeField = new PrimeField(ffa, mFFA);

	    primeField.pow(rFFA, aFFA, eFFA);

	    BigInteger resultFFA = new BigInteger(ffa.toString(rFFA), 16);
	    BigInteger result = a.modPow(e, m);
	    assertEquals("Internal error in test",result,result.mod(m));
	    assertEquals("Internal error in test",resultFFA,resultFFA.mod(m));
	    
	    assertEquals("testModPow (bits=" + bits + ") failed \n" + "\t"
		    + a.toString(16) + "^" + e.toString(16) + " mod "
		    + m.toString(16) + " \n" + "\texpected: "
		    + result.toString(16) + "\n" + "\tffaResult: "
		    + resultFFA.toString(16), resultFFA, result);

	    ffa.releaseVar(aFFA);
	    ffa.releaseVar(mFFA);
	    ffa.releaseVar(eFFA);
	}
    }

    private void testSquare(int bits, int n) throws Exception {

	FFA ffa = new FFA(bits);
	for (int i = 0; i < n; i++) {
	    SecureRandom se = new SecureRandom();
	    BigInteger a = new BigInteger(bits, se);

	    BigInteger m = new BigInteger(bits, se);

	    int[] mFFA = ffa.from(m.toString(16));

	    int[] aFFA = ffa.from(a.toString(16));
	    int[] rFFA = ffa.acquireDoubleVar();

	    PrimeField primeField = new PrimeField(ffa, mFFA);

	    primeField.square(rFFA, aFFA);

	    BigInteger resultFFA = new BigInteger(ffa.toString(rFFA), 16);
	    BigInteger result = a.multiply(a).mod(m);
	    assertEquals("testSquare (bits=" + bits + ") failed \n" + "\t"
		    + a.toString(16) + " ^2 mod " + m.toString(16) + "\n"
		    + "\texpected: " + result.toString(16) + "\n"
		    + "\tffaResult: " + resultFFA.toString(16), resultFFA,
		    result);

	    ffa.releaseVar(aFFA);
	    ffa.releaseVar(rFFA);
	    ffa.releaseVar(mFFA);
	}

    }

}
