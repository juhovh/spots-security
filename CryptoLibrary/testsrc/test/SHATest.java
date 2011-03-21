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

package test;

import junit.framework.TestCase;

import com.sun.spot.security.DigestException;
import com.sun.spot.security.MessageDigest;
import com.sun.spot.security.implementation.Util;


public class SHATest extends TestCase {

    
//  test vectors
    private static final String[] testVectorHexString = {
        "",
        "61",
        "616263",
        "6162636465666768696a6b6c6d6e6f707172737475767778797a"
    };
    
    
    
    // SHA1-digests
    private static final String[] sha1TestVectorHexString = {
        "da39a3ee5e6b4b0d3255bfef95601890afd80709",
        "86f7e437faa5a7fce15d1ddcb9eaeaea377667b8",
        "a9993e364706816aba3e25717850c26c9cd0d89d",
        "32d10c7b8cf96570ca04ce37f2a19d84240d3a89"
    };
       private MessageDigest sha;

  
    protected void setUp() throws Exception {
	super.setUp();
	sha=MessageDigest.getInstance("sha");
	
    }

    protected void tearDown() throws Exception {
	super.tearDown();
    }

    public void testGetAlgorithm() {
        System.out.println("Testing SHA getAlgorithm .... ");
	assertEquals("SHA", sha.getAlgorithm());
	
    }

    public void testGetLength() {
        System.out.println("Testing SHA getDigestLength .... ");
	assertEquals(20, sha.getDigestLength());
    }

    public void testSHA() {
	byte [] digest=new byte[sha.getDigestLength()];
	
	System.out.println("Testing SHA .... ");
	for (int i=0;i<testVectorHexString.length;i++) {
	
	    byte[] testVector = Util.hexDecode(testVectorHexString[i]);
	    byte[] md5TestVector = Util.hexDecode(sha1TestVectorHexString[i]);
	    sha.update(testVector, 0, testVector.length);
	    try {
		sha.digest(digest, 0, digest.length);
	    } catch (DigestException e) {
		e.printStackTrace();
		fail(e.getMessage());
	    }
	    for (int j=0;j<md5TestVector.length;j++) {
	    assertEquals(digest[j],md5TestVector[j]);
	}
	
	
	
	}	
    }
}
