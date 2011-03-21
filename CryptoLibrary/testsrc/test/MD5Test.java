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

import com.sun.spot.security.MessageDigest;
import com.sun.spot.security.implementation.Util;


public class MD5Test extends TestCase {

    
//  test vectors
    private static final String[] testVectorHexString = {
        "",
        "61",
        "616263",
        "6162636465666768696a6b6c6d6e6f707172737475767778797a"
    };
    
    
    
    
    // MD5-digests
    private static final String[] md5TestVectorHexString = {
        "d41d8cd98f00b204e9800998ecf8427e",
        "0cc175b9c0f1b6a831c399e269772661",
        "900150983cd24fb0d6963f7d28e17f72",
        "c3fcd3d76192e4007dfb496cca67e13b"
    };
   
       private MessageDigest md5;

  
    protected void setUp() throws Exception {
	super.setUp();
	md5=MessageDigest.getInstance("md5");
	//md5=new MD5();	
    }

    protected void tearDown() throws Exception {
	super.tearDown();
    }

    public void testGetAlgorithm() {
        System.out.println("Testing MD5 getAlgorithm .... ");
	assertEquals("MD5", md5.getAlgorithm());
	
    }

    public void testGetLength() {
        System.out.println("Testing MD5 getDigestLength .... ");
	assertEquals(16, md5.getDigestLength());
    }

    public void testMD5() throws Exception {
	byte [] digest=new byte[md5.getDigestLength()];
	
	System.out.println("Testing MD5 .... ");
	for (int i=0;i<testVectorHexString.length;i++) {
	
	    byte[] testVector = Util.hexDecode(testVectorHexString[i]);
	    byte[] md5TestVector = Util.hexDecode(md5TestVectorHexString[i]);
	    md5.update(testVector, 0, testVector.length);
	    md5.digest(digest, 0, digest.length);
	    for (int j=0;j<md5TestVector.length;j++) {
	    assertEquals(digest[j],md5TestVector[j]);
	}
	
	
	
	}	
    }
}
