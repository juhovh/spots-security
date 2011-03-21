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

import com.sun.spot.security.implementation.Util;
import com.sun.spotx.crypto.Cipher;
import com.sun.spotx.crypto.spec.SecretKeySpec;




public class ARCFOURTest extends TestCase {

    /*
     * ARC4 tests vectors from OpenSSL (crypto/rc4/rc4test.c)
     */

    private static final String[] arc4keys = {
        "0123456789abcdef",
        "0123456789abcdef",
        "0000000000000000",
        "ef012345",
        "0123456789abcdef",
        "ef012345"
    };

    private static final String[] arc4plain = {
        "0123456789abcdef",
        "0000000000000000",
        "0000000000000000",
        "0000000000000000000000000000000000000000",
        "123456789ABCDEF0123456789ABCDEF0123456789ABCDEF012345678",
        "00000000000000000000",
        ""
    };

    private static final String[] arc4cipher = {
        "75b7878099e0c596",
        "7494c2e7104b0879",
        "de188941a3375d3a",
        "d6a141a7ec3c38dfbd615a1162e1c7ba36b67858",
        "66a0949f8af7d6891f7f832ba833c00c892ebe30143ce28740011ecf",
        "d6a141a7ec3c38dfbd61",
        ""
    };
    

    private static void doTest(String cipherString, String[] keys, String[] plainText, String[] cipherText) throws Exception {
        byte[] result = new byte[64];
        boolean passed = true;
        String failed = null;
        int i;
        
        Cipher cipher=Cipher.getInstance(cipherString);
        for (i = 0; i < keys.length; i++) {
            byte[] pt = Util.hexDecode(plainText[i]);            
            byte[] ct = Util.hexDecode(cipherText[i]);
            byte[] k = Util.hexDecode(keys[i]);
            
            
            SecretKeySpec key = 
			new SecretKeySpec(k,0,k.length,cipherString); 

                        cipher.init(Cipher.ENCRYPT_MODE, key);
            cipher.doFinal(pt, 0, pt.length, result, 0);

            for (int j=0;j<ct.length;j++) {
    		assertEquals(result[j],ct[j]);
    	    }
            cipher.init(Cipher.DECRYPT_MODE, key);
            cipher.doFinal(ct, 0, ct.length, result, 0);
            
            for (int j=0;j<pt.length;j++) {
    		assertEquals(result[j],pt[j]);
    	    }
            
        }
        
        if (passed) {
            System.out.println("Passed");
        } else {
            System.out.println("Failed Testvector #" + i + " (" + failed + ")");
        }
    }


     
    public void testRC4() throws Exception {
        System.out.println("Testing ARCFOUR .... "); System.out.flush();
        doTest("RC4",
                arc4keys, arc4plain, arc4cipher);
    }
   
}
