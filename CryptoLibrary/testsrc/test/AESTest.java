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

import com.sun.spot.security.NoSuchAlgorithmException;
import com.sun.spot.security.implementation.Util;
import com.sun.spotx.crypto.Cipher;
import com.sun.spotx.crypto.NoSuchPaddingException;
import com.sun.spotx.crypto.spec.IvParameterSpec;
import com.sun.spotx.crypto.spec.SecretKeySpec;


public class AESTest extends TestCase {

    /*
     * AES tests vectors from http://csrc.nist.gov/CryptoToolkit/aes/rijndael/
     * ecb_iv.txt - this file also gives intermediate values for each round
     */
    private static final String[] ecbkeys = {
        "000102030405060708090A0B0C0D0E0F",
        "000102030405060708090A0B0C0D0E0F1011121314151617",
        "000102030405060708090A0B0C0D0E0F101112131415161718191A1B1C1D1E1F"
    };

    private static final String[] ecbplain = {
        "000102030405060708090A0B0C0D0E0F",
        "000102030405060708090A0B0C0D0E0F",
        "000102030405060708090A0B0C0D0E0F"
    };

    private static final String[] ecbcipher = {
        "0A940BB5416EF045F1C39458C653EA5A",
        "0060BFFE46834BB8DA5CF9A61FF220AE",
        "5A6E045708FB7196F02E553D02C3A692"
    };

    /*
     * AES-CBC test vectors from RFC 3602
     */
            
    private static final String[] cbckeys = {
        "c286696d887c9aa0611bbb3e2025a45a",
        "56e47a38c5598974bc46903dba290349"
    };

    private static final String[] cbciv = {
        "562e17996d093d28ddb3ba695a2e6f58",
        "8ce82eefbea0da3c44699ed7db51b7d9"
    };
    
    private static final String[] cbcplain = {
        "000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f",
        "a0a1a2a3a4a5a6a7a8a9aaabacadaeafb0b1b2b3b4b5b6b7b8b9babbbcbdbebfc0c1c2c3c4c5c6c7c8c9cacbcccdcecfd0d1d2d3d4d5d6d7d8d9dadbdcdddedf"
    };

    private static final String[] cbccipher = {
        "d296cd94c2cccf8a3a863028b5e1dc0a7586602d253cfff91b8266bea6d61ab1",
        "c30e32ffedc0774e6aff6af0869f71aa0f3af07a9a31a9c684db207eb0ef8e4e35907aa632c3ffdf868bb7b29d3d46ad83ce9f9a102ee99d49a53e87f4c3da55"
    };
    
    


    
    private static void doTest(String cipher, String[] keys, String[] IV, String[] plainText, String[] cipherText) throws Exception {
        byte[] result = new byte[65];

        int i;
        
        Cipher aes=(Cipher)Cipher.getInstance(cipher);
        for (i = 0; i < keys.length; i++) {
            byte[] pt = Util.hexDecode(plainText[i]);            
            byte[] ct = Util.hexDecode(cipherText[i]);
            byte[] k = Util.hexDecode(keys[i]);
            byte[] iv = null;
            if (IV != null) {
                iv = Util.hexDecode(IV[i]);
            }
            
            SecretKeySpec key = new SecretKeySpec(k,0,k.length,cipher); 
            IvParameterSpec ivParameter=null;
            if ((IV!=null)&&(IV[i]!=null)) 
        	ivParameter=new IvParameterSpec(iv,0,iv.length);
            
            aes.init(Cipher.ENCRYPT_MODE, key,ivParameter);
            
            aes.doFinal(pt, 0, pt.length, result, 0);
            
            
    	    for (int j=0;j<ct.length;j++) {
    		assertEquals(result[j],ct[j]);
    	    }
         
    	    aes.init(Cipher.DECRYPT_MODE, key,ivParameter);
            aes.doFinal(ct, 0, ct.length, result, 0);
            
            
            for (int j=0;j<pt.length;j++) {
    		assertEquals(result[j],pt[j]);
    	    }                        
        }
       
    }

    public void testAES_CBC() throws Exception {
        System.out.println("Testing AES-CBC .... "); System.out.flush();
        doTest("AES/CBC/NoPadding",
                cbckeys, cbciv, cbcplain, cbccipher);
    }
    public void testAES_ECB() throws Exception {
        System.out.println("Testing AES-ECB .... "); System.out.flush();
        doTest("AES/ECB/NoPadding",
                 ecbkeys, null, ecbplain, ecbcipher);
                
    }
    
    public void testAES_UnsupportedMode() throws Exception {
        try {
            System.out.println("Testing AES-ECB1 nopadding .... ");
            doTest("AES/ECB1/NoPadding",
        	         ecbkeys, null, ecbplain, ecbcipher);
            assertTrue(false);
        } catch (NoSuchAlgorithmException ex) {            
        }
        
        
    }
    
    public void testAES_NoSuchPadding() throws Exception {
        try {
            System.out.println("Testing AES No such padding .... ");
            doTest("AES/CBC/PKCS5Padding",
        	         cbckeys, cbciv, cbcplain, cbccipher);
            assertTrue(false);
        } catch (NoSuchPaddingException ex) {            
        }
    }
    
    
    
    
}
