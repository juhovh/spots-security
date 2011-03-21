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



import java.awt.event.KeyListener;
import java.util.Random;

import junit.framework.TestCase;

import com.sun.spot.security.InvalidKeyException;
import com.sun.spot.security.NoSuchAlgorithmException;
import com.sun.spot.security.Signature;
import com.sun.spot.security.SignatureException;
import com.sun.spot.security.implementation.ECKeyImpl;
import com.sun.spot.security.implementation.ECPrivateKeyImpl;
import com.sun.spot.security.implementation.ECPublicKeyImpl;
import com.sun.spot.security.implementation.SecureRandom;
import com.sun.spot.security.implementation.Util;
import com.sun.spotx.crypto.KeyAgreement;



/*
 * The main method of this class is called by the bootstrap to start the application.
 * 
 * Edit the main method to start your application.
 * 
 */

public abstract class ECCTest extends TestCase {
    
   /* public void testECC() throws Exception {
     	long beginTime;
    	long endTime;
    	
    	
    	ECCurve curve = ECCurve.getInstance(ECCurve.SECP160R1);
    	
    	FFA ffa = curve.getField().getFFA();
    	
    	
    	debug("----------------------------------");
    	debug("ECC Point Multiplication");
    	debug("----------------------------------");
    	debug("");
    	
    	
    	// point
    	int[] x = ffa.from("4A96B5688EF573284664698968C38BB913CBFC82");
    	int[] y = ffa.from("23A628553168947D59DCC912042351377AC5FB32");
        
            	
    	// scalar
    	int[] k = ffa.from("53878A943D84957CAE79516A1D94FB61900FF894");
    	
    	debug("Point:");
    	debug("  x = " + ffa.toString(x));
    	debug("  y = " + ffa.toString(y));
    	debug("");

    	debug("Scalar:");
    	debug("  k = " + ffa.toString(k));
    	debug("");

    	debug("Expected Result:");
    	debug("  x = 2252F27C869077D04819F4E7482FD2278B6E5F78".toLowerCase());
    	debug("  y = 48F6DC93782A7D26614160EFFEBB27D2B0C54337".toLowerCase());
    	debug("");
    	
    	// init objects
       	ECPoint point = new ECPoint(curve, x, y);
       	
    	debug("Performing Multiplication...");
    	debug("");
       	
    	// do the multiplication
    	System.gc();
    	Thread.sleep(500);
    	beginTime = System.currentTimeMillis();
    	curve.multiply(point, k);
    	endTime = System.currentTimeMillis();
    	
    	debug("Result:");
    	debug("  x = " + ffa.toString(point.x));
    	debug("  y = " + ffa.toString(point.y));
    	debug("");
    	debug("Time: " + (endTime - beginTime) + " ms");
    	debug("");
    }*/
    
    
    public void testKeyAgreement() throws Exception {
        /*JavaCardKeyPair pair1;
	JavaCardKeyPair pair2;*/
	ECPublicKeyImpl publicKeyAlice = new ECPublicKeyImpl(curveId);
	ECPrivateKeyImpl privateKeyAlice = new ECPrivateKeyImpl(curveId);;
	
	ECPublicKeyImpl publicKeyBob = new ECPublicKeyImpl(curveId);;
	ECPrivateKeyImpl privateKeyBob = new ECPrivateKeyImpl(curveId);;
	
        long startTime;
        long endTime;
        
    	debug("Building Keys");
        
    	
    	/*pair1 = new JavaCardKeyPair(JavaCardKeyPair.ALG_EC_FP, ECKey.SECP160R1);
        pair2 = new JavaCardKeyPair(JavaCardKeyPair.ALG_EC_FP, ECKey.SECP160R1);*/
        
    	debug("Generating Key Pairs");
        
    	/*pair1.genKeyPair();
        pair2.genKeyPair();*/
    	
    	ECKeyImpl.genKeyPair(publicKeyAlice, privateKeyAlice);
    	ECKeyImpl.genKeyPair(publicKeyBob, privateKeyBob);
    	
        
        byte[] public1 = new byte[256*2];
        byte[] public2 = new byte[256*2];
        
        int alicePublicKeyLength = publicKeyAlice.getW(public1, 0);
        
        int bobPublicKeyLength = publicKeyBob.getW(public2, 0);
        
        assertFalse(alicePublicKeyLength==0);
        assertFalse(bobPublicKeyLength==0);
        
        
    	debug("Building KeyAgreements");
        KeyAgreement agr1 = KeyAgreement.getInstance(KeyAgreement.ALG_EC_SVDP_DH);
        KeyAgreement agr2 = KeyAgreement.getInstance(KeyAgreement.ALG_EC_SVDP_DH);
        
        agr1.init(privateKeyAlice);
        agr2.init(privateKeyBob);
        
        byte[] secret1 = new byte[60];
        byte[] secret2 = new byte[60];

    	debug("Generating Secrets");
        startTime = System.currentTimeMillis();
        int bobSecretLength=agr1.generateSecret(public2, 0, bobPublicKeyLength, secret1, 0);
        endTime = System.currentTimeMillis();
        System.out.println("Key agreement1: " + 
                (endTime - startTime) + " ms.");
   
        startTime = System.currentTimeMillis();
        int aliceSecretLength= agr2.generateSecret(public1, 0, alicePublicKeyLength, secret2, 0);
        endTime = System.currentTimeMillis();
        System.out.println("Key agreement2: " + 
                (endTime - startTime) + " ms.");
               
        debug("Secret1: " + Util.hexEncode(secret1,aliceSecretLength));
        debug("Secret2: " + Util.hexEncode(secret2,bobSecretLength));
        
        assertEquals(aliceSecretLength,bobSecretLength);
        assertFalse(aliceSecretLength==0);
        boolean equal = true;
        for (int i = 0; i < aliceSecretLength; i++) {
            if (secret1[i] != secret2[i]) {
                equal = false;
                break;
            }
        }
        assertTrue(equal);
        debug("Match: " + equal);
    }




private ECPublicKeyImpl publicKey;
private ECPrivateKeyImpl privateKey;
private Signature sig;
    
private byte[] message;
//private byte[] message2 = "Hello World?".getBytes();
private byte[] signature = new byte[200];
private int sigLen;


    public void testSigSHA1() throws Exception {
	createNewKeyPair();
	testSig("SHA1WITHECDSA");
	testSig("SHA1WITHECDSA");
    }

    public void testSigMD5() throws Exception {
	createNewKeyPair();	
	testSig("MD5WITHECDSA");
	testSig("MD5WITHECDSA");
    }
    
    public void testSignatureModifiedMessage() throws Exception  {
	testSignatureModifiedMessage("MD5WITHECDSA");
	testSignatureModifiedMessage("SHA1WITHECDSA");
    }
    
    public void testSignatureMessageLength() throws Exception  {
	testSignatureMessageLength("MD5WITHECDSA",1);
	testSignatureMessageLength("MD5WITHECDSA",2);
	testSignatureMessageLength("MD5WITHECDSA",10);
	testSignatureMessageLength("MD5WITHECDSA",100);
	testSignatureMessageLength("MD5WITHECDSA",101);
	testSignatureMessageLength("MD5WITHECDSA",1000);
	testSignatureMessageLength("SHA1WITHECDSA",1);
	testSignatureMessageLength("SHA1WITHECDSA",2);
	testSignatureMessageLength("SHA1WITHECDSA",10);
	testSignatureMessageLength("SHA1WITHECDSA",100);
	testSignatureMessageLength("SHA1WITHECDSA",101);
	testSignatureMessageLength("SHA1WITHECDSA",1000);
    }
    
    public void testSignatureModifiedSignature() throws Exception  {
	testSignatureModifiedSignature("MD5WITHECDSA");
	testSignatureModifiedSignature("SHA1WITHECDSA");
    }
    public void testSignatureDifferentSignatureForDifferentMessages() throws Exception{
	testSignatureDifferentSignatureForDifferentMessages("MD5WITHECDSA");
	testSignatureDifferentSignatureForDifferentMessages("SHA1WITHECDSA");
    }
    
    public void testSeparatePrivateKeyDiffer() throws InvalidKeyException, NoSuchAlgorithmException, InterruptedException {
	createNewKeyPair();
	int [] keydata = privateKey.getKeyData();
	createNewKeyPair();
	int [] keydata2 = privateKey.getKeyData();
	assertEquals(keydata.length, keydata2.length);
	boolean equals=true;
	for (int i=0;i<keydata.length;i++ ){
	    if (keydata[i]!=keydata2[i]) {
		equals=false;
	    }
	}
	assertFalse(equals);
	
    }
    private void testSignatureMessageLength(String alg,int length) throws InvalidKeyException, NoSuchAlgorithmException, InterruptedException, SignatureException, java.security.NoSuchAlgorithmException {
	boolean match;
	SecureRandom r = SecureRandom.getInstance(SecureRandom.ALG_SECURE_RANDOM);
	Random ra = new Random();
	createNewKeyPair();
	
	
		sig = Signature.getInstance(alg);
		message=new byte[length];
		r.generateData(message, 0, length);		
		sign();
		match = verify();
	        assertTrue(match);
	        int index =ra.nextInt(message.length);
	        message[index]=(byte)(message[index]+ra.nextInt(253)+1);
	        match=verify();
	        if (match) {
	            System.out.println("");
	        }
	        assertFalse(match);
	        
		}
    

    private void testSignatureDifferentSignatureForDifferentMessages(String alg) throws InvalidKeyException, NoSuchAlgorithmException, InterruptedException, SignatureException {
	createNewKeyPair();
	sig = Signature.getInstance(alg);
	message="Test".getBytes();		
	sign();
	byte[] sig1 = Util.cloneArray(signature);
	int sigLen1= sigLen;
	message[1]=(byte)(message[1]+1);
	sign();	
	boolean equal = true;
	if (sigLen1== sigLen) {
	for (int i=0;i<sigLen1;i++) {
	    if (signature[i]!=sig1[i]) {
		equal=false;
	    }
	}
	}
	else {
	    equal=false;
	}
	
	assertFalse(equal);
        
}

    
    private void testSignatureModifiedMessage(String alg) throws InvalidKeyException, NoSuchAlgorithmException, InterruptedException, SignatureException {
	boolean match;
	createNewKeyPair();
	sig = Signature.getInstance(alg);
	message="Test".getBytes();		
	sign();
	message[2]=(byte)(message[2]+1);
	match = verify();
        assertFalse(match);
        debug("Match: " + match);
}
    
    private void testSignatureModifiedSignature(String alg) throws InvalidKeyException, NoSuchAlgorithmException, InterruptedException, SignatureException {
	boolean match;
	createNewKeyPair();
	sig = Signature.getInstance(alg);
	message="Test".getBytes();		
	sign();
	signature[2]=(byte)(signature[2]+1);
	match = verify();
	
        assertFalse(match);
        debug("Match: " + match);
}

    
    private void createNewKeyPair() throws InvalidKeyException, NoSuchAlgorithmException, InterruptedException {
	  long startTime;
	        long endTime;
	       
	debug("Creating Key Objects");
        publicKey = new ECPublicKeyImpl(curveId);
        privateKey = new ECPrivateKeyImpl(curveId);
       
    	debug("Generating Key Pair");
        startTime = System.currentTimeMillis();
        //pair.genKeyPair();
        ECKeyImpl.genKeyPair(publicKey, privateKey);
        endTime = System.currentTimeMillis();
        System.out.println("Key pair generation: " + 
                (endTime - startTime) + " ms.");           
        
    }
    
    private void sign() throws SignatureException, InvalidKeyException {
	sig.initSign(privateKey);
	debug("Signing");
        long startTime = System.currentTimeMillis();
        sig.update(message, 0, message.length);
        sigLen = sig.sign(signature, 0, signature.length);
        long endTime = System.currentTimeMillis();
        debug("signature: " + Util.hexEncode(signature, sigLen));
        System.out.println("Signing: " + 
                (endTime - startTime) + " ms.");
        

    }
    private boolean verify() throws InvalidKeyException, SignatureException {
	sig.initVerify(publicKey);
 	//debug("Verifying with modified signature");
    	sig.update(message, 0, message.length);
    	return sig.verify(signature, 0, sigLen);        
    }
    
    private void testSig(String algorithm) throws Exception {
        System.out.println("Testing " + algorithm) ;       
        sig = Signature.getInstance(algorithm);
        message= "SunSPOT".getBytes();
    	sign();
    	boolean match = verify();
    	assertTrue(match);
    	message = "SunSPoT".getBytes();
    	match = verify();
    	assertFalse(match);
    	
    }
    

    
	
    private static void debug(String s) {
        System.out.println(s);
    }	

    
    protected int curveId;

}
