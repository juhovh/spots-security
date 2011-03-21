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

import java.io.FileInputStream;
import java.io.FileOutputStream;
import java.util.Properties;
import java.io.File;
import java.util.Date;
import java.lang.Integer;

import com.sun.squawk.security.CryptoException;
import com.sun.squawk.security.ECPublicKey;
import com.sun.squawk.security.signing.ECPrivateKey;
import com.sun.squawk.security.HexEncoding;
import com.sun.squawk.security.ecc.ECCurveFp;
import com.sun.squawk.security.ecc.ECPoint;
import com.sun.squawk.security.ecc.FFA;
import com.sun.squawk.security.signing.GenCert;

/**
 * The SigningService class is used to sign suites and other data on the desktop
 * using the SDK private key. <br>
 * It also allows retrieving the public key from the keyfile.
 *
 * @author Vipul Gupta
 * @author Christian Pühringer
 */
final public class SigningService {
    
    // In version 0.1, we only stored the raw key pair. Starting
    // with version 0.2, we also store the SDK self-signed cert
    public static final String FORMAT_VERSION = "0.2";
    
    private static String keyFileName = null;
        
    private static String keyDirName = null;
    
    private static SigningService signingService = null;
    
    private File keyFile = null;
    
    private ECPrivateKey SDKPrivateKey = null;
    
    private ECPublicKey SDKPublicKey = null;
    
    private String SDKName = "SDK";
    
    private byte[] SDKCertBytes = null;
    
    private int SDKlastSerialNo = 0; // incremented for each cert issued
    
    private String verStr = null;
    
    private static final int SPOT_CERT_VALIDITY_PERIOD = 3650; // in days
    private static final int SDK_CERT_VALIDITY_PERIOD = 3650;
    
    private Properties props = new Properties();
    
    /**
     * Creates a new instance of SigningService.
     */
    private SigningService() throws SigningServiceException {
        if (keyFileName == null)
            throw new SigningServiceException(
                    "setKeyDirectoryName must be called before using "
                    + "SigningService");
        if (Debug.ENABLED)
            System.out.println("SigningService: Using key file " + keyFileName);
        keyFile = new File(SigningService.keyFileName);
        if (keyFile.exists())
            loadKeyPair();
        else {
            generateKeyPair();
            saveKeyPair();
            saveSDKCert();
        }
    }
    
    /**
     * Sets the directory where the key file (sdk.key) resides. Must be
     * called before using any of the other SigningService methods.
     *
     * @param keyDirectoryName
     *                the directory where the keyfile is located
     */
    public static void setKeyDirectoryName(String keyDirectoryName) {
        keyDirName = new String(keyDirectoryName);
        keyFileName = new File(keyDirName, "sdk.key").getPath();
        signingService = null;
    }
    
    /**
     * Get the singleton instance of this class. First access triggers
     * loading of the keys from the key file set by setKeydDirectoryName. If
     * the keyfile does not exist a new keyfile is created.
     *
     * @return The singleton instance
     */
    public static synchronized SigningService getInstance()
    throws SigningServiceException {
        if (signingService == null) {
            signingService = new SigningService();
        }
        return signingService;
    }
    
    /**
     * Signs the input byte array (which might contain a suite or a command)
     * with the SDK's private key and returns the DER-encoded ECDSA
     * signature.
     *
     * @param data
     *                to be signed
     * @return signature
     */
    public byte[] sign(byte[] data) throws SigningServiceException {
        if (Debug.ENABLED)
            System.out.println("Debug: SigningService.sign: Compute suite "
                    + "signature for data buf");
        try {
            
            ECDSASignature s = new ECDSASignature();
            
            s.init(SDKPrivateKey);
            byte[] signature = new byte[s.getLength()];
            int signatureLength = s.sign(data, 0, data.length, signature, 0);
            // Ensure that the returned signature buffer is not
            // larger than the real length of the signature
            if (signatureLength < signature.length) {
                byte[] signatureCorrectedLength = new byte[signatureLength];
                System.arraycopy(signature, 0, signatureCorrectedLength, 0,
                        signatureCorrectedLength.length);
                return signatureCorrectedLength;
            } else
                return signature;
        } catch (CryptoException ex) {
            if (Debug.ENABLED)
                ex.printStackTrace();
            throw new SigningServiceException("Signing failed (" + ex + ")");
        }
    }
    
    /**
     * Returns encoded SDK public key. For elliptic curve keys, the encoding
     * consists of the byte 0x04 (for uncompressed point) followed by the
     * X9.62 octet encodings of the x and y coordinates.
     *
     * @return The SDKs public key
     */
    public byte[] getPublicKeyBytes() throws SigningServiceException {
        try {
            // Example: A 160-bit ECC key will be encoded using 41
            // bytes
            int size = 1 + 2 * ((SDKPublicKey.getSize() + 7) / 8);
            byte[] keyBytes = new byte[size];
            int tmp = ((ECPublicKey) SDKPublicKey).getW(keyBytes, 0);
            if (Debug.ENABLED)
                System.out.println("Pubkey buffer size is " + keyBytes.length
                        + ", saved " + tmp + " bytes.");
            return keyBytes;
        } catch (CryptoException ex) {
            throw new SigningServiceException("getPublicKeyBytes failed (" + ex
                    + ")");
        }
    }
    
    /**
     * The SDK public key is encoded as a self-signed X.509 certificate and
     * the bytes corresponding to the certificate's DER encoding are returned.
     *
     *  @return bytes in the DER encoding of the SDK's self-signed X.509
     *  certificate
     */
    public byte[] getCertBytes() throws SigningServiceException {
        if (SDKCertBytes == null)
            throw new SigningServiceException("SDK Cert not initialized");
        byte[] result = new byte[SDKCertBytes.length];
        System.arraycopy(SDKCertBytes, 0, result, 0, result.length);
        return result;
    }
    
    private byte[] getPrivateKeyBytes() throws SigningServiceException {
        try {
            byte[] keyBytes = new byte[(SDKPrivateKey.getSize() + 7)/8];
            int tmp = ((ECPrivateKey) SDKPrivateKey).getS(keyBytes, 0);
            keyBytes = new byte[tmp];
            ((ECPrivateKey) SDKPrivateKey).getS(keyBytes, 0);
            if (Debug.ENABLED) {
                System.out.println("Privkey size = " + SDKPrivateKey.getSize());
                System.out.println("Privkey buffer size is " + keyBytes.length
                        + ", saved " + tmp + " bytes.");
            }
            return keyBytes;
        } catch (CryptoException ex) {
            throw new SigningServiceException("getPrivateKeyBytes failed ("
                    + ex + ")");
        }
        
    }
    
    /**
     * Generates a new SDK key pair and saves it into the keyfile specified
     * in the constructor.
     */
    public void generateKeyPair() throws SigningServiceException {
        ECKeyPair sdkKeyPair = null;
        try {
            String pubkeyPrefix = null;
            sdkKeyPair = new ECKeyPair();
            sdkKeyPair.genKeyPair();
            SDKPublicKey = sdkKeyPair.getPublic();
            SDKPrivateKey = sdkKeyPair.getPrivate();
            
            pubkeyPrefix = HexEncoding.hexEncode(getPublicKeyBytes());
            // We choose the first four bytes of the SDK's public key
            // as its identifier.
            if (pubkeyPrefix.length() > 8)
                pubkeyPrefix = pubkeyPrefix.substring(0, 8);
            try {
                SDKName = "SDK-" + pubkeyPrefix;
                SDKCertBytes = GenCert.mkECCertBytes(true, // X.509 version 3 cert
                        (short) 1, // serial number
                        SDKName, // issuer
                        SDK_CERT_VALIDITY_PERIOD, // validity in days
                        SDKName, // subject
                        SDKPublicKey, SDKPrivateKey);
                SDKlastSerialNo = 1;
            } catch (Exception e) {
                System.out.println("Could not make ECCCert: " + e.getMessage());
                throw new SigningServiceException("Could not make ECCCert");
            }
            
        } catch (CryptoException ex) {
            if (Debug.ENABLED)
                ex.printStackTrace();
            throw new SigningServiceException(
                    "Could not generate SDK key pair in " + keyFile.getPath()
                    + " (" + ex + ")");
        }
    }
    
    // Returns true iff the specified version is newer or same as what we support
    private boolean isNewerOrSame(String ver) {
        int major, minor;
        int tmp;
        
        tmp = ver.indexOf(".");
        if (tmp <= 0) return false;
        try {
            major = Integer.parseInt(ver.substring(0, tmp));
            minor = Integer.parseInt(ver.substring(tmp + 1));
            if ((major == 0) && (minor >= 2))
                return true;
        } catch (Exception e) {
            return false;
        }
        
        return false;
    }
    
    private void saveKeyPair() throws SigningServiceException {
        // TODO: Use password to encrypt private key
        try {
            FileOutputStream keyFileOut = new FileOutputStream(keyFile);

            String keyStr = null;
            
            // do not overwrite version if it is newer
            if ((verStr == null) || !isNewerOrSame(verStr)) {
                props.setProperty("SDKKeyFormatVersion", FORMAT_VERSION);
            }
               
            keyStr = HexEncoding.hexEncode(getPublicKeyBytes());
            props.setProperty("SDKPublicKey", keyStr);
            keyStr = HexEncoding.hexEncode(getPrivateKeyBytes());
            props.setProperty("SDKPrivateKey", keyStr);
            keyStr = HexEncoding.hexEncode(getCertBytes());
            props.setProperty("SDKCertBytes", keyStr);
            props.setProperty("SDKName", SDKName);
            props.setProperty("SDKlastSerialNo", 
                    (new Integer(SDKlastSerialNo)).toString());
            props.store(keyFileOut, null);
            keyFileOut.close();
            if (Debug.ENABLED)
                System.out.println(keyFile.getName() + " written.");
            
        } catch (Exception ex) {
            if (Debug.ENABLED)
                ex.printStackTrace();
            throw new SigningServiceException(
                    "Could not save key store to file " + keyFile.getPath()
                    + " (" + ex + ")");
        }
    }
    
    private void writeToFile(String filename, byte[] buf) throws SigningServiceException {
        try {
            String fname = new File(keyDirName, filename).getPath();
            FileOutputStream fileOS = new FileOutputStream(new File(fname));
            fileOS.write(buf);
            fileOS.close();
        } catch (Exception ex) {
            throw new SigningServiceException(
                    "Could not write to " + filename + " (" + ex + ")");
        }
    }
    
    private void saveSDKCert() throws SigningServiceException {
        writeToFile("sdkcert.der", getCertBytes());
    }
    
    private void loadKeyPair() throws SigningServiceException {
        // TODO: Use password to encrypt private key
        
        String pubKeyStr, privKeyStr, certStr, serialNoStr;
        try {
            FileInputStream keyFileIn = new FileInputStream(keyFile);
            props.load(keyFileIn);
            keyFileIn.close();
            verStr = props.getProperty("SDKKeyFormatVersion");
            pubKeyStr = props.getProperty("SDKPublicKey");
            privKeyStr = props.getProperty("SDKPrivateKey");
            certStr = props.getProperty("SDKCertBytes");
            SDKName = props.getProperty("SDKName");
            serialNoStr = props.getProperty("SDKlastSerialNo");
        } catch (Exception ex) {
            if (Debug.ENABLED)
                ex.printStackTrace();
            throw new SigningServiceException("Problems reading keypair file.");
        }
        
        
        if ((verStr == null) || !verStr.startsWith("0.") || 
                (pubKeyStr == null) || (privKeyStr == null)) {
            // we only handle formats 0.x 
            throw new SigningServiceException("Bad key file format.");
        }
       
        try {
            byte[] keyBytes;
            
            SDKPublicKey = new ECPublicKey();
            keyBytes = HexEncoding.hexDecode(pubKeyStr);
            ((ECPublicKey) SDKPublicKey).setW(keyBytes, 0, keyBytes.length);
            if (Debug.ENABLED) {
                System.out.println("loadKeyPair: pubKeyStr: "
                        + HexEncoding.hexEncode(keyBytes));
            }
            
            SDKPrivateKey = new ECPrivateKey();
            keyBytes = HexEncoding.hexDecode(privKeyStr);
            ((ECPrivateKey) SDKPrivateKey).setS(keyBytes, 0, keyBytes.length);
            if (Debug.ENABLED) {
                System.out.println("loadKeyPair: privKeyStr: "
                        + HexEncoding.hexEncode(keyBytes));
            }
            
            // Version 0.1 did not have the self signed cert so create
            // one now and save it for later
            if (verStr.compareTo("0.1") == 0) {
                String pubkeyPrefix = new String(pubKeyStr);

                // We choose the first four bytes of the SDK's public key
                // as its identifier.
                if (pubkeyPrefix.length() > 8)
                    pubkeyPrefix = pubKeyStr.substring(0, 8);

                try {
                    SDKName = "SDK-" + pubkeyPrefix;
                    SDKCertBytes = GenCert.mkECCertBytes(true, // X.509 version 3 cert
                            (short)1, // serial number
                            SDKName, // issuer
                            SDK_CERT_VALIDITY_PERIOD, // validity in days
                            SDKName, // subject
                            SDKPublicKey, SDKPrivateKey);
                    SDKlastSerialNo = 1;
                } catch (Exception e) {
                    throw new SigningServiceException("Could not make ECCCert");
                }
                
                saveKeyPair();
                saveSDKCert();
            } else { // we already have version 0.2 or higer (but compatible)
                if ((certStr != null) && (serialNoStr != null)) {
                    SDKCertBytes = HexEncoding.hexDecode(certStr);
                    SDKlastSerialNo = Integer.parseInt(serialNoStr);
                    if (Debug.ENABLED) {
                        System.out.println("loadKeyPair: certStr: "
                                + HexEncoding.hexEncode(SDKCertBytes));
                    }
                } else {
                    throw new SigningServiceException("Missing SDKCertBytes" +
                            " or SDKlastSerialNo");
                }
            }
        } catch (Exception ex) {
            if (Debug.ENABLED)
                ex.printStackTrace();
            throw new SigningServiceException(
                    "Could not load key store from file. " + keyFile.getPath()
                    + " (" + ex + ")");
        }
        ensureIsKeyPair();
    }
    
    /**
     * To determine whether a private key was loaded.
     *
     * @return false if keyfile does not exist or private key is not
     *         initialized
     *
     */
    public boolean hasNoSDKKey() {
        return (SDKPrivateKey == null) || (!SDKPrivateKey.isInitialized());
    }
    
    /**
     * Makes sure that the public and private key form a matching pair by
     * multiplying the generator (base point) with the private key and
     * comparing the result against the public key.
     *
     * @throws SigningServiceException
     *                 if the public and private key don't form a key pair
     */
    private void ensureIsKeyPair() throws SigningServiceException {
        ECCurveFp curve = ECCurveFp.getInstance();
        ECPoint generatorECPoint = curve.getGenerator().clonePoint();
        
        // generate the public key which corresponds to the private key
        
        FFA ffa = curve.getOrder().getFFA();
        
        int[] privateKeyIntegerArray =
                ffa.from(HexEncoding.hexEncode(getPrivateKeyBytes()));
        curve.multiply(generatorECPoint, privateKeyIntegerArray);
        byte[] correctPublicKeyPointEncoded =
                new byte[2 * (curve.getField().getFFA().getBitSize() + 7) >>> 3];
        curve.encodePoint(generatorECPoint, correctPublicKeyPointEncoded, 0);
        
        byte[] publicKeyBytes = getPublicKeyBytes();
        boolean match = true;
        if (publicKeyBytes.length == correctPublicKeyPointEncoded.length) {
            for (int i = 0; i < publicKeyBytes.length; i++)
                if (correctPublicKeyPointEncoded[i] != publicKeyBytes[i])
                    match = false;
            
        } else
            match = false;
        if (match == false)
            throw new SigningServiceException(
                    "Public key in keyfile doesn't correspond to private "
                    + "key in key file. "
                    + "\n\tPublic key in keyfile: "
                    + HexEncoding.hexEncode(publicKeyBytes)
                    + "\n\tPublic key generated from private key in "
                    + "keyfile: "
                    + HexEncoding
                    .hexEncode(correctPublicKeyPointEncoded));
        
        else if (Debug.ENABLED)
            System.out.println("Public key in key file is OK");
    }
    
    /**
     * Creates an X.509 certificate for the given subject and key that is signed
     * by the SDK's private key. 
     * @param subjectCN  String to be placed in the common name part of the
     *                   subject's distinguished name
     * @param pub        Public key associated with the subject
     * @return           a byte array containing the DER encoding of the X.509 
     *                   certificate
     * @throws           an Exception if there is a problem creating in the 
     *                   certificate
     */
    public byte[] mkECCertBytes(String subjectCN,
            ECPublicKey pub) throws Exception {
        byte[] val = null;
        val = GenCert.mkECCertBytes(true, (short) (SDKlastSerialNo + 1), SDKName,
                SPOT_CERT_VALIDITY_PERIOD, subjectCN, pub, SDKPrivateKey);
        SDKlastSerialNo += 1;
        saveKeyPair(); // serial number was incremented, no need to save SDKcert
        writeToFile(subjectCN + "-" + SDKName + ".der", val);
        return val;
    }
}
