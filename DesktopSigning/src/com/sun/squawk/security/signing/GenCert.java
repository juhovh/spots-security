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

import com.sun.squawk.security.CryptoException;
import com.sun.squawk.security.ECPublicKey;
import com.sun.squawk.security.signing.ECPrivateKey;
import com.sun.squawk.security.HexEncoding;
import com.sun.squawk.security.ecc.ECCurveFp;
import com.sun.squawk.security.ecc.ECPoint;
import com.sun.squawk.security.ecc.FFA;

import java.util.Calendar;
import java.util.TimeZone;
import java.util.Date;

class GenCert {
    private static int MAX_CERT_SIZE = 1024;
    private static int TBSCERT_CONTENT_OFFSET = 8;
    private static int MAX_CURVE_SIZE_IN_BYTES = 70;
    private static long MAX_TIME_SLACK_MILLIS = 3600000; // 1 hour

    private static byte INT_TYPE             = 0x02;
    private static byte BITSTRING_TYPE       = 0x03;
    private static byte OID_TYPE             = 0x06;
    private static byte PRINTABLESTRING_TYPE = 0x13;
    private static byte UTCTIME_TYPE         = 0x17;
    private static byte SEQ_TYPE             = 0x30;
    private static byte SET_TYPE             = 0x31;
    
    private static byte[] ECDSAwithSHA1_OID = {
        0x2a, (byte) 0x86, 0x48, (byte) 0xce, 0x3d, 0x04, 0x01
    };

    private static byte[] ECPublicKey_OID = {
        0x2a, (byte) 0x86, 0x48, (byte) 0xce, 0x3d, 0x02, 0x01
    };

    private static byte[] CN_OID = {
        0x55, 0x04, 0x03
    };

    private static byte[] SECP160R1_OID = {
        0x2b, (byte) 0x81, 0x04, 0x00, 0x08
    };

    private static byte[] v3encoding = {
        (byte) 0xa0, 0x03, 0x02, 0x01, 0x02
    };
      
    private static int insertCN(byte[] buf, int idx, String name) {
        byte[] strBytes = name.getBytes();
        int len = strBytes.length;

        buf[idx++] = SEQ_TYPE;
        buf[idx++] = (byte) (len + 11);
        buf[idx++] = SET_TYPE;
        buf[idx++] = (byte) (len + 9);
        buf[idx++] = SEQ_TYPE;
        buf[idx++] = (byte) (len + 7);        
        buf[idx++] = OID_TYPE;
        buf[idx++] = (byte) CN_OID.length;
        System.arraycopy(CN_OID, 0, buf, idx, CN_OID.length);
        idx += CN_OID.length;
        buf[idx++] = PRINTABLESTRING_TYPE;
        buf[idx++] = (byte) len;
        System.arraycopy(strBytes, 0, buf, idx, len);
        return (len + 13);
    }

    private static int prependLength(byte[] buf, int start, int len) {
        if (len <= 127) {
            start -= 2;
            buf[start] = SEQ_TYPE;
            buf[start+1] = (byte) len;
            return 2;
        } else if (len <= 255) {
            start -= 3;
            buf[start] = SEQ_TYPE;
            buf[start+1] = (byte) 0x81;
            buf[start+2] = (byte) len;
            return 3;
        } else {
            start -= 4;
            buf[start] = SEQ_TYPE;
            buf[start+1] = (byte) 0x82;
            buf[start+2] = (byte) (len >>> 8);
            buf[start+2] = (byte) (len & 0xff);
            return 4;
        }
    }

    private static byte[] calToUTCTimeBytes(Calendar cal) {
        int[] period = new int[6];
        byte[] val = new byte[13];
        
        period[0] = cal.get(Calendar.YEAR) - 2000;  // assumes YY is after 2000  
        period[1] = cal.get(Calendar.MONTH) + 1;  // because months go 0-11
        period[2] = cal.get(Calendar.DAY_OF_MONTH);
        period[3] = cal.get(Calendar.HOUR_OF_DAY);
        period[4] = cal.get(Calendar.MINUTE);
        period[5] = cal.get(Calendar.SECOND);
       
        for (int i = 0; i < period.length; i++) {
           val[2*i] = (byte) (period[i]/10 + '0');
           val[2*i + 1] = (byte) (period[i] % 10 + '0');           
        }
        val[12] = 'Z';
        
        return val;
    };

    static byte[] mkECCertBytes(boolean isV3, short serialNo,
            String issuerCN, int validityPeriodInDays, String subjectCN, 
            ECPublicKey pub, ECPrivateKey priv) throws Exception {
        byte[] buf = new byte[MAX_CERT_SIZE];
        int start = TBSCERT_CONTENT_OFFSET;
        int end = 0;
        byte[] byteArray = null;
        int len = 0;
        int val = 0;
        long lval = 0;
        int idx = start;
        int savedIdx = 0;
        ECDSASignature sig = null;
        Calendar cal;

        // Start collecting the TBSCert contents
        // . version
        if (isV3) {
            System.arraycopy(v3encoding, 0, buf, idx, v3encoding.length);
            idx += v3encoding.length;
        }

        // . serial No
        buf[idx++] = INT_TYPE;
        if (serialNo <= 0xff) { // can be encoded in 1 byte
            buf[idx++] = (byte) 0x01;
        } else {
            buf[idx++] = (byte) 0x02;
            buf[idx++] = (byte) (serialNo >>> 8);
        }
        buf[idx++] = (byte) (serialNo & 0xff);

        // . cert signature Id
        len = ECDSAwithSHA1_OID.length;
        buf[idx++] = SEQ_TYPE;
        buf[idx++] = (byte) (2 + len);
        buf[idx++] = OID_TYPE;
        buf[idx++] = (byte) len;
        System.arraycopy(ECDSAwithSHA1_OID, 0, buf, idx, len);
        idx += len;

        // . issuer
        idx += insertCN(buf, idx, issuerCN);

        // . validity
        lval = System.currentTimeMillis() - MAX_TIME_SLACK_MILLIS;
        cal = Calendar.getInstance(TimeZone.getTimeZone("GMT"));

        buf[idx++] = SEQ_TYPE;
        buf[idx++] = (byte) 0x1e;
        
        cal.setTime(new Date(lval));
        byteArray = calToUTCTimeBytes(cal);
        len = byteArray.length;
        buf[idx++] = UTCTIME_TYPE;
        buf[idx++] = (byte) len;
        System.arraycopy(byteArray, 0, buf, idx, len);
        idx += len;

        lval += MAX_TIME_SLACK_MILLIS  + (validityPeriodInDays * 86400000L);
        cal.setTime(new Date(lval));
        byteArray = calToUTCTimeBytes(cal);
        len = byteArray.length;
        buf[idx++] = UTCTIME_TYPE;
        buf[idx++] = (byte) len;
        System.arraycopy(byteArray, 0, buf, idx, len);
        idx += len;

        // . subject
        idx += insertCN(buf, idx, subjectCN);

        // . publicKeyInfo
        buf[idx++] = SEQ_TYPE;
        savedIdx = idx++;  // need to fill length later
        buf[idx++] = SEQ_TYPE;
        // switch (pub.getCurve()) {
        // case ECCurve.SECP160R1:
            len = SECP160R1_OID.length;
            byteArray = SECP160R1_OID;
            buf[savedIdx] = (byte) (16 + len); // we still need to add W.length
        //    break;
        //default:
        //    throw new Exception("Unknown curve");
        //}
        buf[idx++] = (byte) (len + 11);
        len = ECPublicKey_OID.length;
        buf[idx++] = OID_TYPE;
        buf[idx++] = (byte) len;
        System.arraycopy(ECPublicKey_OID, 0, buf, idx, len);
        idx += len;
        // insert curve OID saved in byteArray
        buf[idx++] = OID_TYPE;
        len = byteArray.length;
        buf[idx++] = (byte) len;
        System.arraycopy(byteArray, 0, buf, idx, len);
        idx += len;
                
        byteArray = new byte[(MAX_CURVE_SIZE_IN_BYTES * 2) + 1];
        len = pub.getW(byteArray, 0);
        buf[idx++] = BITSTRING_TYPE;
        buf[idx++] = (byte) (len + 1);
        buf[idx++] = 0x00;
        System.arraycopy(byteArray, 0, buf, idx, len);
        idx += len;
        buf[savedIdx] += (byte) len;  // finish adding length of W

        // compute TBS length and encode it
        len = idx - start;

        start -= prependLength(buf, start, len);
        end = idx;

        // signture type following TBSCert
        buf[idx++] = SEQ_TYPE;
        len = ECDSAwithSHA1_OID.length;
        buf[idx++] = (byte) (len + 2);
        buf[idx++] = OID_TYPE;
        buf[idx++] = (byte) len;
        System.arraycopy(ECDSAwithSHA1_OID, 0, buf, idx, len);
        idx += len;

        // signature encoding
        buf[idx++] = BITSTRING_TYPE;
        savedIdx = idx++; // fill length later
        buf[idx++] = 0x00;
        byteArray = new byte[((MAX_CURVE_SIZE_IN_BYTES + 2) * 2) + 1];
        sig = new ECDSASignature();
        sig.init(priv);
        
        byte[] signature = new byte[sig.getLength()];
	len = sig.sign(buf, start, (end - start), signature, 0);
	System.arraycopy(signature, 0, buf, idx, len);
        
        idx += len;
        buf[savedIdx] = (byte) (len + 1);
        
        // compute and fill out cert len
        len = idx - start;
     
        start -= prependLength(buf, start, len);

        // Dump out the cert
        byteArray = new byte[idx - start];
        System.arraycopy(buf, start, byteArray, 0, byteArray.length);
        return byteArray;
    }
}

        /* Cert size has these components
         * Max cert wrap: 4 bytes
         * TBSCert has:
         *   0x30 0x82 0xll 0xll
         *   TBScontent length = 0/5 + (serialNo.len + 2) + 11 + 
         *      (IssuerCN.len + 13) + 32 + (SubjectCN.len + 13) +
         *      (W.length + curveOID.len + 18)
         *      = serialNo.len + IssuerCN.len + SubjectCN.len + W.len +
         *        curveOID.len + 89 + 0/5
         *   version: 0 bytes or 5 bytes (0xa0 0x03 0x02 0x01 0x02)
         *   serial number: serialNo.len + 2 
         *        0x02 0x(serialNo.len) <serialNo>
         *   cert signature alg: OIDlen + 4 (=11 bytes for ECDSAwithSHA1)
         *        0x30 0x(OIDlen+2) 0x06 0x(OIDlen) <sigOID>, 
         *        for ECDSAwithSHA1, this is:
         *        0x30 0x09 0x06 0x07 0x2a 0x86 0x48 0xce 0x3d 0x04 0x01
         *   Issuer: IssuerCN.len + 13 
         *       0x30 0x(IssuerCN.len+11) 
         *         0x31 0x(IssuerCN.len+9) 
         *           0x30 0x(IssuerCN.len+7) 
         *             0x06 0x03 0x55 0x04 0x03 
         *             0x13 0x(IssuerCN.len) <IssuerCN>
         *   Validity: 32 bytes
         *       0x30 0x1e 0x17 0x0d 'YYMMDDHHMMSSZ' 0x17 0x0d 'YYMMDDHHMMSSZ'
         *   Subject: SubjectCN.len + 13 
         *       0x30 0x(SubjectCN.len+11) 
         *         0x31 0x(SubjectCN.len+9) 
         *           0x30 0x(SubjectCN.len+7) 
         *             0x06 0x03 0x55 0x04 0x03 
         *             0x13 0x(SubjectCN.len) <SubjectCN>
         *   PublicKeyInfo: W.length + curveOID.len + 18
         *          0x30 0x(4 + (curveOIDlength+11) + (W.length+1))
         *            0x30 0x(curveOIDlength + 11)
         *               0x06 0x07 2a 86 48 ce 3d 02 01 (ECPublicKey OID)
         *               0x06 0x(curveOIDlength) <curveOID>  
         *            0x03 0x(W.length+1)  0x00  <W>
         *
         * signature OID: OID.len + 4 (=11 for ECDSAwithSHA1)
         *    0x30 0x(OID.len+2)
         *      0x06 0x(OID.len) <OID>
         *
         * signature = signature.len + 3
         *    0x03 0x(sig.len+1) 0x00 <signature>
         */
