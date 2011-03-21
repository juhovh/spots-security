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

package com.sun.squawk.io.j2me.sradiostream;

import java.io.InputStream;
import java.io.OutputStream;

import javax.microedition.io.Connection;

import com.sun.spot.io.j2me.radiostream.RadiostreamConnection;
import com.sun.spot.io.j2me.radiostream.RadioInputStream;
import com.sun.spot.io.j2me.radiostream.RadioOutputStream;
import com.sun.spot.peripheral.RadioConnectionBase;
import com.sun.spot.peripheral.Spot;
import com.sun.spot.peripheral.TrustManager;
import com.sun.spot.peripheral.radio.ConnectionID;
import com.sun.spot.peripheral.radio.IRadioPolicyManager;
import com.sun.spot.peripheral.radio.IRadiostreamProtocolManager;
import com.sun.spot.peripheral.radio.RadioPolicy;
import com.sun.spot.peripheral.radio.RadiostreamProtocolManager;
import com.sun.spot.util.IEEEAddress;

import com.sun.midp.pki.SpotCertStore;
import com.sun.midp.ssl.SSLStreamConnection;

import java.io.IOException;

/**
 * This class provides the "sradiostream" protocol for accessing the SPOT radio
 * using streams secured by SSL. 
 * It is an implementor of {@link RadiostreamConnection}
 * 
 * @see RadiostreamConnection
 */
public class Protocol extends RadioConnectionBase implements RadiostreamConnection {

	private long macAddress;
	private byte portNo;

	private RadioPolicy selection = RadioPolicy.ON;

	private RadioInputStream radioInputStream;
	private RadioOutputStream radioOutputStream;
	private static IRadiostreamProtocolManager protocolManager;
	private static IRadioPolicyManager radioPolicyManager;

        private SSLStreamConnection s_conn;
        
	private static synchronized IRadiostreamProtocolManager getProtocolManager() {
		if (protocolManager == null) {
			protocolManager = RadiostreamProtocolManager.getInstance();
		}
		return protocolManager;
	}

	public static void setProtocolManager(IRadiostreamProtocolManager protocolManager) {
		Protocol.protocolManager = protocolManager;
	}
	
	private static synchronized IRadioPolicyManager getRadioPolicyManager() {
		if (radioPolicyManager == null) {
			radioPolicyManager = Spot.getInstance().getRadioPolicyManager();
		}
		return radioPolicyManager;
	}
	
	public static void setRadioPolicyManager(IRadioPolicyManager manager) {
		radioPolicyManager = manager;
	}
	
	/* (non-Javadoc)
	 * @see com.sun.squawk.io.ConnectionBase#open(java.lang.String, java.lang.String, int, boolean)
	 */
	public Connection open(String protocolName,
                               String name,
                               int mode,
                               boolean timeouts) throws IOException {

                boolean server;
                int portNoAsInt = 0; // Special value if no port requested
		
                name = name.substring(2); // strip the two /s
                                
		int split = name.indexOf(":");
		                
		if (split >= 0 && split != (name.length()-1)) {
			portNoAsInt = Integer.parseInt(name.substring(split+1));
                        if (portNoAsInt <= 0 || portNoAsInt > 255) {
				throw new IllegalArgumentException(
                                    "Cannot open " + name 
                                    + ". Port number is invalid");
			}
		} else if (split < 0) {
			split = name.length();
		} else {
			// trailing colon special case
			split = name.length()-1;
		}
                name = name.substring(0, split);

                /* the device with the greater address acts as the server */
                server = System.getProperty("IEEE_ADDRESS").compareTo(name) > 0;
                
                macAddress = new IEEEAddress(name).asLong();
                portNo = (byte)portNoAsInt;
		if (timeouts) {
			setTimeout(DEFAULT_TIMEOUT);
		}
             
                /* open underlying unsecure InputStream */
                InputStream u_in = openUnsecureInputStream();
                
                /* open underlying unsecure OutputStream */
                OutputStream u_out = openUnsecureOutputStream();
                
                /* Secure the streams */
                if (server) {
                    s_conn = new SSLStreamConnection(name, u_in, u_out, null);
                } else {
                    TrustManager tm = TrustManager.getTrustManager();
                    SpotCertStore cs = tm.getCertStore();
                    s_conn = new SSLStreamConnection(name, portNoAsInt, u_in, u_out, cs);
                }
                return this;
	}
 
	private InputStream openUnsecureInputStream() {
		ConnectionID inputConnectionID = getProtocolManager().addInputConnection(macAddress, portNo);
		radioInputStream = new RadioInputStream(getProtocolManager(), inputConnectionID, getTimeout(), selection, getRadioPolicyManager());
		portNo = inputConnectionID.getPortNo();
		return radioInputStream;
        }
        
	/* (non-Javadoc)
	 * @see com.sun.squawk.io.ConnectionBase#openInputStream()
	 */
        public InputStream openInputStream() throws IOException {
                return s_conn.openInputStream();
        }

	private OutputStream openUnsecureOutputStream() {
		ConnectionID outputConnectionID = getProtocolManager().addOutputConnection(macAddress, portNo);
		radioOutputStream = new RadioOutputStream(getProtocolManager(), outputConnectionID, selection, getRadioPolicyManager());
		portNo = outputConnectionID.getPortNo(); 
		return radioOutputStream;
        }

	/* (non-Javadoc)
	 * @see com.sun.squawk.io.ConnectionBase#openOutputStream()
	 */
        public OutputStream openOutputStream() throws IOException {
                return s_conn.openOutputStream();
        }

	public void setRadioPolicy(RadioPolicy selection) {
		this.selection = selection;
		if (radioInputStream != null) {
			radioInputStream.setRadioPolicy(selection);
		}
		if (radioOutputStream != null) {
			radioOutputStream.setRadioPolicy(selection);
		}
	}

	public byte getLocalPort() {
		if (portNo == 0) {
			throw new IllegalStateException("Radiostream" +
                                " connection has no port assigned" +
                                " before streams opened.");
		}
		return portNo;
	}
        
        public void close() throws IOException {
            // close the SSL session
            s_conn.close();
            // close the underlying connection
            super.close();
        }
}
