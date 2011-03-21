/*
 * Copyright (c) 2007 Sun Microsystems, Inc.
 *
 * Permission is hereby granted, free of charge, to any person obtaining a copy
 * of this software and associated documentation files (the "Software"), to
 * deal in the Software without restriction, including without limitation the
 * rights to use, copy, modify, merge, publish, distribute, sublicense, and/or
 * sell copies of the Software, and to permit persons to whom the Software is
 * furnished to do so, subject to the following conditions:
 *
 * The above copyright notice and this permission notice shall be included in
 * all copies or substantial portions of the Software.
 *
 * THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
 * IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
 * FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
 * AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
 * LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING
 * FROM, OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER
 * DEALINGS IN THE SOFTWARE.
 */

/*
 * StartApplication.java
 *
 * Created on Jun 18, 2007 2:12:17 PM;
 */

package org.sunspotworld.demo;

import com.sun.spot.peripheral.Spot;
import com.sun.spot.sensorboard.EDemoBoard;
import com.sun.spot.sensorboard.peripheral.ITriColorLED;
import com.sun.spot.peripheral.radio.IRadioPolicyManager;
import com.sun.spot.io.j2me.radiostream.*;
import com.sun.spot.io.j2me.radiogram.*;
import com.sun.spot.util.*;

import java.io.*;
import javax.microedition.io.*;
import javax.microedition.midlet.MIDlet;
import javax.microedition.midlet.MIDletStateChangeException;

/**
 * The startApp method of this class is called by the VM to start the
 * application.
 * 
 * The manifest specifies this class as MIDlet-1, which means it will
 * be selected for execution.
 */
public class StartApplication extends MIDlet {
   
    private String[] testURLs = {
//        "socket://www.google.com:80",
//        "http://www.google.com/",
//        "https://www.google.com/",
//        "sslsocket://www.google.com",
          "https://login.yahoo.com/",
          "sslsocket://login.yahoo.com:443",
        // reverse the order of the next two to see session reuse in action
//        "sslsocket://127.0.0.1:4433",
//        "https://127.0.0.1:4433/",   
//        "https://www.verisign.com/",
//        "https://webbranch.techcu.com/",
//        "sslsocket://webbranch.techcu.com:443",
//        "https://us.etrade.com/",

//        "https://www.amazon.com/",
    };
        
    protected void startApp() throws MIDletStateChangeException {
        System.out.println("Started WebClient application ...");
        new BootloaderListener().start(); 
        // monitor the USB (if connected) and recognize commands from host
        
        for (int i = 0; i < testURLs.length; i++) {
            System.out.println("Testing URL " + testURLs[i]);
            System.out.println("Memory available at start: " +
                    Runtime.getRuntime().freeMemory() + "/" +
                    Runtime.getRuntime().totalMemory());
            
            runtest(testURLs[i]);
            
            System.out.println("Memory available at end: " +
                    Runtime.getRuntime().freeMemory() + "/" +
                    Runtime.getRuntime().totalMemory());

        }
        
        System.out.println("\n *** FINISHED WEBCLIENT APPLICATION ***");
    }

    protected void pauseApp() {
        // This will never be called by the Squawk VM
    }

    protected void destroyApp(boolean arg0) throws MIDletStateChangeException {
        // Only called if startApp throws any exception other than MIDletStateChangeException
    }

    private void runtest(String url) {
        System.out.println("------------------------------------------------");
        System.out.println("Started testing GCF connection <" +
                url + ">\n");
        try {
            if (url.startsWith("sslsocket://") ||
                    url.startsWith("socket://")) {
                getViaStreamConnection(url);
            } else if (url.startsWith("http://")) {
                getViaHttpConnection(url);
            } else if (url.startsWith("https://")) {
                getViaHttpsConnection(url);
            } else {
                System.out.println("Unknown protocol.");
            }
        } catch (Exception exc) {
            System.out.println("Caught " + exc);
        }
        
        System.out.println("Finished testing GCF connection <" +
                url + ">\n");
        System.out.println("------------------------------------------------");
     }
     
    void getViaStreamConnection(String url) throws IOException {
         StreamConnection c = null;
         InputStream is = null;
         OutputStream os = null;
         try {
             long starttime = System.currentTimeMillis();
             c = (StreamConnection)Connector.open(url);
             is = c.openInputStream();
             long endTime = System.currentTimeMillis();
             System.out.println("Time for streamconnection set up: "
                    + (endTime - starttime) + " ms");
             os = c.openOutputStream();
             System.out.println("Writing GET request ...");
             os.write("GET / HTTP/1.0\r\n\r\n".getBytes());
             os.flush();
             int ch;
             System.out.println("Reading response ...");
             while ((ch = is.read()) != -1) {
                  System.out.print((char) ch);
             }
             System.out.flush();
             endTime = System.currentTimeMillis();
             System.out.println("Total time to retrieve page " +
                    "(including connection set up): " +
                    + (endTime - starttime) + " ms");
            
         } finally {
             if (is != null) 
                 is.close();
             if (os != null)
                 is.close();
             if (c != null)
                 c.close();
         }
     }
    
    void getViaHttpsConnection(String url) throws IOException {
        HttpsConnection c = null;
        InputStream is = null;
        try {
            long starttime = System.currentTimeMillis();
            c = (HttpsConnection)Connector.open(url);
            
            // Getting the InputStream will open the connection
            // and read the HTTP headers. They are stored until
            // requested.
            is = c.openInputStream();
            long endTime = System.currentTimeMillis();
            System.out.println("Time for HTTPS connection set up: "
                    + (endTime - starttime) + " ms");
            
            // Get the ContentType
            String type = c.getType();
            
            // Get the length and process the data
            int len = (int) c.getLength();
            if (len > 0) {
                byte[] data = new byte[len];
                int actual = is.read(data);
                System.out.println("Data received [" + actual + " of " +
                        len + " bytes] ...");
                System.out.println(new String(data, 0, actual));
            } else {
                int ch;
                System.out.println("Data received ...");
                while ((ch = is.read()) != -1) {
                    System.out.print((char) ch);
                }
            }
            
            System.out.flush();
            
            endTime = System.currentTimeMillis();
            System.out.println("Total time to retrieve page " +
                    "(including connection set up): " +
                    + (endTime - starttime) + " ms");
            
            System.out.println("SSLSecurityInfo for <" + url + ">\n" +
                    c.getSecurityInfo());
           
        } finally {
            if (is != null)
                is.close();
            if (c != null)
                c.close();
        }
    }
              
    void getViaHttpConnection(String url) throws IOException {
        HttpConnection c = null;
        InputStream is = null;
        try {
            long starttime = System.currentTimeMillis();
            c = (HttpConnection)Connector.open(url);
            
            // Getting the InputStream will open the connection
            // and read the HTTP headers. They are stored until
            // requested.
            is = c.openInputStream();
            long endTime = System.currentTimeMillis();
            System.out.println("Time for HTTP connection set up: "
                    + (endTime - starttime) + " ms");
            
            // Get the ContentType
            String type = c.getType();
            
            // Get the length and process the data
            int len = (int) c.getLength();
            if (len > 0) {
                byte[] data = new byte[len];
                int actual = is.read(data);
                System.out.println("Data received [" + actual + " of " + 
                        len + " bytes] ...");
                System.out.println(new String(data, 0, actual));
            } else {
                int ch;
                System.out.println("Data received ...");
                while ((ch = is.read()) != -1) {
                    System.out.print((char) ch);
                }                
            }
            
            System.out.flush();
            endTime = System.currentTimeMillis();
            System.out.println("Total time to retrieve page " +
                    "(including connection set up): " +
                    + (endTime - starttime) + " ms");
        } finally {
            if (is != null)
                is.close();
            if (c != null)
                c.close();
        }
    }
    
    /*    
    void postViaHttpConnection(String url) throws IOException {
        HttpConnection c = null;
        InputStream is = null;
        OutputStream os = null;
        
        try {
            c = (HttpConnection)Connector.open(url);
            
            // Set the request method and headers
            c.setRequestMethod(HttpConnection.POST);
            c.setRequestProperty("If-Modified-Since",
                    "29 Oct 1999 19:43:31 GMT");
            c.setRequestProperty("User-Agent",
                    "Profile/MIDP-1.0 Configuration/CLDC-1.0");
            c.setRequestProperty("Content-Language", "en-US");
            
            // Getting the output stream may flush the headers
            os = c.openOutputStream();
            os.write("LIST games\n".getBytes());
            os.flush();                // Optional, openInputStream will flush
            
            // Opening the InputStream will open the connection
            // and read the HTTP headers. They are stored until
            // requested.
            is = c.openInputStream();
            
            // Get the ContentType
            String type = c.getType();
            processType(type);
            
            // Get the length and process the data
            int len = (int)c.getLength();
            if (len > 0) {
                byte[] data = new byte[len];
                int actual = is.read(data);
                process(data);
            } else {
                int ch;
                while ((ch = is.read()) != -1) {
                    process((byte)ch);
                }
            }
        } finally {
            if (is != null)
                is.close();
            if (os != null)
                os.close();
            if (c != null)
                c.close();
        }
    }
*/ 
}
