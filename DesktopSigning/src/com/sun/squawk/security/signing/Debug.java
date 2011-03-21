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

/**
 * 
 * 
 * @author Christian
 */
public final class Debug {
    /**
         * DEBUG is used for enabling and disabling debug code, usually to write
         * debug messages which are defined in the form: <br>
         * if (Debug.ENABLED) {<some code} <br>
         * If enabled is set to false the compiler will not include the debug
         * code in the class file, as the statements are unreachable. Thus using
         * this kind of debug statements doesn't increase the size of the code.
         * This wouldn't be the case if the statement is in another method, and
         * as code size and execution time is crucial for spots no debug_output
         * method is included in the Debug class and the if statement must be
         * indcluded in the code which needs debug output.<br>
         * TODO: make a field in SigningService (reverted this changes, as Debug
         * is used in DebugClient as well)
         */

    public static final boolean ENABLED = false;

}
