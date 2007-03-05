/*
 * =============================================================================
 * 
 *   Copyright (c) 2007, The JASYPT team (http://www.jasypt.org)
 * 
 *   Licensed under the Apache License, Version 2.0 (the "License");
 *   you may not use this file except in compliance with the License.
 *   You may obtain a copy of the License at
 * 
 *       http://www.apache.org/licenses/LICENSE-2.0
 * 
 *   Unless required by applicable law or agreed to in writing, software
 *   distributed under the License is distributed on an "AS IS" BASIS,
 *   WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 *   See the License for the specific language governing permissions and
 *   limitations under the License.
 * 
 * =============================================================================
 */
package org.jasypt.util.digest;


import java.security.MessageDigest;

import junit.framework.TestCase;

import org.apache.commons.lang.ArrayUtils;

public class MessageDigesterTest extends TestCase {

    
    
    public void testDigest() throws Exception {
        
        byte[] message = "This is a Message".getBytes("UTF-8");
        
        MessageDigester messageDigester = new MessageDigester();
        byte[] encryptedMessage = messageDigester.digest(message);
        
        MessageDigest md = MessageDigest.getInstance("MD5");
        
        for (int i = 0; i < 100; i++) {
            assertTrue(ArrayUtils.isEquals(md.digest(message), encryptedMessage));
        }
        
        byte[] message2 = "This is a  Message".getBytes("UTF-8");
        for (int i = 0; i < 100; i++) {
            assertFalse(ArrayUtils.isEquals(md.digest(message2), encryptedMessage));
        }
        
        MessageDigester messageDigester2 = new MessageDigester();
        messageDigester2.setAlgorithm("SHA-1");
        byte[] encryptedMessage2 = messageDigester2.digest(message);
        
        MessageDigest md2 = MessageDigest.getInstance("SHA-1");
        
        for (int i = 0; i < 100; i++) {
            assertTrue(ArrayUtils.isEquals(md2.digest(message), encryptedMessage2));
        }
        
        
    }

    
}
