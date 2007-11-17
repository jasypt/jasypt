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
package org.jasypt.encryption.pbe;

import junit.framework.TestCase;

public class SecondEncryptionAfterFailBehaviourTest extends TestCase {

    
    /*
     * This test refers to a bug in JCE Cipher implementation, documented in:
     * http://bugs.sun.com/bugdatabase/view_bug.do?bug_id=4501868
     */
    public void testSecondEncryptionAfterFailBehaviour() throws Exception {

        String vsessionid = "012345678";
        StandardPBEStringEncryptor encryptor = 
            new StandardPBEStringEncryptor();
        encryptor.setPassword("jasypt");

        try {
                encryptor.decrypt(vsessionid);
        } catch (Exception ignored) {
            // This exception will be always thrown, but ignored
        }
        String enc = encryptor.encrypt(vsessionid);
        try {
            encryptor.decrypt(enc);
        } catch (Exception e) {           
            assertTrue(false);
        }
        
    }
}
