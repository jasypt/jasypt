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
package org.jasypt.digest;

import org.apache.commons.codec.binary.Base64;
import org.jasypt.exceptions.EncryptionOperationNotPossibleException;


public final class StandardStringDigester implements StringDigester {

    private static final String MESSAGE_CHARSET = "UTF-8";
    private static final String DIGEST_CHARSET = "US-ASCII";

    private StandardByteDigester byteDigester = null;
    private Base64 base64 = null;

    
    public StandardStringDigester() {
        this.byteDigester = new StandardByteDigester();
        this.base64 = new Base64();
    }
    
    
    public void setAlgorithm(String algorithm) {
        byteDigester.setAlgorithm(algorithm);
    }
    
    public void setSaltSizeBytes(int saltSizeBytes) {
        byteDigester.setSaltSizeBytes(saltSizeBytes);
    }

    public void setIterations(int iterations) {
        byteDigester.setIterations(iterations);
    }
    
    
    
    public String digest(String message) {
        
        if (message == null) {
            return null;
        }
        
        try {

            byte[] messageBytes = message.getBytes(MESSAGE_CHARSET);
            
            byte[] digest = byteDigester.digest(messageBytes);
            
            synchronized (base64) {
                digest = base64.encode(digest);
            }
            
            return new String(digest, DIGEST_CHARSET);
        
        } catch (Exception e) {
            throw new EncryptionOperationNotPossibleException();
        }
        
    }

    
    
    public boolean matches(String message, String digest) {

        if (message == null) {
            return (digest == null);
        } else if (digest == null) {
            return false;
        }
        
        try {
            
            byte[] messageBytes = message.getBytes(MESSAGE_CHARSET);
            byte[] digestBytes = digest.getBytes(DIGEST_CHARSET);
            
            synchronized (base64) {
                digestBytes = base64.decode(digestBytes);
            }
            
            return byteDigester.matches(messageBytes, digestBytes); 
        
        } catch (Exception e) {
            throw new EncryptionOperationNotPossibleException();
        }

    }
    
    
}
