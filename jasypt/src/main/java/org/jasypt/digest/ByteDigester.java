/*
 * =============================================================================
 * 
 *   Copyright (c) 2007-2010, The JASYPT team (http://www.jasypt.org)
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

/**
 * <p>
 * Common interface for all digesters which receive a byte array message and 
 * return a byte array digest.
 * </p>
 * <p>
 * For a default implementation, see {@link StandardByteDigester}.
 * </p>
 * 
 * @since 1.0
 * 
 * @author Daniel Fern&aacute;ndez
 * 
 */
public interface ByteDigester {


    /**
     * <p>
     * Create a digest of the input message.
     * </p>
     * 
     * @param message the message to be digested
     * @return the digest
     */
    public byte[] digest(byte[] message);
    
    
    /**
     * <p>
     * Check whether a message matches a digest, managing aspects like
     * salt, hashing iterations, etc. (if applicable).
     * </p>
     * 
     * @param message the message to check
     * @param digest the digest to check
     * @return TRUE if the message matches the digest, FALSE if not.
     */
    public boolean matches(byte[] message, byte[] digest);

}
