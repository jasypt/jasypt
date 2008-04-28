/*
 * =============================================================================
 * 
 *   Copyright (c) 2007-2008, The JASYPT team (http://www.jasypt.org)
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
package org.jasypt.util.binary;

import org.jasypt.encryption.pbe.StandardPBEByteEncryptor;


/**
 * <p>
 * Utility class for easily performing normal-strength encryption of 
 * binaries (byte arrays).
 * </p>
 * <p>
 * This class internally holds a {@link StandardPBEByteEncryptor} 
 * configured this way:
 * <ul>
 *   <li>Algorithm: <tt>PBEWithMD5AndDES</tt>.</li>
 *   <li>Key obtention iterations: <tt>1000</tt>.</li>
 * </ul>
 * </p>
 * <p>
 * The required steps to use it are:
 * <ol>
 *   <li>Create an instance (using <tt>new</tt>).</li>
 *   <li>Set a password (using <tt>{@link #setPassword(String)}</tt>).</li>
 *   <li>Perform the desired <tt>{@link #encrypt(byte[])}</tt> or 
 *       <tt>{@link #decrypt(byte[])}</tt> operations.</li> 
 * </ol> 
 * </p>
 * <p>
 * This class is <i>thread-safe</i>.
 * </p>
 * 
 * @since 1.2
 * 
 * @author Daniel Fern&aacute;ndez
 * 
 */
public final class BasicBinaryEncryptor implements BinaryEncryptor {


    // The internal encryptor 
    private final StandardPBEByteEncryptor encryptor;
    
    
    /**
     * Creates a new instance of <tt>BasicBinaryEncryptor</tt>.
     */
    public BasicBinaryEncryptor() {
        super();
        this.encryptor = new StandardPBEByteEncryptor();
        this.encryptor.setAlgorithm("PBEWithMD5AndDES");
    }

    
    /**
     * Sets a password.
     * 
     * @param password the password to be set.
     */
    public void setPassword(String password) {
        this.encryptor.setPassword(password);
    }

    
    /**
     * Encrypts a byte array
     * 
     * @param binary the byte array to be encrypted.
     * @see StandardPBEByteEncryptor#encrypt(byte[])
     */
    public byte[] encrypt(byte[] binary) {
        return this.encryptor.encrypt(binary);
    }

    
    /**
     * Decrypts a byte array.
     * 
     * @param encryptedBinary the byte array to be decrypted.
     * @see StandardPBEByteEncryptor#decrypt(byte[])
     */
    public byte[] decrypt(byte[] encryptedBinary) {
        return this.encryptor.decrypt(encryptedBinary);
    }


    
}
