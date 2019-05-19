/*
 * =============================================================================
 * 
 *   Copyright (c) 2019, The JASYPT team (http://www.jasypt.org)
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
package org.jasypt.util.text;

import org.jasypt.encryption.pbe.StandardPBEStringEncryptor;
import org.jasypt.iv.RandomIvGenerator;

/**
 * <p>
 * Utility class for easily performing high-strength encryption of texts.
 * </p>
 * <p>
 * This class internally holds a {@link StandardPBEStringEncryptor} 
 * configured this way:
 * <ul>
 *   <li>Algorithm: <tt>PBEWithHMACSHA512AndAES_256"</tt>.</li>
 *   <li>Key obtention iterations: <tt>1000</tt>.</li>
 * </ul>
 * </p>
 * <p>
 * The required steps to use it are:
 * <ol>
 *   <li>Create an instance (using <tt>new</tt>).</li>
 *   <li>Set a password (using <tt>{@link #setPassword(String)}</tt> or
 *       <tt>{@link #setPasswordCharArray(char[])}</tt>).</li>
 *   <li>Perform the desired <tt>{@link #encrypt(String)}</tt> or 
 *       <tt>{@link #decrypt(String)}</tt> operations.</li> 
 * </ol> 
 * </p>
 * <p>
 * This class is <i>thread-safe</i>.
 * </p>
 * 
 * @since 1.9.3
 * 
 * @author Hoki Torres
 * 
 */
public final class AES256TextEncryptor implements TextEncryptor {


    // The internal encryptor
    private final StandardPBEStringEncryptor encryptor;



    /**
     * Creates a new instance of <tt>StrongTextEncryptor</tt>.
     */
    public AES256TextEncryptor() {
        super();
        this.encryptor = new StandardPBEStringEncryptor();
        this.encryptor.setAlgorithm("PBEWithHMACSHA512AndAES_256");
        this.encryptor.setIvGenerator(new RandomIvGenerator());
    }

    
    /**
     * Sets a password.
     * 
     * @param password the password to be set.
     */
    public void setPassword(final String password) {
        this.encryptor.setPassword(password);
    }

    
    /**
     * Sets a password, as a char[].
     *
     * @param password the password to be set.
     */
    public void setPasswordCharArray(final char[] password) {
        this.encryptor.setPasswordCharArray(password);
    }

    
    /**
     * Encrypts a message.
     * 
     * @param message the message to be encrypted.
     * @see StandardPBEStringEncryptor#encrypt(String)
     */
    public String encrypt(final String message) {
        return this.encryptor.encrypt(message);
    }
    

    /**
     * Decrypts a message.
     * 
     * @param encryptedMessage the message to be decrypted.
     * @see StandardPBEStringEncryptor#decrypt(String)
     */
    public String decrypt(final String encryptedMessage) {
        return this.encryptor.decrypt(encryptedMessage);
    }
    
}
