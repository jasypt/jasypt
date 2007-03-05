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
package org.jasypt.util.password;

import org.jasypt.digest.StandardByteDigester;
import org.jasypt.digest.StandardStringDigester;
import org.jasypt.digest.config.DigesterConfig;

/**
 * <p>
 * Utility class for easily performing password digesting and checking.
 * </p>
 * <p>
 * This class internally holds a {@link StandardStringDigester}
 * which can be configured by the user by optionally choosing the algorithm 
 * to be used, the mechanism of encryption (plain digests vs. use of salt
 * and iteration count) and even use a {@link DigesterConfig} object for
 * more advanced configuration.
 * </p>
 * <p>
 * The results obtained when encoding with this class are encoded in
 * BASE64 form.
 * </p>
 * <p>
 * The required steps to use it are:
 * <ol>
 *   <li>Create an instance (using <tt>new</tt>).</li>
 *   <li>Configure if needed with the <tt>setX()</tt> methods.</li>
 *   <li>Perform the desired <tt>{@link #encryptPassword(String)}</tt> or 
 *       <tt>{@link #checkPassword(String, String)}</tt> 
 *       operations.</li> 
 * </ol> 
 * </p>
 * <p>
 * This class is <i>thread-safe</i>
 * </p>
 * 
 * @since 1.2
 * 
 * @author Daniel Fern&aacute;ndez Garrido
 * 
 */
public final class ConfigurablePasswordEncryptor implements PasswordEncryptor {

    // The internal digester used
    private StandardStringDigester digester = null;
    
    
    /**
     * Creates a new instance of <tt>ConfigurablePasswordEncryptor</tt>
     *
     */
    public ConfigurablePasswordEncryptor() {
        super();
        this.digester = new StandardStringDigester();
    }


    /**
     * Lets the user configure this encryptor with a {@link DigesterConfig}
     * object, like if he/she were using a {@link StandardStringDigester} object
     * directly.
     * 
     * @param config the DigesterConfig object to be set for configuration.
     * @see StandardStringDigester#setConfig(DigesterConfig)
     */
    public void setConfig(DigesterConfig config) {
        this.digester.setConfig(config);
    }


    /**
     * <p>
     * Sets the algorithm to be used for digesting, like <tt>MD5</tt> 
     * or <tt>SHA-1</tt>.
     * </p>
     * 
     * <p>
     * This algorithm has to be supported by your Java Virtual Machine, and
     * it should be allowed as an algorithm for creating
     * java.security.MessageDigest instances.
     * </p>
     * 
     * @param algorithm the name of the algorithm to be used. See Appendix A 
     *                  in the <a target="_blank" 
     *                  href="http://java.sun.com/j2se/1.5.0/docs/guide/security/CryptoSpec.html#AppA">Java 
     *                  Cryptography Architecture API Specification & 
     *                  Reference</a>
     *                  for information about standard algorithm names.
     * @see StandardStringDigester#setAlgorithm(String)
     */
    public void setAlgorithm(String algorithm) {
        this.digester.setAlgorithm(algorithm);
    }
    

    /**
     * Lets the user specify if he/she wants a plain digest used as an
     * encryption mechanism (no salt or iterations, as with 
     * {@link java.security.MessageDigest}), or rather use the
     * jasypt's usual stronger mechanism for password encryption (based
     * on the use of a salt and the iteration of the hash function).
     * 
     * @param plainDigest true for using plain digests, false for the strong
     *        salt and iteration count based mechanism.
     */
    public void setPlainDigest(boolean plainDigest) {
        if (plainDigest) {
            this.digester.setIterations(1);
            this.digester.setSaltSizeBytes(0);
        } else {
            this.digester.setIterations(StandardByteDigester.DEFAULT_ITERATIONS);
            this.digester.setSaltSizeBytes(StandardByteDigester.DEFAULT_SALT_SIZE_BYTES);
        }
    }
    
    
    /**
     * Encrypts (digests) a password.
     * 
     * @param password the password to be encrypted.
     * @return the resulting digest.
     * @see StandardStringDigester#digest(String)
     */
    public String encryptPassword(String password) {
        return digester.digest(password);
    }

    
    /**
     * Checks an unencrypted (plain) password against an encrypted one
     * (a digest) to see if they match.
     * 
     * @param plainPassword the plain password to check.
     * @param encryptedPassword the digest against which to check the password.
     * @return true if passwords match, false if not.
     * @see StandardStringDigester#matches(String, String)
     */
    public boolean checkPassword(String plainPassword, 
            String encryptedPassword) {
        return digester.matches(plainPassword, encryptedPassword);
    }
    
}
