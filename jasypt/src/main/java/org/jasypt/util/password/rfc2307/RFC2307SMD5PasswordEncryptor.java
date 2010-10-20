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
package org.jasypt.util.password.rfc2307;

import org.jasypt.digest.StandardStringDigester;
import org.jasypt.util.password.PasswordEncryptor;

/**
 * <p>
 * Utility class for easily performing password digesting and checking
 * according to {SMD5}, a password encryption scheme defined in RFC2307
 * and commonly found in LDAP systems.
 * </p>
 * <p>
 * This class internally holds a {@link StandardStringDigester} 
 * configured this way:
 * <ul>
 *   <li>Algorithm: <tt>MD5</tt>.</li>
 *   <li>Salt size: <tt>8 bytes</tt> (configurable with {@link #setSaltSizeBytes(int)}).</li>
 *   <li>Iterations: <tt>1</tt> (no hash iteration).</li>
 *   <li>Prefix: <tt>{SMD5}</tt>.</li>
 *   <li>Invert position of salt in message before digesting: <tt>true</tt>.</li>
 *   <li>Invert position of plain salt in encryption results: <tt>true</tt>.</li>
 * </ul>
 * </p>
 * <p>
 * This class is <i>thread-safe</i>
 * </p>
 * 
 * @since 1.7
 * 
 * @author Daniel Fern&aacute;ndez
 * 
 */
public final class RFC2307SMD5PasswordEncryptor implements PasswordEncryptor {

    // The internal digester used
    private final StandardStringDigester digester;
    
    
    /**
     * Creates a new instance of <tt>RFC2307OpenLDAPSSHAPasswordEncryptor</tt>
     *
     */
    public RFC2307SMD5PasswordEncryptor() {
        super();
        this.digester = new StandardStringDigester();
        this.digester.setAlgorithm("MD5");
        this.digester.setIterations(1);
        this.digester.setSaltSizeBytes(8);
        this.digester.setPrefix("{SMD5}");
        this.digester.setInvertPositionOfSaltInMessageBeforeDigesting(true);
        this.digester.setInvertPositionOfPlainSaltInEncryptionResults(true);
    }

    
    /**
     * <p>
     * Sets the size (in bytes) of the salt to be used. 
     * </p>
     * <p>
     * Default is 4, which is the value used by OpenLDAP. Other scenarios
     * might require different values (for example, SunONE uses an
     * 8-byte salt).
     * </p>
     * 
     * @param saltSizeBytes the salt size in bytes
     */
    public void setSaltSizeBytes(final int saltSizeBytes) {
        this.digester.setSaltSizeBytes(saltSizeBytes);
    }

    
    /**
     * <p>
     * Sets the the form in which String output
     * will be encoded. Available encoding types are:
     * </p>
     * <ul>
     *   <li><tt><b>base64</b></tt> (default)</li>
     *   <li><tt><b>hexadecimal</b></tt></li>
     * </ul>
     * 
     * @param stringOutputType the string output type.
     */
    public void setStringOutputType(final String stringOutputType) {
        this.digester.setStringOutputType(stringOutputType);
    }
    
    
    /**
     * Encrypts (digests) a password.
     * 
     * @param password the password to be encrypted.
     * @return the resulting digest.
     * @see StandardStringDigester#digest(String)
     */
    public String encryptPassword(final String password) {
        return this.digester.digest(password);
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
    public boolean checkPassword(final String plainPassword, 
            final String encryptedPassword) {
        return this.digester.matches(plainPassword, encryptedPassword);
    }
 
    
    
}
