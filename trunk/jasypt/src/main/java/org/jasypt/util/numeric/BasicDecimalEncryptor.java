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
package org.jasypt.util.numeric;

import java.math.BigDecimal;

import org.jasypt.encryption.pbe.StandardPBEBigDecimalEncryptor;
import org.jasypt.encryption.pbe.algorithms.PBEAlgorithms;

/**
 * <p>
 * Utility class for easily performing normal-strength encryption of 
 * BigDecimal objects.
 * </p>
 * <p>
 * This class internally holds a {@link StandardPBEBigDecimalEncryptor} 
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
 *   <li>Perform the desired <tt>{@link #encrypt(BigDecimal)}</tt> or 
 *       <tt>{@link #decrypt(BigDecimal)}</tt> operations.</li> 
 * </ol> 
 * </p>
 * <p>
 * This class is <i>thread-safe</i>.
 * </p>
 * 
 * @since 1.2
 * 
 * @author Daniel Fern&aacute;ndez Garrido
 * 
 */
public class BasicDecimalEncryptor implements DecimalEncryptor {


    // The internal encryptor 
    private StandardPBEBigDecimalEncryptor encryptor = null;
    
    
    /**
     * Creates a new instance of <tt>BasicDecimalEncryptor</tt>.
     */
    public BasicDecimalEncryptor() {
        super();
        this.encryptor = new StandardPBEBigDecimalEncryptor();
        this.encryptor.setAlgorithm(PBEAlgorithms.PBE_WITH_MD5_AND_DES);
    }

    
    /**
     * Sets a password.
     * 
     * @param password the password to be set.
     */
    public void setPassword(String password) {
        encryptor.setPassword(password);
    }


    /**
     * Encrypts a number
     * 
     * @param number the number to be encrypted.
     * @see StandardPBEBigDecimalEncryptor#encrypt(BigDecimal)
     */
    public BigDecimal encrypt(BigDecimal number) {
        return encryptor.encrypt(number);
    }
    
    
    /**
     * Decrypts a number.
     * 
     * @param encryptedNumber the number to be decrypted.
     * @see StandardPBEBigDecimalEncryptor#decrypt(BigDecimal)
     */
    public BigDecimal decrypt(BigDecimal encryptedNumber) {
        return encryptor.decrypt(encryptedNumber);
    }

}
