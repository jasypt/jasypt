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
package org.jasypt.encryption.pbe.config;

import java.io.Serializable;


/**
 * <p>
 * Common interface for config classes applicable to 
 * {@link org.jasypt.encryption.pbe.StandardPBEByteEncryptor} or 
 * {@link org.jasypt.encryption.pbe.StandardPBEStringEncryptor} objects. 
 * </p>
 * <p>
 * Objects of classes implementing this interface will provide values for:
 * <ul>
 *   <li>Algorithm.</li>
 *   <li>Password.</li>
 *   <li>Hashing iterations for obtaining the encryption key.</li>
 * </ul>
 * Providing this interface lets the user create new <tt>PBEConfig</tt>
 * classes which retrieve values for this parameters from different
 * (and maybe more secure) sources (remote servers, LDAP, other databases...),
 * and do this transparently for the encryptor object. 
 * </p>
 * <p>
 * The config objects passed to an encryptor <u>will only be queried once</u>
 * for each configuration parameter, and this will happen 
 * during the initialization of the encryptor object. 
 * </p>
 * <p>
 * For a default implementation, see {@link SimplePBEConfig}.
 * </p>
 * 
 * @since 1.0
 * 
 * @author Daniel Fern&aacute;ndez Garrido
 * 
 */
public interface PBEConfig extends Serializable {

    
    /**
     * <p>
     * Returns the algorithm to be used for encryption, like 
     * <tt>PBEWithMD5AndDES</tt>.
     * </p>
     * 
     * <p>
     * This algorithm has to be supported by your Java Virtual Machine, and
     * it must be one of the algorithms registered at 
     * {@link org.jasypt.encryption.pbe.algorithms.PBEAlgorithms}.
     * </p>
     * 
     * @return the name of the algorithm to be used.
     * @see org.jasypt.encryption.pbe.algorithms.PBEAlgorithms
     */
    public String getAlgorithm();

    
    /**
     * <p>
     * Returns the password to be used.
     * </p>
     * <p>
     * <b>There is no default value for password</b>, so not setting
     * this parameter either from a 
     * {@link org.jasypt.encryption.pbe.config.PBEConfig} object or from
     * a call to <tt>setPassword</tt> will result in an
     * EncryptionInitializationException being thrown during initialization.
     * </p>
     * 
     * @return the password to be used.
     */
    public String getPassword();

    
    /**
     * <p>
     * Returns the number of hashing iterations applied to obtain the
     * encryption key.
     * </p>
     * <p>
     * This mechanism is explained in 
     * <a href="http://www.rsasecurity.com/rsalabs/node.asp?id=2127" 
     * target="_blank">PKCS &#035;5: Password-Based Cryptography Standard</a>.
     * </p>
     * 
     * @return the number of iterations
     */
    public Integer getKeyObtentionIterations();
    
}
