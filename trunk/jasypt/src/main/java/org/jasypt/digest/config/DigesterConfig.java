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
package org.jasypt.digest.config;

import java.security.Provider;

import org.jasypt.salt.SaltGenerator;

/**
 * <p>
 * Common interface for config classes applicable to 
 * {@link org.jasypt.digest.StandardByteDigester} or 
 * {@link org.jasypt.digest.StandardStringDigester} objects. 
 * </p>
 * <p>
 * Objects of classes implementing this interface will provide values for:
 * <ul>
 *   <li>Algorithm.</li>
 *   <li>Security provider (or provider name).</li>
 *   <li>Salt size (in bytes).</li>
 *   <li>Hashing iterations.</li>
 *   <li>Salt generator.</li>
 * </ul>
 * Providing this interface lets the user create new <tt>DigesterConfig</tt>
 * classes which retrieve values for this parameters from different
 * (and maybe more secure) sources (remote servers, LDAP, other databases...),
 * and do this transparently for the digester object. 
 * </p>
 * <p>
 * The config objects passed to a digester <u>will only be queried once</u>
 * for each configuration parameter, and this will happen 
 * during the initialization of the digester object. 
 * </p>
 * <p>
 * For a default implementation, see {@link SimpleDigesterConfig}.
 * </p>
 * 
 * @since 1.0
 * 
 * @author Daniel Fern&aacute;ndez
 * 
 */
public interface DigesterConfig {

    /**
     * <p>
     * Returns the name of an algorithm to be used for hashing, like "MD5" or 
     * "SHA-1".
     * </p>
     * <p>
     * This algorithm has to be supported by your Java Virtual Machine, and
     * it should be allowed as an algorithm for creating
     * java.security.MessageDigest instances.
     * </p>
     * <p>
     * If this method returns null, the digester will ignore the config object
     * when deciding the algorithm to be used.
     * </p>
     * 
     * @return the name of the algorithm to be used, or null if this object
     *         will not want to set an algorithm. See Appendix A 
     *         in the <a target="_blank" 
     *         href="http://java.sun.com/j2se/1.5.0/docs/guide/security/CryptoSpec.html#AppA">Java 
     *         Cryptography Architecture API Specification & 
     *         Reference</a>
     *         for information about standard algorithm names.
     */
    public String getAlgorithm();

    
    /**
     * <p>
     * Returns the size of the salt to be used to compute the digest.
     * This mechanism is explained in 
     * <a href="http://www.rsasecurity.com/rsalabs/node.asp?id=2127" 
     * target="_blank">PKCS &#035;5: Password-Based Cryptography Standard</a>.
     * </p>
     * <p>
     * If salt size is set to zero, then no salt will be used.
     * </p>
     * <p>
     * If this method returns null, the digester will ignore the config object
     * when deciding the size of the salt to be used.
     * </p>
     * 
     * @return the size of the salt to be used, in bytes, or null if
     *         this object will not want to set a size for salt.
     */
    public Integer getSaltSizeBytes();

    
    /**
     * <p>
     * Returns the number of times the hash function will be applied recursively.
     * <br/>
     * The hash function will be applied to its own results as many times as 
     * specified: <i>h(h(...h(x)...))</i>
     * </p>
     * <p>
     * This mechanism is explained in 
     * <a href="http://www.rsasecurity.com/rsalabs/node.asp?id=2127" 
     * target="_blank">PKCS &#035;5: Password-Based Cryptography Standard</a>.
     * </p>
     * <p>
     * If this method returns null, the digester will ignore the config object
     * when deciding the number of hashing iterations.
     * </p>
     * 
     * @return the number of iterations, or null if this object will not want
     *         to set the number of iterations.
     */
    public Integer getIterations();

    
    /**
     * <p>
     * Returns a {@link SaltGenerator} implementation to be used by the digester.
     * </p>
     * <p>
     * If this method returns null, the digester will ignore the config object
     * when deciding the salt generator to be used.
     * </p>
     * 
     * @since 1.2
     * 
     * @return the salt generator, or null if this object will not want to set
     *         a specific SaltGenerator implementation.
     */
    public SaltGenerator getSaltGenerator();


    /**
     * <p>
     * Returns the name of the <tt>java.security.Provider</tt> implementation
     * to be used by the digester for obtaining the digest algorithm. This
     * provider must have been registered beforehand.
     * </p>
     * <p>
     * If this method returns null, the digester will ignore this parameter
     * when deciding the name of the security provider to be used.
     * </p>
     * <p>
     * If this method does not return null, and neither does {@link #getProvider()},
     * <tt>providerName</tt> will be ignored, and the provider object returned
     * by <tt>getProvider()</tt> will be used.
     * </p>
     * 
     * @since 1.3
     * 
     * @return the name of the security provider to be used.
     */
    public String getProviderName();

    
    /**
     * <p>
     * Returns the <tt>java.security.Provider</tt> implementation object
     * to be used by the digester for obtaining the digest algorithm.
     * </p>
     * <p>
     * If this method returns null, the digester will ignore this parameter
     * when deciding the security provider object to be used.
     * </p>
     * <p>
     * If this method does not return null, and neither does {@link #getProviderName()},
     * <tt>providerName</tt> will be ignored, and the provider object returned
     * by <tt>getProvider()</tt> will be used.
     * </p>
     * <p>
     * The provider returned by this method <b>does not need to be
     * registered beforehand<b>, and its use will not result in its 
     * being registered.
     * </p>
     * 
     * @since 1.3
     * 
     * @return the security provider object to be asked for the digest
     *         algorithm.
     */
    public Provider getProvider();
    
    
    /**
     * <p>
     * Returns <tt>Boolean.TRUE</tt> if the salt bytes are to be appended after the 
     * message ones before performing the digest operation on the whole. The 
     * default behaviour is to insert those bytes before the message bytes, but 
     * setting this configuration item to <tt>true</tt> allows compatibility 
     * with some external systems and specifications (e.g. LDAP {SSHA}).
     * </p>
     * 
     * @since 1.7
     * 
     * @return whether salt will be appended after the message before applying 
     *         the digest operation on the whole, instead of inserted before it
     *         (which is the default). If null is returned, the default 
     *         behaviour will be applied.
     */
    public Boolean getInvertPositionOfSaltInMessageBeforeDigesting();
    
    
    /**
     * <p>
     * Returns <tt>Boolean.TRUE</tt> if the plain (not hashed) salt bytes are to 
     * be appended after the digest operation result bytes. The default behaviour is 
     * to insert them before the digest result, but setting this configuration 
     * item to <tt>true</tt> allows compatibility with some external systems
     * and specifications (e.g. LDAP {SSHA}).
     * </p>
     * 
     * @since 1.7
     * 
     * @return whether plain salt will be appended after the digest operation 
     *         result instead of inserted before it (which is the 
     *         default). If null is returned, the default behaviour will be 
     *         applied.
     */
    public Boolean getInvertPositionOfPlainSaltInEncryptionResults();

    
}
