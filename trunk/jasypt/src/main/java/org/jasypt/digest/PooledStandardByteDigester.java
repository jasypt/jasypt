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

import java.security.Provider;

import org.jasypt.digest.config.DigesterConfig;
import org.jasypt.exceptions.EncryptionInitializationException;
import org.jasypt.exceptions.EncryptionOperationNotPossibleException;
import org.jasypt.salt.SaltGenerator;



/**
 * <p>
 * Pooled implementation of {@link ByteDigester} that in fact contains
 * an array of {@link StandardByteDigester} objects which are used
 * to attend digest and match requests in round-robin. This should
 * result in higher performance in multiprocessor systems.
 * </p>
 * <p>
 * Configuration of this class is equivalent to that of
 * {@link StandardByteDigester}.
 * </p>
 * <p>
 * This class is <i>thread-safe</i>.
 * </p>
 * 
 * 
 * @since 1.7
 * 
 * @author Daniel Fern&aacute;ndez
 *
 */
public class PooledStandardByteDigester implements ByteDigester {

    
    private final int poolSize;
    private final StandardByteDigester[] pool;
    private int roundRobin = 0;


    /*
     * Flag which indicates whether the digester has been initialized or not.
     * 
     * Once initialized, no further modifications to its configuration will
     * be allowed.
     */
    private boolean initialized = false;
    
    
    
    /**
     * Creates a new instance of <tt>PooledStandardByteDigester</tt>.
     */
    public PooledStandardByteDigester(final int poolSize) {
        super();
        if (poolSize < 1) {
            throw new IllegalArgumentException("Pool size must be > 0");
        }
        this.poolSize = poolSize;
        this.pool = new StandardByteDigester[this.poolSize];
        this.pool[0] = new StandardByteDigester();
    }
    
    
    /**
     * <p>
     * Sets a <tt>{@link org.jasypt.digest.config.DigesterConfig}</tt> object 
     * for the digester. If this config
     * object is set, it will be asked values for:
     * </p>
     * 
     * <ul>
     *   <li>Algorithm</li>
     *   <li>Security Provider (or provider name)</li>
     *   <li>Salt size</li>
     *   <li>Hashing iterations</li>
     *   <li>Salt generator</li>
     *   <li>Location of the salt in relation to the encrypted message 
     *       (default: before)</li>
     * </ul>
     * 
     * <p>
     * The non-null values it returns will override the default ones, 
     * <i>and will be overriden by any values specified with a <tt>setX</tt>
     * method</i>.
     * </p>
     * 
     * @param config the <tt>DigesterConfig</tt> object to be used as the 
     *               source for configuration parameters.
     */
    public synchronized void setConfig(final DigesterConfig config) {
        this.pool[0].setConfig(config);
    }
    
    
    /**
     * <p>
     * Sets the algorithm to be used for digesting, like <tt>MD5</tt> 
     * or <tt>SHA-1</tt>.
     * </p>
     * <p>
     * This algorithm has to be supported by your security infrastructure, and
     * it should be allowed as an algorithm for creating
     * java.security.MessageDigest instances.
     * </p>
     * <p>
     * If you are specifying a security provider with {@link #setProvider(Provider)} or
     * {@link #setProviderName(String)}, this algorithm should be
     * supported by your specified provider.
     * </p>
     * <p>
     * If you are not specifying a provider, you will be able to use those
     * algorithms provided by the default security provider of your JVM vendor.
     * For valid names in the Sun JVM, see <a target="_blank" 
     *         href="http://java.sun.com/j2se/1.5.0/docs/guide/security/CryptoSpec.html#AppA">Java 
     *         Cryptography Architecture API Specification & 
     *         Reference</a>.
     * </p>
     * 
     * @param algorithm the name of the algorithm to be used.
     */
    public synchronized void setAlgorithm(final String algorithm) {
        this.pool[0].setAlgorithm(algorithm);
    }
    
    
    /**
     * <p>
     * Sets the size of the salt to be used to compute the digest.
     * This mechanism is explained in 
     * <a href="http://www.rsasecurity.com/rsalabs/node.asp?id=2127" 
     * target="_blank">PKCS &#035;5: Password-Based Cryptography Standard</a>.
     * </p>
     * 
     * <p>
     * If salt size is set to zero, then no salt will be used.
     * </p>
     * 
     * @param saltSizeBytes the size of the salt to be used, in bytes.
     */
    public synchronized void setSaltSizeBytes(final int saltSizeBytes) {
        this.pool[0].setSaltSizeBytes(saltSizeBytes);
    }

    
    /**
     * <p>
     * Set the number of times the hash function will be applied recursively.
     * <br/>
     * The hash function will be applied to its own results as many times as 
     * specified: <i>h(h(...h(x)...))</i>
     * </p>
     * <p>
     * This mechanism is explained in 
     * <a href="http://www.rsasecurity.com/rsalabs/node.asp?id=2127" 
     * target="_blank">PKCS &#035;5: Password-Based Cryptography Standard</a>.
     * </p>
     * 
     * @param iterations the number of iterations.
     */
    public synchronized void setIterations(final int iterations) {
        this.pool[0].setIterations(iterations);
    }

    
    /**
     * <p>
     * Sets the salt generator to be used. If no salt generator is specified,
     * an instance of {@link org.jasypt.salt.RandomSaltGenerator} will be used. 
     * </p>
     * 
     * @param saltGenerator the salt generator to be used.
     */
    public synchronized void setSaltGenerator(final SaltGenerator saltGenerator) {
        this.pool[0].setSaltGenerator(saltGenerator);
    }
    
    
    /**
     * <p>
     * Sets the name of the security provider to be asked for the
     * digest algorithm. This security provider has to be registered beforehand
     * at the JVM security framework. 
     * </p>
     * <p>
     * The provider can also be set with the {@link #setProvider(Provider)}
     * method, in which case it will not be necessary neither registering
     * the provider beforehand,
     * nor calling this {@link #setProviderName(String)} method to specify
     * a provider name.
     * </p>
     * <p>
     * Note that a call to {@link #setProvider(Provider)} overrides any value 
     * set by this method.
     * </p>
     * <p>
     * If no provider name / provider is explicitly set, the default JVM
     * provider will be used.
     * </p>
     * 
     * @param providerName the name of the security provider to be asked
     *                     for the digest algorithm.
     */
    public synchronized void setProviderName(final String providerName) {
        this.pool[0].setProviderName(providerName);
    }
    
    
    /**
     * <p>
     * Sets the security provider to be asked for the digest algorithm.
     * The provider does not have to be registered at the security 
     * infrastructure beforehand, and its being used here will not result in
     * its being registered.
     * </p>
     * <p>
     * If this method is called, calling {@link #setProviderName(String)}
     * becomes unnecessary.
     * </p>
     * <p>
     * If no provider name / provider is explicitly set, the default JVM
     * provider will be used.
     * </p>
     * 
     * @param provider the provider to be asked for the chosen algorithm
     */
    public synchronized void setProvider(final Provider provider) {
        this.pool[0].setProvider(provider);
    }
    
    
    /**
     * <p>
     * Whether the salt bytes are to be appended after the 
     * message ones before performing the digest operation on the whole. The 
     * default behaviour is to insert those bytes before the message bytes, but 
     * setting this configuration item to <tt>true</tt> allows compatibility 
     * with some external systems and specifications (e.g. LDAP {SSHA}).
     * </p>
     * <p>
     * If this parameter is not explicitly set, the default behaviour 
     * (insertion of salt before message) will be applied.
     * </p>
     * 
     * @param invertPositionOfSaltInMessageBeforeDigesting
     *        whether salt will be appended after the message before applying 
     *        the digest operation on the whole, instead of inserted before it
     *        (which is the default).
     */
    public synchronized void setInvertPositionOfSaltInMessageBeforeDigesting(
            final boolean invertPositionOfSaltInMessageBeforeDigesting) {
        this.pool[0].setInvertPositionOfSaltInMessageBeforeDigesting(invertPositionOfSaltInMessageBeforeDigesting);
    }
    
    
    /**
     * <p>
     * Whether the plain (not hashed) salt bytes are to 
     * be appended after the digest operation result bytes. The default behaviour is 
     * to insert them before the digest result, but setting this configuration 
     * item to <tt>true</tt> allows compatibility with some external systems
     * and specifications (e.g. LDAP {SSHA}).
     * </p>
     * <p>
     * If this parameter is not explicitly set, the default behaviour 
     * (insertion of plain salt before digest result) will be applied.
     * </p>
     * 
     * @since 1.7
     * 
     * @param invertPositionOfPlainSaltInEncryptionResults
     *        whether plain salt will be appended after the digest operation 
     *        result instead of inserted before it (which is the 
     *        default).
     */
    public synchronized void setInvertPositionOfPlainSaltInEncryptionResults(
            final boolean invertPositionOfPlainSaltInEncryptionResults) {
        this.pool[0].setInvertPositionOfPlainSaltInEncryptionResults(invertPositionOfPlainSaltInEncryptionResults);
    }

    
    
    /**
     * <p>
     * Whether digest matching operations will allow matching
     * digests with a salt size different to the one configured in the "saltSizeBytes"
     * property. This is possible because digest algorithms will produce a fixed-size 
     * result, so the remaining bytes from the hashed input will be considered salt.
     * </p>
     * <p>
     * This will allow the digester to match digests produced in environments which do not
     * establish a fixed salt size as standard (for example, SSHA password encryption
     * in LDAP systems).  
     * </p>
     * <p>
     * The value of this property will <b>not</b> affect the creation of digests, 
     * which will always have a salt of the size established by the "saltSizeBytes" 
     * property. It will only affect digest matching.  
     * </p>
     * <p>
     * Setting this property to <tt>true</tt> is not compatible with {@link SaltGenerator}
     * implementations which return false for their 
     * {@link SaltGenerator#includePlainSaltInEncryptionResults()} property. 
     * </p>
     * <p>
     * Also, be aware that some algorithms or algorithm providers might not support
     * knowing the size of the digests beforehand, which is also incompatible with
     * a lenient behaviour.
     * </p>
     * <p>
     * If this parameter is not explicitly set, the default behaviour 
     * (NOT lenient) will be applied.
     * </p>
     * 
     * @param useLenientSaltSizeCheck whether the digester will allow matching of 
     *        digests with different salt sizes than established or not (default 
     *        is false).
     */
    public synchronized void setUseLenientSaltSizeCheck(final boolean useLenientSaltSizeCheck) {
        this.pool[0].setUseLenientSaltSizeCheck(useLenientSaltSizeCheck);
    }



    
    /**
     * <p>
     *   Returns true if the digester has already been initialized, false if
     *   not.<br/> 
     *   Initialization happens:
     * </p>
     * <ul>
     *   <li>When <tt>initialize</tt> is called.</li>
     *   <li>When <tt>digest</tt> or <tt>matches</tt> are called for the
     *       first time, if <tt>initialize</tt> has not been called before.</li>
     * </ul>
     * <p>
     *   Once a digester has been initialized, trying to
     *   change its configuration (algorithm, provider, salt size, iterations
     *   or salt generator) will
     *   result in an <tt>AlreadyInitializedException</tt> being thrown.
     * </p>
     * 
     * @return true if the digester has already been initialized, false if
     *   not.
     */
    public boolean isInitialized() {
        return this.initialized;
    }
    

    
    
    /**
     * <p>
     * Initialize the digester.
     * </p>
     * <p>
     * This operation will consist in determining the actual configuration 
     * values to be used, and then initializing the digester with them.
     * <br/>
     * These values are decided by applying the following priorities:
     * </p>
     * <ol>
     *   <li>First, the default values are considered.</li>
     *   <li>Then, if a 
     *       <tt>{@link org.jasypt.digest.config.DigesterConfig}</tt> 
     *       object has been set with
     *       <tt>setConfig</tt>, the non-null values returned by its
     *       <tt>getX</tt> methods override the default values.</li>
     *   <li>Finally, if the corresponding <tt>setX</tt> method has been called
     *       on the digester itself for any of the configuration parameters, the 
     *       values set by these calls override all of the above.</li>
     * </ol>
     * <p>
     *   Once a digester has been initialized, trying to
     *   change its configuration will result in an 
     *   <tt>AlreadyInitializedException</tt> being thrown.
     * </p>
     * 
     * @throws EncryptionInitializationException if initialization could not
     *         be correctly done (for example, if the digest algorithm chosen
     *         cannot be used).
     *
     */
    public synchronized void initialize() {
        
        // Double-check to avoid synchronization issues
        if (!this.initialized) {

            for (int i = 1; i < this.poolSize; i++) {
                this.pool[i] = this.pool[i - 1].cloneDigester();
            }
            
            this.initialized = true;
            
        }
        
    }
    

    
    
    /**
     * <p>
     * Performs a digest operation on a byte array message.
     * </p>
     * <p>
     * The steps taken for creating the digest are:
     * <ol>
     *   <li>A salt of the specified size is generated (see 
     *       {@link SaltGenerator}).</li>
     *   <li>The salt bytes are added to the message.</li>
     *   <li>The hash function is applied to the salt and message altogether, 
     *       and then to the
     *       results of the function itself, as many times as specified
     *       (iterations).</li>
     *   <li>If specified by the salt generator (see 
     *       {@link org.jasypt.salt.SaltGenerator#includePlainSaltInEncryptionResults()}), 
     *       the <i>undigested</i> salt and the final result of the hash
     *       function are concatenated and returned as a result.</li>
     * </ol>
     * Put schematically in bytes:
     * <ul>
     *   <li>
     *     DIGEST = <tt>|<b>S</b>|..(ssb)..|<b>S</b>|<b>X</b>|<b>X</b>|<b>X</b>|...|<b>X</b>|</tt>
     *       <ul>
     *         <li><tt><b>S</b></tt>: salt bytes (plain, not digested). <i>(OPTIONAL)</i>.</li>
     *         <li><tt>ssb</tt>: salt size in bytes.</li>
     *         <li><tt><b>X</b></tt>: bytes resulting from hashing (see below).</li>
     *       </ul>
     *   </li>
     *   <li>
     *     <tt>|<b>X</b>|<b>X</b>|<b>X</b>|...|<b>X</b>|</tt> = 
     *     <tt><i>H</i>(<i>H</i>(<i>H</i>(..(it)..<i>H</i>(<b>Z</b>|<b>Z</b>|<b>Z</b>|...|<b>Z</b>|))))</tt>
     *     <ul>
     *       <li><tt><i>H</i></tt>: Hash function (algorithm).</li>
     *       <li><tt>it</tt>: Number of iterations.</li>
     *       <li><tt><b>Z</b></tt>: Input for hashing (see below).</li> 
     *     </ul>
     *   </li>
     *   <li>
     *     <tt>|<b>Z</b>|<b>Z</b>|<b>Z</b>|...|<b>Z</b>|</tt> =
     *     <tt>|<b>S</b>|..(ssb)..|<b>S</b>|<b>M</b>|<b>M</b>|<b>M</b>...|<b>M</b>|</tt>
     *     <ul>
     *         <li><tt><b>S</b></tt>: salt bytes (plain, not digested).</li>
     *         <li><tt>ssb</tt>: salt size in bytes.</li>
     *         <li><tt><b>M</b></tt>: message bytes.</li>
     *     </ul>
     *   </li>
     * </ul>
     * </p>
     * <p>
     * <b>If a random salt generator is used, two digests created for the same 
     * message will always be different
     * (except in the case of random salt coincidence).</b>
     * Because of this, in this case the result of the <tt>digest</tt> method 
     * will contain both the <i>undigested</i> salt and the digest of the 
     * (salt + message), so that another digest operation can be performed 
     * with the same salt on a different message to check if both messages 
     * match (all of which will be managed automatically by the 
     * <tt>matches</tt> method).
     * </p>
     * 
     * @param message the byte array to be digested 
     * @return the digest result
     * @throws EncryptionOperationNotPossibleException if the digest operation
     *         fails, ommitting any further information about the cause for
     *         security reasons.
     * @throws EncryptionInitializationException if initialization could not
     *         be correctly done (for example, if the digest algorithm chosen
     *         cannot be used).
     *         
     */
    public byte[] digest(byte[] message) {

        // Check initialization
        if (!isInitialized()) {
            initialize();
        }
        
        int poolPosition;
        synchronized(this) {
            poolPosition = this.roundRobin;
            this.roundRobin = (this.roundRobin + 1) % this.poolSize;
        }
        
        return this.pool[poolPosition].digest(message);
        
    }
    
    
    
    
    /**
     * <p>
     * Checks a message against a given digest.
     * </p>
     * <p>
     * This method tells whether a message corresponds to a specific digest
     * or not by getting the salt with which the digest was created and
     * applying it to a digest operation performed on the message. If 
     * new and existing digest match, the message is said to match the digest.
     * </p>
     * <p>
     * This method will be used, for instance, for password checking in
     * authentication processes.
     * </p>
     * <p>
     * A null message will only match a null digest.
     * </p>
     * 
     * @param message the message to be compared to the digest.
     * @param digest the digest. 
     * @return true if the specified message matches the digest, false
     *         if not.
     * @throws EncryptionOperationNotPossibleException if the digest matching
     *         operation fails, ommitting any further information about the 
     *         cause for security reasons.
     * @throws EncryptionInitializationException if initialization could not
     *         be correctly done (for example, if the digest algorithm chosen
     *         cannot be used).
     */
    public boolean matches(final byte[] message, final byte[] digest) {

        // Check initialization
        if (!isInitialized()) {
            initialize();
        }
        
        int poolPosition;
        synchronized(this) {
            poolPosition = this.roundRobin;
            this.roundRobin = (this.roundRobin + 1) % this.poolSize;
        }
        
        return this.pool[poolPosition].matches(message, digest);
        
    }

    
    
    
}
