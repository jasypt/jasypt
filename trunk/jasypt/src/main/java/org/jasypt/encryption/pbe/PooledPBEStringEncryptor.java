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
package org.jasypt.encryption.pbe;

import java.security.Provider;

import org.jasypt.commons.CommonUtils;
import org.jasypt.encryption.pbe.config.PBEConfig;
import org.jasypt.exceptions.AlreadyInitializedException;
import org.jasypt.salt.SaltGenerator;





/**
 * <p>
 * Pooled implementation of {@link PBEStringEncryptor} that in fact contains
 * an array of {@link StandardPBEStringEncryptor} objects which are used
 * to attend encrypt and decrypt requests in round-robin. This should
 * result in higher performance in multiprocessor systems.
 * </p>
 * <p>
 * Configuration of this class is equivalent to that of
 * {@link StandardPBEStringEncryptor}.
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
public final class PooledPBEStringEncryptor implements PBEStringCleanablePasswordEncryptor {

    
    private final StandardPBEStringEncryptor firstEncryptor;
    
    private PBEConfig config = null;
    private int poolSize = 0;
    private boolean poolSizeSet = false;
    
    private StandardPBEStringEncryptor[] pool;
    private int roundRobin = 0;


    /*
     * Flag which indicates whether the digester has been initialized or not.
     * 
     * Once initialized, no further modifications to its configuration will
     * be allowed.
     */
    private boolean initialized = false;
    
    
    
    /**
     * Creates a new instance of <tt>PooledStandardPBEStringEncryptor</tt>.
     */
    public PooledPBEStringEncryptor() {
        super();
        this.firstEncryptor = new StandardPBEStringEncryptor();
    }

    
    
    /**
     * <p>
     * Sets a <tt>{@link org.jasypt.encryption.pbe.config.PBEConfig}</tt> object 
     * for the encryptor. If this config
     * object is set, it will be asked values for:
     * </p>
     * 
     * <ul>
     *   <li>Algorithm</li>
     *   <li>Security Provider (or provider name)</li>
     *   <li>Password</li>
     *   <li>Hashing iterations for obtaining the encryption key</li>
     *   <li>Salt generator</li>
     *   <li>Output type (base64, hexadecimal) 
     *       (only <tt>StringPBEConfig</tt>)</li>
     * </ul>
     * 
     * <p>
     * The non-null values it returns will override the default ones, 
     * <i>and will be overriden by any values specified with a <tt>setX</tt>
     * method</i>.
     * </p>
     * 
     * @param config the <tt>PBEConfig</tt> object to be used as the 
     *               source for configuration parameters.
     */
    public synchronized void setConfig(final PBEConfig config) {
        this.firstEncryptor.setConfig(config);
        this.config = config;
    }

    
    /**
     * <p>
     * Sets the algorithm to be used for encryption, like 
     * <tt>PBEWithMD5AndDES</tt>.
     * </p>
     * <p>
     * This algorithm has to be supported by your JCE provider (if you specify
     * one, or the default JVM provider if you don't) and, if it is supported,
     * you can also specify <i>mode</i> and <i>padding</i> for 
     * it, like <tt>ALGORITHM/MODE/PADDING</tt>.
     * </p>
     * 
     * @param algorithm the name of the algorithm to be used.
     */
    public void setAlgorithm(final String algorithm) {
        this.firstEncryptor.setAlgorithm(algorithm);
    }

    
    /**
     * <p>
     * Sets the password to be used.
     * </p>
     * <p>
     * <b>There is no default value for password</b>, so not setting
     * this parameter either from a 
     * {@link org.jasypt.encryption.pbe.config.PBEConfig} object or from
     * a call to <tt>setPassword</tt> will result in an
     * EncryptionInitializationException being thrown during initialization.
     * </p>
     * 
     * @param password the password to be used.
     */
    public void setPassword(final String password) {
        this.firstEncryptor.setPassword(password);
    }
    
    
    /**
     * <p>
     * Sets the password to be used, as a char[].
     * </p>
     * <p>
     * This allows the password to be specified as a <i>cleanable</i>
     * char[] instead of a String, in extreme security conscious environments
     * in which no copy of the password as an immutable String should
     * be kept in memory.
     * </p>
     * <p>
     * <b>Important</b>: the array specified as a parameter WILL BE COPIED
     * in order to be stored as encryptor configuration. The caller of
     * this method will therefore be responsible for its cleaning (jasypt
     * will only clean the internally stored copy).
     * </p>
     * <p>
     * <b>There is no default value for password</b>, so not setting
     * this parameter either from a 
     * {@link org.jasypt.encryption.pbe.config.PBEConfig} object or from
     * a call to <tt>setPassword</tt> will result in an
     * EncryptionInitializationException being thrown during initialization.
     * </p>
     * 
     * @since 1.8
     * 
     * @param password the password to be used.
     */
    public synchronized void setPasswordCharArray(char[] password) {
        this.firstEncryptor.setPasswordCharArray(password);
    }
    

    /**
     * <p>
     * Set the number of hashing iterations applied to obtain the
     * encryption key.
     * </p>
     * <p>
     * This mechanism is explained in 
     * <a href="http://www.rsasecurity.com/rsalabs/node.asp?id=2127" 
     * target="_blank">PKCS &#035;5: Password-Based Cryptography Standard</a>.
     * </p>
     * 
     * @param keyObtentionIterations the number of iterations
     */
    public void setKeyObtentionIterations(final int keyObtentionIterations) {
        this.firstEncryptor.setKeyObtentionIterations(keyObtentionIterations);
    }

    
    /**
     * <p>
     * Sets the salt generator to be used. If no salt generator is specified,
     * an instance of {@link org.jasypt.salt.RandomSaltGenerator} will be used. 
     * </p>
     * 
     * @param saltGenerator the salt generator to be used.
     */
    public void setSaltGenerator(final SaltGenerator saltGenerator) {
        this.firstEncryptor.setSaltGenerator(saltGenerator);
    }
    
    
    /**
     * <p>
     * Sets the name of the security provider to be asked for the
     * encryption algorithm. This security provider has to be registered 
     * beforehand at the JVM security framework. 
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
     *                     for the encryption algorithm.
     */
    public void setProviderName(final String providerName) {
        this.firstEncryptor.setProviderName(providerName);
    }
    
    
    /**
     * <p>
     * Sets the security provider to be asked for the encryption algorithm.
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
    public void setProvider(final Provider provider) {
        this.firstEncryptor.setProvider(provider);
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
     * <p>
     * If not set, null will be returned.
     * </p>
     * 
     * @param stringOutputType the string output type.
     */
    public synchronized void setStringOutputType(final String stringOutputType) {
        this.firstEncryptor.setStringOutputType(stringOutputType);
    }

    
    
    /**
     * <p>
     * Sets the size of the pool of digesters to be created.
     * </p>
     * <p>
     * This parameter is <b>required</b>.
     * </p>
     * 
     * @param poolSize size of the pool
     */
    public synchronized void setPoolSize(final int poolSize) {
        CommonUtils.validateIsTrue(poolSize > 0, "Pool size be > 0");
        if (isInitialized()) {
            throw new AlreadyInitializedException();
        }
        this.poolSize = poolSize;
        this.poolSizeSet = true;
    }

    
    
    
    /**
     * <p>
     *   Returns true if the encryptor has already been initialized, false if
     *   not.<br/> 
     *   Initialization happens:
     * </p>
     * <ul>
     *   <li>When <tt>initialize</tt> is called.</li>
     *   <li>When <tt>encrypt</tt> or <tt>decrypt</tt> are called for the
     *       first time, if <tt>initialize</tt> has not been called before.</li>
     * </ul>
     * <p>
     *   Once an encryptor has been initialized, trying to
     *   change its configuration will
     *   result in an <tt>AlreadyInitializedException</tt> being thrown.
     * </p>
     * 
     * @return true if the encryptor has already been initialized, false if
     *         not.
     */
    public boolean isInitialized() {
        return this.initialized;
    }

    
    /**
     * <p>
     * Initialize the encryptor.
     * </p>
     * <p>
     * This operation will consist in determining the actual configuration 
     * values to be used, and then initializing the encryptor with them.
     * <br/>
     * These values are decided by applying the following priorities:
     * </p>
     * <ol>
     *   <li>First, the default values are considered (except for password).
     *   </li>
     *   <li>Then, if a 
     *       <tt>{@link org.jasypt.encryption.pbe.config.PBEConfig}</tt> 
     *       object has been set with
     *       <tt>setConfig</tt>, the non-null values returned by its
     *       <tt>getX</tt> methods override the default values.</li>
     *   <li>Finally, if the corresponding <tt>setX</tt> method has been called
     *       on the encryptor itself for any of the configuration parameters, 
     *       the values set by these calls override all of the above.</li>
     * </ol>
     * <p>
     *   Once an encryptor has been initialized, trying to
     *   change its configuration will
     *   result in an <tt>AlreadyInitializedException</tt> being thrown.
     * </p>
     * 
     * @throws EncryptionInitializationException if initialization could not
     *         be correctly done (for example, no password has been set).
     */
    public synchronized void initialize() {
        
        // Double-check to avoid synchronization issues
        if (!this.initialized) {

            if (this.config != null) {
                
                final Integer configPoolSize = this.config.getPoolSize();

                this.poolSize = 
                    ((this.poolSizeSet) || (configPoolSize == null))?
                            this.poolSize : configPoolSize.intValue();
                
            }
            
            if (this.poolSize <= 0) {
                throw new IllegalArgumentException("Pool size must be set and > 0");
            }
            
            this.pool = this.firstEncryptor.cloneAndInitializeEncryptor(this.poolSize);
            
            this.initialized = true;
            
        }
        
    }
    
    
    /**
     * <p>
     * Encrypts a message using the specified configuration.
     * </p>
     * </p>
     * The Strings returned by this method are BASE64-encoded (default) or
     * HEXADECIMAL ASCII Strings.
     * </p>
     * <p>
     * The mechanisms applied to perform the encryption operation are described
     * in <a href="http://www.rsasecurity.com/rsalabs/node.asp?id=2127" 
     * target="_blank">PKCS &#035;5: Password-Based Cryptography Standard</a>.
     * </p>
     * <p>
     * This encryptor uses a salt for each encryption
     * operation. The size of the salt depends on the algorithm
     * being used. This salt is used
     * for creating the encryption key and, if generated by a random generator,
     * it is also appended unencrypted at the beginning
     * of the results so that a decryption operation can be performed.
     * </p>
     * <p>
     * <b>If a random salt generator is used, two encryption results for 
     * the same message will always be different
     * (except in the case of random salt coincidence)</b>. This may enforce
     * security by difficulting brute force attacks on sets of data at a time
     * and forcing attackers to perform a brute force attack on each separate
     * piece of encrypted data.
     * </p>
     * 
     * @param message the String message to be encrypted
     * @return the result of encryption 
     * @throws EncryptionOperationNotPossibleException if the encryption 
     *         operation fails, ommitting any further information about the
     *         cause for security reasons.
     * @throws EncryptionInitializationException if initialization could not
     *         be correctly done (for example, no password has been set).
     */
    public String encrypt(final String message) {

        // Check initialization
        if (!isInitialized()) {
            initialize();
        }
        
        int poolPosition;
        synchronized(this) {
            poolPosition = this.roundRobin;
            this.roundRobin = (this.roundRobin + 1) % this.poolSize;
        }
        
        return this.pool[poolPosition].encrypt(message);
        
    }

    
    /**
     * <p>
     * Decrypts a message using the specified configuration.
     * </p>
     * <p>
     * This method expects to receive a BASE64-encoded (default)
     * or HEXADECIMAL ASCII String.
     * </p>
     * <p>
     * The mechanisms applied to perform the decryption operation are described
     * in <a href="http://www.rsasecurity.com/rsalabs/node.asp?id=2127" 
     * target="_blank">PKCS &#035;5: Password-Based Cryptography Standard</a>.
     * </p>
     * <p>
     * If a random salt generator is used, this decryption operation will
     * expect to find an unencrypted salt at the 
     * beginning of the encrypted input, so that the decryption operation can be
     * correctly performed (there is no other way of knowing it).
     * </p>
     * 
     * @param encryptedMessage the String message to be decrypted
     * @return the result of decryption 
     * @throws EncryptionOperationNotPossibleException if the decryption 
     *         operation fails, ommitting any further information about the
     *         cause for security reasons.
     * @throws EncryptionInitializationException if initialization could not
     *         be correctly done (for example, no password has been set).
     */
    public String decrypt(final String encryptedMessage) {

        // Check initialization
        if (!isInitialized()) {
            initialize();
        }
        
        int poolPosition;
        synchronized(this) {
            poolPosition = this.roundRobin;
            this.roundRobin = (this.roundRobin + 1) % this.poolSize;
        }
        
        return this.pool[poolPosition].decrypt(encryptedMessage);
        
    }

    
}
