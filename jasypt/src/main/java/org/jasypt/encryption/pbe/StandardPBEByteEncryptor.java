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
package org.jasypt.encryption.pbe;

import java.security.InvalidKeyException;

import javax.crypto.Cipher;
import javax.crypto.SecretKey;
import javax.crypto.SecretKeyFactory;
import javax.crypto.spec.PBEKeySpec;
import javax.crypto.spec.PBEParameterSpec;

import org.apache.commons.lang.ArrayUtils;
import org.apache.commons.lang.Validate;
import org.jasypt.encryption.pbe.algorithms.PBEAlgorithms;
import org.jasypt.encryption.pbe.config.PBEConfig;
import org.jasypt.exceptions.AlreadyInitializedException;
import org.jasypt.exceptions.EncryptionInitializationException;
import org.jasypt.exceptions.EncryptionOperationNotPossibleException;
import org.jasypt.salt.SaltGeneration;

/**
 * <p>
 * Standard implementation of the {@link PBEByteEncryptor} interface.
 * This class lets the user specify the algorithm to be used for 
 * encryption, the password to use, and
 * the number of hashing iterations that will be applied for obtaining
 * the encryption key.
 * </p>
 * <p>
 * This class is <i>thread-safe</i>.
 * </p>
 * <p>
 * <br/><b><u>Configuration</u></b>
 * </p>
 * <p>
 * The algorithm, password and key-obtention iterations can take 
 * values in any of these ways:
 * <ul>
 *   <li>Using its default values (except for password).</li>
 *   <li>Setting a <tt>{@link org.jasypt.encryption.pbe.config.PBEConfig}</tt> 
 *       object which provides new 
 *       configuration values.</li>
 *   <li>Calling the corresponding <tt>setAlgorithm</tt>, 
 *       <tt>setPassword</tt> or <tt>setKeyObtentionIterations</tt> 
 *       methods.</li>
 * </ul>
 * And the actual values to be used for initialization will be established
 * by applying the following priorities:
 * <ol>
 *   <li>First, the default values are considered (except for password).</li>
 *   <li>Then, if a <tt>{@link org.jasypt.encryption.pbe.config.PBEConfig}</tt> 
 *       object has been set with
 *       <tt>setConfig</tt>, the non-null values returned by its
 *       <tt>getX</tt> methods override the default values.</li>
 *   <li>Finally, if the corresponding <tt>setX</tt> method has been called
 *       on the encryptor itself for any of the configuration parameters, the 
 *       values set by these calls override all of the above.</li>
 * </ol>
 * </p>
 * 
 * <p>
 * <br/><b><u>Initialization</u></b>
 * </p>
 * <p>
 * Before it is ready to encrypt, an object of this class has to be
 * <i>initialized</i>. Initialization happens:
 * <ul>
 *   <li>When <tt>initialize</tt> is called.</li>
 *   <li>When <tt>encrypt</tt> or <tt>decrypt</tt> are called for the
 *       first time, if <tt>initialize</tt> has not been called before.</li>
 * </ul>
 * Once an encryptor has been initialized, trying to
 * change its configuration will
 * result in an <tt>AlreadyInitializedException</tt> being thrown.
 * </p>
 * 
 * <p>
 * <br/><b><u>Usage</u></b>
 * </p>
 * <p>
 * An ecryptor may be used for:
 * <ul>
 *   <li><i>Encrypting messages</i>, by calling the <tt>encrypt</tt> method.</li>
 *   <li><i>Decrypting messages</i>, by calling the <tt>decrypt</tt> method.</li> 
 * </ul>
 * <b>Because of the use of a random salt, two encryption results for 
 * the same message will always be different
 * (except in the case of random salt coincidence)</b>. This enforces
 * security by difficulting brute force attacks on sets of data at a time
 * and forcing attackers to perform a brute force attack on each separate
 * piece of encrypted data.
 * </p>
 * <p>     
 * To learn more about the mechanisms involved in encryption, read
 * <a href="http://www.rsasecurity.com/rsalabs/node.asp?id=2127" 
 * target="_blank">PKCS &#035;5: Password-Based Cryptography Standard</a>.
 * </p>
 * 
 * @since 1.0
 * 
 * @author Daniel Fern&aacute;ndez Garrido
 * 
 */
public final class StandardPBEByteEncryptor implements PBEByteEncryptor {
    
    /**
     * The default algorithm to be used if none specified: PBEWithMD5AndDES.
     */
    public static final String DEFAULT_ALGORITHM = 
        PBEAlgorithms.PBE_WITH_MD5_AND_DES;

    /**
     * The default number of hashing iterations applied for obtaining the
     * encryption key from the specified password, set to 1000. 
     */
    public static final int DEFAULT_KEY_OBTENTION_ITERATIONS = 1000;


    // Algorithm for Password Based Encoding. Must be registered in 
    // org.jasypt.encryption.pbe.algorithms.PBEAlgorithms.
    private String algorithm = DEFAULT_ALGORITHM;
    
    // Password to be applied. This will NOT have a default value. If none
    // is set during configuration, an exception will be thrown.
    private String password = null;
    
    // Number of hashing iterations to be applied for obtaining the encryption
    // key from the specified password.
    private int keyObtentionIterations = DEFAULT_KEY_OBTENTION_ITERATIONS;

    // Size in bytes of the random salt to be used for obtaining the
    // encryption key. This size will depend on the PBE algorithm being used,
    // so instead of being set by the user it will be provided by the
    //org.jasypt.encryption.pbe.algorithms.PBEAlgorithms registry.
    private int saltSizeBytes = 0;
    
    // Config object set (optionally).
    private PBEConfig config = null;

    /*
     * Set of booleans which indicate whether the config or default values
     * have to be overriden because of the setX methods having been
     * called.
     */
    private boolean algorithmSet = false;
    private boolean passwordSet = false;
    private boolean iterationsSet = false;
    
    
    /*
     * Flag which indicates whether the encryptor has been initialized or not.
     * 
     * Once initialized, no further modifications to its configuration will
     * be allowed.
     */
    private boolean initialized = false;

    
    // Encryption key generated.
    private SecretKey key = null;
    
    // Ciphers to be used for encryption and decryption.
    private Cipher encryptCipher = null;
    private Cipher decryptCipher = null;
    
    

    
    /**
     * Creates a new instance of <tt>StandardPBEByteEncryptor</tt>.
     */
    public StandardPBEByteEncryptor() {
        super();
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
     *   <li>Password</li>
     *   <li>Hashing iterations for obtaining the encryption key</li>
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
    public synchronized void setConfig(PBEConfig config) {
        Validate.notNull(config, "Config cannot be set null");
        if (isInitialized()) {
            throw new AlreadyInitializedException();
        }
        this.config = config;
    }

    
    /**
     * <p>
     * Sets the algorithm to be used for encryption, like 
     * <tt>PBEWithMD5AndDES</tt>.
     * </p>
     * 
     * <p>
     * This algorithm has to be supported by your Java Virtual Machine, and
     * it must be one of the algorithms registered at 
     * {@link org.jasypt.encryption.pbe.algorithms.PBEAlgorithms}.
     * </p>
     * 
     * @param algorithm the name of the algorithm to be used.
     * @see org.jasypt.encryption.pbe.algorithms.PBEAlgorithms
     */
    public synchronized void setAlgorithm(String algorithm) {
        Validate.notEmpty(algorithm, "Algorithm cannot be set empty");
        PBEAlgorithms.validateAlgorithm(algorithm);
        if (isInitialized()) {
            throw new AlreadyInitializedException();
        }
        this.algorithm = algorithm;
        this.algorithmSet = true;
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
    public synchronized void setPassword(String password) {
        Validate.notEmpty(password, "Password cannot be set empty");
        if (isInitialized()) {
            throw new AlreadyInitializedException();
        }
        this.password = password;
        this.passwordSet = true;
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
    public synchronized void setKeyObtentionIterations(
            int keyObtentionIterations) {
        Validate.isTrue(keyObtentionIterations > 0, 
                "Number of iterations for key obtention must be " +
                "greater than zero");
        if (isInitialized()) {
            throw new AlreadyInitializedException();
        }
        this.keyObtentionIterations = keyObtentionIterations;
        this.iterationsSet = true;
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
     *   change its configuration (algorithm, password or key obtention
     *   iterations) will
     *   result in an <tt>AlreadyInitializedException</tt> being thrown.
     * </p>
     * 
     * @return true if the encryptor has already been initialized, false if
     *         not.
     */
    public synchronized boolean isInitialized() {
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
     *   change its configuration (algorithm, password or key obtention
     *   iterations) will
     *   result in an <tt>AlreadyInitializedException</tt> being thrown.
     * </p>
     * 
     * @throws EncryptionInitializationException if initialization could not
     *         be correctly done (for example, no password has been set).
     */
    public synchronized void initialize() {
        
        // Double-check to avoid synchronization issues
        if (!this.initialized) {
            
            /*
             * If a PBEConfig object has been set, we need to 
             * consider the values it returns (if, for each value, the
             * corresponding "setX" method has not been called).
             */
            if (this.config != null) {
                
                String configAlgorithm = config.getAlgorithm();
                if (configAlgorithm != null) {
                    Validate.notEmpty(password, 
                            "Algorithm cannot be set empty");
                    PBEAlgorithms.validateAlgorithm(algorithm);
                }
                
                
                String configPassword = config.getPassword();
                if (configPassword != null) {
                    Validate.notEmpty(configPassword, 
                            "Password cannot be set empty");
                }
                
                Integer configKeyObtentionIterations = 
                    config.getKeyObtentionIterations();
                if (configKeyObtentionIterations != null) {
                    Validate.isTrue(configKeyObtentionIterations.intValue() > 0, 
                            "Number of iterations for key obtention must be " +
                            "greater than zero");
                }
                
                this.algorithm = 
                    ((this.algorithmSet) || (configAlgorithm == null))?
                            this.algorithm : configAlgorithm;
                this.password = 
                    ((this.passwordSet) || (configPassword == null))?
                            this.password : configPassword;
                this.keyObtentionIterations = 
                    ((this.iterationsSet) || 
                     (configKeyObtentionIterations == null))?
                            this.keyObtentionIterations : 
                            configKeyObtentionIterations.intValue();
                
            }

            // The specific parameter (salt size) for the chosen algorithm
            // is retrieved from the algorithm registry.
            PBEAlgorithms.Parameters parameters =
                PBEAlgorithms.getParameters(this.algorithm);
            this.saltSizeBytes = parameters.getSaltSizeBytes();

            
            try {
            
                // Password cannot be null.
                if (this.password == null) {
                    throw new EncryptionInitializationException(
                            "Password not set for Password Based Encryptor");
                }
                
                /*
                 * Encryption and decryption Ciphers are created the usual way.
                 */
                PBEKeySpec pbeKeySpec = 
                    new PBEKeySpec(this.password.toCharArray());
                SecretKeyFactory factory =
                    SecretKeyFactory.getInstance(this.algorithm);
                
                this.key = factory.generateSecret(pbeKeySpec);
                
                this.encryptCipher = Cipher.getInstance(this.algorithm);
                this.decryptCipher = Cipher.getInstance(this.algorithm);
                
            } catch (EncryptionInitializationException e) {
                throw e;
            } catch (Throwable t) {
                throw new EncryptionInitializationException(t);
            }
            this.initialized = true;
        }
        
    }


    /**
     * <p>
     * Encrypts a message using the specified configuration.
     * </p>
     * <p>
     * The mechanisms applied to perform the encryption operation are described
     * in <a href="http://www.rsasecurity.com/rsalabs/node.asp?id=2127" 
     * target="_blank">PKCS &#035;5: Password-Based Cryptography Standard</a>.
     * </p>
     * <p>
     * This encryptor uses a different random salt for each encryption
     * operation. The size of the salt depends on the algorithm
     * being used. This salt is used
     * for creating the encryption key, and it is also appended unencrypted 
     * at the beginning
     * of the results so that a decryption operation can be performed.
     * </p>
     * <p>
     * <b>Because of the use of a random salt, two encryption results for 
     * the same message will always be different
     * (except in the case of random salt coincidence)</b>. This enforces
     * security by difficulting brute force attacks on sets of data at a time
     * and forcing attackers to perform a brute force attack on each separate
     * piece of encrypted data.
     * </p>
     * 
     * @param message the byte array message to be encrypted
     * @return the result of encryption 
     * @throws EncryptionOperationNotPossibleException if the encryption 
     *         operation fails, ommitting any further information about the
     *         cause for security reasons.
     * @throws EncryptionInitializationException if initialization could not
     *         be correctly done (for example, no password has been set).
     */
    public byte[] encrypt(byte[] message) 
            throws EncryptionOperationNotPossibleException {
        
        if (message == null) {
            return null;
        }
        
        // Check initialization
        if (!isInitialized()) {
            initialize();
        }
        
        try {
            
            // Create random salt
            byte[] salt = SaltGeneration.generateSalt(this.saltSizeBytes);

            /*
             * Perform encryption using the Cipher
             */
            PBEParameterSpec parameterSpec = 
                new PBEParameterSpec(salt, this.keyObtentionIterations);

            byte[] encyptedMessage = null;
            synchronized (this.encryptCipher) {
                this.encryptCipher.init(
                        Cipher.ENCRYPT_MODE, this.key, parameterSpec);
                encyptedMessage = this.encryptCipher.doFinal(message);
            }

            // Append the unencrypted salt at the beginning of the result.
            return ArrayUtils.addAll(salt, encyptedMessage);
            
        } catch (InvalidKeyException e) {
            // The problem could be not having the unlimited strength policies
            // installed, so better give a usefull error message.
            handleInvalidKeyException();
            throw new EncryptionOperationNotPossibleException();
        } catch (Exception e) {
            // If encryption fails, it is more secure not to return any 
            // information about the cause in nested exceptions. Simply fail.
            throw new EncryptionOperationNotPossibleException();
        }
        
    }


    /**
     * <p>
     * Decrypts a message using the specified configuration.
     * </p>
     * <p>
     * The mechanisms applied to perform the decryption operation are described
     * in <a href="http://www.rsasecurity.com/rsalabs/node.asp?id=2127" 
     * target="_blank">PKCS &#035;5: Password-Based Cryptography Standard</a>.
     * </p>
     * <p>
     * This decryption operation expects to find an unencrypted salt at the 
     * beginning of the encrypted input, so that the decryption operation can be
     * correctly performed (this salt is supposed to be random and so, there
     * is no other way of knowing it).
     * </p>
     * 
     * @param message the byte array message to be decrypted
     * @return the result of decryption 
     * @throws EncryptionOperationNotPossibleException if the decryption 
     *         operation fails, ommitting any further information about the
     *         cause for security reasons.
     * @throws EncryptionInitializationException if initialization could not
     *         be correctly done (for example, no password has been set).
     */
    public byte[] decrypt(byte[] encryptedMessage) 
            throws EncryptionOperationNotPossibleException {
        
        if (encryptedMessage == null) {
            return null;
        }
        
        // Check initialization
        if (!isInitialized()) {
            initialize();
        }
    
        try {

            // Obtain unencrypted salt from the beginning of the message
            byte[] salt = 
                ArrayUtils.subarray(encryptedMessage, 0, this.saltSizeBytes);

            
            /*
             * Perform decryption using the Cipher
             */
            PBEParameterSpec parameterSpec = 
                new PBEParameterSpec(salt, this.keyObtentionIterations);

            byte[] decryptedMessage = null;
            
            byte[] encryptedMessageKernel = 
                ArrayUtils.subarray(encryptedMessage, this.saltSizeBytes, 
                        encryptedMessage.length);
                 
            synchronized (this.decryptCipher) {
                this.decryptCipher.init(
                        Cipher.DECRYPT_MODE, this.key, parameterSpec);
                decryptedMessage = 
                    this.decryptCipher.doFinal(encryptedMessageKernel);
            }

            // Return the results
            return decryptedMessage;
            
            
        } catch (InvalidKeyException e) {
            // The problem could be not having the unlimited strength policies
            // installed, so better give a usefull error message.
            handleInvalidKeyException();
            throw new EncryptionOperationNotPossibleException();
        } catch (Exception e) {
            // If decryption fails, it is more secure not to return any 
            // information about the cause in nested exceptions. Simply fail.
            throw new EncryptionOperationNotPossibleException();
        }
        
    }    


    /*
     * Method used to provide an useful error message in the case that the
     * user tried to use a strong PBE algorithm like TripleDES and he/she
     * has not installed the Unlimited Strength Policy files (the default
     * message for this is simply "invalid key size", which does not provide
     * enough clues for the user to know what is really going on).
     */
    private void handleInvalidKeyException() {
        
        String vmVendor = System.getProperty("java.vm.vendor");
        if ((this.algorithm.equals(
                PBEAlgorithms.PBE_WITH_MD5_AND_TRIPLE_DES)) &&
            (vmVendor != null) && 
            (vmVendor.toUpperCase().contains("SUN"))) {
            
            throw new EncryptionOperationNotPossibleException(
                    "Encryption raised an exception. A possible cause is " +
                    "you are using strong encryption algorithms and " +
                    "you have not installed the Java Cryptography " + 
                    "Extension (JCE) Unlimited Strength Jurisdiction " +
                    "Policy Files in this Java Virtual Machine");
            
        }
        
    }
    
}

