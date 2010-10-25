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
package org.jasypt.encryption.pbe.config;

import java.security.Provider;

import org.jasypt.exceptions.EncryptionInitializationException;
import org.jasypt.salt.SaltGenerator;


/**
 * <p>
 * Bean implementation for {@link PBEConfig}. This class allows 
 * the values for the configuration parameters to be set
 * via "standard" <tt>setX</tt> methods.
 * </p>
 * <p>
 * For any of the configuration parameters, if its <tt>setX</tt>
 * method is not called, a <tt>null</tt> value will be returned by the
 * corresponding <tt>getX</tt> method. 
 * </p>
 * <p>
 * <b>Note that there is not an exact correspondence between <tt>setX()</tt>
 * and <tt>getX()</tt> methods</b>, as sometimes two methods like
 * <tt>setProvider()</tt> and <tt>setProviderClassName()</tt> will affect the
 * same configuration parameter (<tt>getProvider()</tt>). This means that
 * several combinations of <tt>setX()</tt> methods <b>collide</b>, and 
 * should not be called together (a call to <tt>setProviderClassName()</tt> 
 * will override any previous call to <tt>setProvider()</tt>).
 * </p>
 * 
 * @since 1.0
 * 
 * @author Daniel Fern&aacute;ndez
 * 
 */
public class SimplePBEConfig implements PBEConfig {
    
    private String algorithm = null;
    private String password = null;
    private Integer keyObtentionIterations = null;
    private SaltGenerator saltGenerator = null;
    private String providerName = null;
    private Provider provider = null;
    private Integer poolSize = null;


    /**
     * <p>
     * Creates a new <tt>SimplePBEConfig</tt> instance.
     * </p>
     */
    public SimplePBEConfig() {
        super();
    }

    
    /**
     * <p>
     * Sets a value for the encryption algorithm
     * </p>
     * <p>
     * This algorithm has to be supported by your JCE provider and, if this provider
     * supports it, you can also specify <i>mode</i> and <i>padding</i> for 
     * it, like <tt>ALGORITHM/MODE/PADDING</tt>.
     * </p>
     * <p>
     * Determines the result of: {@link #getAlgorithm()}
     * </p>
     * 
     * @param algorithm the name of the algorithm to be used
     */
    public void setAlgorithm(final String algorithm) {
        this.algorithm = algorithm;
    }


    /**
     * Sets the password to be used for encryption.
     * <p>
     * Determines the result of: {@link #getPassword()}
     * </p>
     * 
     * @param password the password to be used.
     */
    public void setPassword(final String password) {
        this.password = password;
    }

    
    /**
     * Sets the number of hashing iterations applied to obtain the
     * encryption key.
     * <p>
     * Determines the result of: {@link #getKeyObtentionIterations()}
     * </p>
     * 
     * @param keyObtentionIterations the number of iterations.
     */
    public void setKeyObtentionIterations(final Integer keyObtentionIterations) {
        this.keyObtentionIterations = keyObtentionIterations;
    }

    
    /**
     * Sets the number of hashing iterations applied to obtain the
     * encryption key.
     * <p>
     * Determines the result of: {@link #getKeyObtentionIterations()}
     * </p>
     * 
     * @since 1.4
     * 
     * @param keyObtentionIterations the number of iterations.
     */
    public void setKeyObtentionIterations(final String keyObtentionIterations) {
        if (keyObtentionIterations != null) {
            try {
                this.keyObtentionIterations = new Integer(keyObtentionIterations);
            } catch (NumberFormatException e) {
                throw new EncryptionInitializationException(e);
            }
        } else {
            this.keyObtentionIterations = null;
        }
    }

    
    /**
     * <p>
     * Sets the salt generator.
     * </p>
     * <p>
     * If not set, null will returned.
     * </p>
     * <p>
     * Determines the result of: {@link #getSaltGenerator()}
     * </p>
     * 
     * @param saltGenerator the salt generator.
     */
    public void setSaltGenerator(final SaltGenerator saltGenerator) {
        this.saltGenerator = saltGenerator;
    }

    
    /**
     * <p>
     * Sets the salt generator.
     * </p>
     * <p>
     * If not set, null will returned.
     * </p>
     * <p>
     * Determines the result of: {@link #getSaltGenerator()}
     * </p>
     *
     * @since 1.4
     * 
     * @param saltGeneratorClassName the name of the salt generator class.
     */
    public void setSaltGeneratorClassName(final String saltGeneratorClassName) {
        if (saltGeneratorClassName != null) {
            try {
                final Class saltGeneratorClass = 
                    Thread.currentThread().getContextClassLoader().loadClass(saltGeneratorClassName);
                this.saltGenerator = 
                    (SaltGenerator) saltGeneratorClass.newInstance();
            } catch (Exception e) {
                throw new EncryptionInitializationException(e);
            }
        } else {
            this.saltGenerator = null;
        }
    }

    
    /**
     * <p>
     * Sets the name of the security provider to be asked for the encryption
     * algorithm. This provider should be already registered.
     * </p>
     * <p>
     * If both the <tt>providerName</tt> and <tt>provider</tt> properties
     * are set, only <tt>provider</tt> will be used, and <tt>providerName</tt>
     * will have no meaning for the encryptor object.
     * </p>
     * <p>
     * If not set, null will be returned.
     * </p>
     * <p>
     * Determines the result of: {@link #getProviderName()}
     * </p>
     * 
     * @since 1.3
     * 
     * @param providerName the name of the security provider.
     */
    public void setProviderName(final String providerName) {
        this.providerName = providerName;
    }

    
    /**
     * <p>
     * Sets the security provider to be used for obtaining the encryption 
     * algorithm. This method is an alternative to 
     * both {@link #setProviderName(String)} and 
     * {@link #setProviderClassName(String)} and they should not be used 
     * altogether.
     * The provider specified with {@link #setProvider(Provider)} does not
     * have to be registered beforehand, and its use will not result in its
     * being registered.
     * </p>
     * <p>
     * If both the <tt>providerName</tt> and <tt>provider</tt> properties
     * are set, only <tt>provider</tt> will be used, and <tt>providerName</tt>
     * will have no meaning for the encryptor object.
     * </p>
     * <p>
     * If not set, null will be returned.
     * </p>
     * <p>
     * Determines the result of: {@link #getProvider()}
     * </p>
     * 
     * @since 1.3
     * 
     * @param provider the security provider object.
     */
    public void setProvider(final Provider provider) {
        this.provider = provider;
    }

    
    /**
     * <p>
     * Sets the security provider to be used for obtaining the encryption 
     * algorithm. This method is an alternative to 
     * both {@link #setProviderName(String)} and {@link #setProvider(Provider)} 
     * and they should not be used altogether.
     * The provider specified with {@link #setProviderClassName(String)} does not
     * have to be registered beforehand, and its use will not result in its
     * being registered.
     * </p>
     * <p>
     * If both the <tt>providerName</tt> and <tt>provider</tt> properties
     * are set, only <tt>provider</tt> will be used, and <tt>providerName</tt>
     * will have no meaning for the encryptor object.
     * </p>
     * <p>
     * If not set, null will be returned.
     * </p>
     * <p>
     * Determines the result of: {@link #getProvider()}
     * </p>
     * 
     * @since 1.4
     * 
     * @param providerClassName the name of the security provider class.
     */
    public void setProviderClassName(final String providerClassName) {
        if (providerClassName != null) {
            try {
                final Class providerClass = 
                    Thread.currentThread().getContextClassLoader().loadClass(providerClassName);
                this.provider = (Provider) providerClass.newInstance();
            } catch (Exception e) {
                throw new EncryptionInitializationException(e);
            }
        } else {
            this.provider = null;
        }
    }

    
    
    
    
    /**
     * <p>
     * Sets the size of the pool of encryptors to be created.
     * </p>
     * <p>
     * <b>This parameter will be ignored if used with a non-pooled encryptor</b>.
     * </p>
     * <p>
     * If not set, null will be returned.
     * </p>
     * <p>
     * Determines the result of: {@link #getPoolSize()}
     * </p>
     *
     * @since 1.7
     * 
     * @param poolSize the size of the pool to be used if this configuration is used with a
     *         pooled encryptor
     */
    public void setPoolSize(final Integer poolSize) {
        this.poolSize = poolSize;
    }
    

    /**
     * <p>
     * Sets the size of the pool of encryptors to be created.
     * </p>
     * <p>
     * <b>This parameter will be ignored if used with a non-pooled encryptor</b>.
     * </p>
     * <p>
     * If not set, null will be returned.
     * </p>
     * <p>
     * Determines the result of: {@link #getPoolSize()}
     * </p>
     *
     * @since 1.7
     * 
     * @param poolSize the size of the pool to be used if this configuration is used with a
     *         pooled encryptor
     */
    public void setPoolSize(final String poolSize) {
        if (poolSize != null) {
            try {
                this.poolSize = new Integer(poolSize);
            } catch (NumberFormatException e) {
                throw new EncryptionInitializationException(e);
            }
        } else {
            this.poolSize = null;
        }
    }

    
    
    
    
    public String getAlgorithm() {
        return this.algorithm;
    }

    
    public String getPassword() {
        return this.password;
    }

    
    public Integer getKeyObtentionIterations() {
        return this.keyObtentionIterations;
    }
    
    
    public SaltGenerator getSaltGenerator() {
        return this.saltGenerator;
    }
    
    public String getProviderName() {
        return this.providerName;
    }
    
    public Provider getProvider() {
        return this.provider;
    }

    public Integer getPoolSize() {
        return this.poolSize;
    }

    
}
