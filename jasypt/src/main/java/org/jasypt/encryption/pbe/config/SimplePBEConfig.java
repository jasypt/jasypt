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

import java.security.Provider;

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
 * 
 * @since 1.0
 * 
 * @author Daniel Fern&aacute;ndez Garrido
 * 
 */
public class SimplePBEConfig implements PBEConfig {
    
    private String algorithm = null;
    private String password = null;
    private Integer keyObtentionIterations = null;
    private SaltGenerator saltGenerator = null;
    private String providerName = null;
    private Provider provider = null;


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
     * 
     * @param algorithm the name of the algorithm to be used
     */
    public void setAlgorithm(String algorithm) {
        this.algorithm = algorithm;
    }


    /**
     * Sets the password to be used for encryption.
     * 
     * @param password the password to be used.
     */
    public void setPassword(String password) {
        this.password = password;
    }

    
    /**
     * Sets the number of hashing iterations applied to obtain the
     * encryption key.
     * 
     * @param keyObtentionIterations the number of iterations.
     */
    public void setKeyObtentionIterations(Integer keyObtentionIterations) {
        this.keyObtentionIterations = keyObtentionIterations;
    }
    
    /**
     * <p>
     * Sets the salt generator.
     * </p>
     * <p>
     * If not set, null will returned.
     * </p>
     * 
     * @param saltGenerator the salt generator.
     */
    public void setSaltGenerator(SaltGenerator saltGenerator) {
        this.saltGenerator = saltGenerator;
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
     * 
     * @since 1.3
     * 
     * @param providerName the name of the security provider.
     */
    public void setProviderName(String providerName) {
        this.providerName = providerName;
    }
    
    /**
     * <p>
     * Sets the security provider to be used for obtaining the encryption 
     * algorithm. This method is an alternative to 
     * {@link #setProviderName(String)} and they should not be used altogether.
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
     * 
     * @since 1.3
     * 
     * @param provider the security provider object.
     */
    public void setProvider(Provider provider) {
        this.provider = provider;
    }

    
    public String getAlgorithm() {
        return algorithm;
    }

    
    public String getPassword() {
        return password;
    }

    
    public Integer getKeyObtentionIterations() {
        return keyObtentionIterations;
    }
    
    
    public SaltGenerator getSaltGenerator() {
        return saltGenerator;
    }
    
    public String getProviderName() {
        return providerName;
    }
    
    public Provider getProvider() {
        return provider;
    }

    
}
