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

import org.jasypt.exceptions.EncryptionInitializationException;
import org.jasypt.salt.SaltGenerator;

/**
 * <p>
 * Bean implementation for {@link DigesterConfig}. This class allows 
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
 * @author Daniel Fern&aacute;ndez Garrido
 * 
 */
public class SimpleDigesterConfig implements DigesterConfig {
    
    private String algorithm = null;
    private Integer iterations = null;
    private Integer saltSizeBytes = null;
    private SaltGenerator saltGenerator = null;
    private String providerName = null;
    private Provider provider = null;
    

    /**
     * <p>
     * Creates a new <tt>SimpleDigesterConfig</tt> instance.
     * </p>
     */
    public SimpleDigesterConfig() {
        super();
    }
    
    /**
     * <p>
     * Sets the name of the algorithm.
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
     * <p>
     * Determines the result of: {@link #getAlgorithm()}
     * </p>
     * 
     * @param algorithm the name of the algorithm.
     */
    public void setAlgorithm(String algorithm) {
        this.algorithm = algorithm;
    }

    
    /**
     * <p>
     * Sets the number of hashing iterations.
     * </p>
     * <p>
     * If not set, null will be returned.
     * </p>
     * <p>
     * Determines the result of: {@link #getIterations()}
     * </p>
     * 
     * @param iterations the number of iterations.
     */
    public void setIterations(Integer iterations) {
        this.iterations = iterations;
    }

    
    /**
     * <p>
     * Sets the number of hashing iterations.
     * </p>
     * <p>
     * If not set, null will be returned.
     * </p>
     * <p>
     * Determines the result of: {@link #getIterations()}
     * </p>
     * 
     * @since 1.4
     * 
     * @param iterations the number of iterations.
     */
    public void setIterations(String iterations) {
        if (iterations != null) {
            try {
                this.iterations = new Integer(iterations);
            } catch (NumberFormatException e) {
                throw new EncryptionInitializationException(e);
            }
        } else {
            this.iterations = null;
        }
    }

    
    /**
     * <p>
     * Size in bytes of the salt to be used.
     * </p>
     * <p>
     * If not set, null will be returned.
     * </p>
     * <p>
     * Determines the result of: {@link #getSaltSizeBytes()}
     * </p>
     * 
     * @param saltSizeBytes the size of the salt, in bytes.
     */
    public void setSaltSizeBytes(Integer saltSizeBytes) {
        this.saltSizeBytes = saltSizeBytes;
    }

    
    /**
     * <p>
     * Size in bytes of the salt to be used.
     * </p>
     * <p>
     * If not set, null will be returned.
     * </p>
     * <p>
     * Determines the result of: {@link #getSaltSizeBytes()}
     * </p>
     *
     * @since 1.4
     * 
     * @param saltSizeBytes the size of the salt, in bytes.
     */
    public void setSaltSizeBytes(String saltSizeBytes) {
        if (saltSizeBytes != null) {
            try {
                this.saltSizeBytes = new Integer(saltSizeBytes);
            } catch (NumberFormatException e) {
                throw new EncryptionInitializationException(e);
            }
        } else {
            this.saltSizeBytes = null;
        }
    }

    
    /**
     * <p>
     * Sets the salt generator.
     * </p>
     * <p>
     * If not set, null will be returned.
     * </p>
     * <p>
     * Determines the result of: {@link #getSaltGenerator()}
     * </p>
     * 
     * @since 1.2
     * 
     * @param saltGenerator the salt generator.
     */
    public void setSaltGenerator(SaltGenerator saltGenerator) {
        this.saltGenerator = saltGenerator;
    }

    
    /**
     * <p>
     * Sets the class name of the salt generator.
     * </p>
     * <p>
     * If not set, null will be returned.
     * </p>
     * <p>
     * Determines the result of: {@link #getSaltGenerator()}
     * </p>
     * 
     * @since 1.4
     * 
     * @param saltGeneratorClassName the name of the salt generator class.
     */
    public void setSaltGeneratorClassName(String saltGeneratorClassName) {
        if (saltGeneratorClassName != null) {
            try {
                Class saltGeneratorClass = 
                    Class.forName(saltGeneratorClassName);
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
     * Sets the name of the security provider to be asked for the digest
     * algorithm. This provider should be already registered.
     * </p>
     * <p>
     * If both the <tt>providerName</tt> and <tt>provider</tt> properties
     * are set, only <tt>provider</tt> will be used, and <tt>providerName</tt>
     * will have no meaning for the digester object.
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
    public void setProviderName(String providerName) {
        this.providerName = providerName;
    }
    
    
    /**
     * <p>
     * Sets the security provider to be used for obtaining the digest 
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
     * will have no meaning for the digester object.
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
    public void setProvider(Provider provider) {
        this.provider = provider;
    }
    
    
    /**
     * <p>
     * Sets the class name for the security provider to be used for 
     * obtaining the digest algorithm. This method is an alternative to 
     * both {@link #setProviderName(String)} {@link #setProvider(Provider)} 
     * and they should not be used altogether.
     * The provider specified with {@link #setProviderClassName(String)} does not
     * have to be registered beforehand, and its use will not result in its
     * being registered.
     * </p>
     * <p>
     * If both the <tt>providerName</tt> and <tt>provider</tt> properties
     * are set, only <tt>provider</tt> will be used, and <tt>providerName</tt>
     * will have no meaning for the digester object.
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
    public void setProviderClassName(String providerClassName) {
        if (providerClassName != null) {
            try {
                Class providerClass = Class.forName(providerClassName);
                this.provider = (Provider) providerClass.newInstance();
            } catch (Exception e) {
                throw new EncryptionInitializationException(e);
            }
        } else {
            this.provider = null;
        }
    }

    
    public String getAlgorithm() {
        return this.algorithm;
    }

    
    public Integer getIterations() {
        return this.iterations;
    }

    
    public Integer getSaltSizeBytes() {
        return this.saltSizeBytes;
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

    
}
