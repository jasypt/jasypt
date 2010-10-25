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

import org.jasypt.salt.SaltGenerator;

/**
 * <p>
 * Implementation for {@link PBEConfig} which can retrieve configuration
 * values from environment variables or system properties.
 * </p>
 * <p>
 * The name of the environment variable or system property (JVM property) to
 * query for each parameter can be set with its corresponding 
 * <tt>setXEnvName</tt> or <tt>setXSysProperty</tt> method.
 * </p>
 * <p>
 * As this class extends {@link SimplePBEConfig}, parameter values
 * can be also set with the usual <tt>setX</tt> methods.
 * </p>
 * <p>
 * For any of the configuration parameters, if its value is not configured
 * in any way, a <tt>null</tt> value will be returned by the
 * corresponding <tt>getX</tt> method. 
 * </p>
 * 
 * @since 1.1
 * 
 * @author Daniel Fern&aacute;ndez
 * 
 */
public class EnvironmentPBEConfig extends SimplePBEConfig {
    
    private String algorithmEnvName = null;
    private String keyObtentionIterationsEnvName = null;
    private String passwordEnvName = null;
    private String saltGeneratorClassNameEnvName = null;
    private String providerNameEnvName = null;
    private String providerClassNameEnvName = null;
    private String poolSizeEnvName = null;

    private String algorithmSysPropertyName = null;
    private String keyObtentionIterationsSysPropertyName = null;
    private String passwordSysPropertyName = null;
    private String saltGeneratorClassNameSysPropertyName = null;
    private String providerNameSysPropertyName = null;
    private String providerClassNameSysPropertyName = null;
    private String poolSizeSysPropertyName = null;
    

    /**
     * <p>
     * Creates a new <tt>EnvironmentPBEConfig</tt> instance.
     * </p>
     */
    public EnvironmentPBEConfig() {
        super();
    }



    /**
     * Retrieve the name of the environment variable which value has been
     * loaded as the algorithm.
     *   
     * @return the name of the variable
     */
    public String getAlgorithmEnvName() {
        return this.algorithmEnvName;
    }


    /**
     * Set the config object to use the specified environment variable to
     * load the value for the algorithm.
     * 
     * @param algorithmEnvName the name of the environment variable
     */
    public void setAlgorithmEnvName(final String algorithmEnvName) {
        this.algorithmEnvName = algorithmEnvName;
        if (algorithmEnvName == null) {
            super.setAlgorithm(null);
        } else {
            this.algorithmSysPropertyName = null;
            super.setAlgorithm(System.getenv(algorithmEnvName));
        }
    }


    /**
     * Retrieve the name of the JVM system property which value has been
     * loaded as the algorithm.
     *   
     * @return the name of the property
     */
    public String getAlgorithmSysPropertyName() {
        return this.algorithmSysPropertyName;
    }


    /**
     * Set the config object to use the specified JVM system property to
     * load the value for the algorithm.
     * 
     * @param algorithmSysPropertyName the name of the property
     */
    public void setAlgorithmSysPropertyName(final String algorithmSysPropertyName) {
        this.algorithmSysPropertyName = algorithmSysPropertyName;
        if (algorithmSysPropertyName == null) {
            super.setAlgorithm(null);
        } else {
            this.algorithmEnvName = null;
            super.setAlgorithm(System.getProperty(algorithmSysPropertyName));
        }
    }


    /**
     * Retrieve the name of the environment variable which value has been
     * loaded as the key obtention iteration count.
     *   
     * @return the name of the variable
     */
    public String getKeyObtentionIterationsEnvName() {
        return this.keyObtentionIterationsEnvName;
    }


    /**
     * Set the config object to use the specified environment variable to
     * load the value for the key obtention iteration count.
     * 
     * @param keyObtentionIterationsEnvName the name of the environment variable
     */
    public void setKeyObtentionIterationsEnvName(final String keyObtentionIterationsEnvName) {
        this.keyObtentionIterationsEnvName = keyObtentionIterationsEnvName;
        if (keyObtentionIterationsEnvName == null) {
            super.setKeyObtentionIterations((Integer)null);
        } else {
            this.keyObtentionIterationsSysPropertyName = null;
            super.setKeyObtentionIterations(
                    System.getenv(keyObtentionIterationsEnvName));
        }
    }


    /**
     * Retrieve the name of the JVM system property which value has been
     * loaded as the key obtention iteration count.
     *   
     * @return the name of the property
     */
    public String getKeyObtentionIterationsSysPropertyName() {
        return this.keyObtentionIterationsSysPropertyName;
    }


    /**
     * Set the config object to use the specified JVM system property to
     * load the value for the key obtention iteration count.
     * 
     * @param keyObtentionIterationsSysPropertyName the name of the property
     */
    public void setKeyObtentionIterationsSysPropertyName(final String keyObtentionIterationsSysPropertyName) {
        this.keyObtentionIterationsSysPropertyName = keyObtentionIterationsSysPropertyName;
        if (keyObtentionIterationsSysPropertyName == null) {
            super.setKeyObtentionIterations((Integer)null);
        } else {
            this.keyObtentionIterationsEnvName = null;
            super.setKeyObtentionIterations(
                    System.getProperty(keyObtentionIterationsSysPropertyName));
        }
    }


    /**
     * Retrieve the name of the environment variable which value has been
     * loaded as the password.
     *   
     * @return the name of the variable
     */
    public String getPasswordEnvName() {
        return this.passwordEnvName;
    }


    /**
     * Set the config object to use the specified environment variable to
     * load the value for the password.
     * 
     * @param passwordEnvName the name of the environment variable
     */
    public void setPasswordEnvName(final String passwordEnvName) {
        this.passwordEnvName = passwordEnvName;
        if (passwordEnvName == null) {
            super.setPassword(null);
        } else {
            this.passwordSysPropertyName = null;
            super.setPassword(System.getenv(passwordEnvName));
        }
    }


    /**
     * Retrieve the name of the JVM system property which value has been
     * loaded as the password.
     *   
     * @return the name of the property
     */
    public String getPasswordSysPropertyName() {
        return this.passwordSysPropertyName;
    }


    /**
     * Set the config object to use the specified JVM system property to
     * load the value for the password.
     * 
     * @param passwordSysPropertyName the name of the property
     */
    public void setPasswordSysPropertyName(final String passwordSysPropertyName) {
        this.passwordSysPropertyName = passwordSysPropertyName;
        if (passwordSysPropertyName == null) {
            super.setPassword(null);
        } else {
            this.passwordEnvName = null;
            super.setPassword(System.getProperty(passwordSysPropertyName));
        }
    }


    /**
     * Retrieve the name of the environment variable which value has been
     * loaded as the salt generator class name.
     * 
     * @since 1.3
     *   
     * @return the name of the variable
     */
    public String getSaltGeneratorClassNameEnvName() {
        return this.saltGeneratorClassNameEnvName;
    }

   
    /**
     * <p>
     * Set the config object to use the specified environment variable to
     * load the value for the salt generator class name.
     * </p>
     * <p>
     * The salt generator class name which is set here must have a no-argument
     * constructor, so that it can be instantiated and passed to the encryptor.
     * </p>
     * 
     * @since 1.3
     * 
     * @param saltGeneratorClassNameEnvName the name of the environment variable
     */
    public void setSaltGeneratorClassNameEnvName(final String saltGeneratorClassNameEnvName) {
        this.saltGeneratorClassNameEnvName = saltGeneratorClassNameEnvName;
        if (saltGeneratorClassNameEnvName == null) {
            super.setSaltGenerator(null);
        } else {
            this.saltGeneratorClassNameSysPropertyName = null;
            final String saltGeneratorClassName = System.getenv(saltGeneratorClassNameEnvName);
            super.setSaltGeneratorClassName(saltGeneratorClassName);
        }
    }


    /**
     * Retrieve the name of the JVM system property which value has been
     * loaded as the salt generator class name.
     * 
     * @since 1.3
     *   
     * @return the name of the property
     */
    public String getSaltGeneratorClassNameSysPropertyName() {
        return this.saltGeneratorClassNameSysPropertyName;
    }


    /**
     * <p>
     * Set the config object to use the specified JVM system property to
     * load the value for the salt generator class name.
     * </p>
     * <p>
     * The salt generator class name which is set here must have a no-argument
     * constructor, so that it can be instantiated and passed to the encryptor.
     * </p>
     * 
     * @since 1.3
     * 
     * @param saltGeneratorClassNameSysPropertyName the name of the property
     */
    public void setSaltGeneratorClassNameSysPropertyName(final String saltGeneratorClassNameSysPropertyName) {
        this.saltGeneratorClassNameSysPropertyName = saltGeneratorClassNameSysPropertyName;
        if (saltGeneratorClassNameSysPropertyName == null) {
            super.setSaltGenerator(null);
        } else {
            this.saltGeneratorClassNameEnvName = null;
            final String saltGeneratorClassName = System.getProperty(saltGeneratorClassNameSysPropertyName);
            super.setSaltGeneratorClassName(saltGeneratorClassName);
        }
    }


    /**
     * Retrieve the name of the environment variable which value has been
     * loaded as the provider name.
     * 
     * @since 1.3
     *   
     * @return the name of the variable
     */
    public String getProviderNameEnvName() {
        return this.providerNameEnvName;
    }


    /**
     * <p>
     * Set the config object to use the specified environment variable to
     * load the value for the provider name.
     * </p>
     * 
     * @since 1.3
     * 
     * @param providerNameEnvName the name of the environment variable
     */
    public void setProviderNameEnvName(final String providerNameEnvName) {
        this.providerNameEnvName = providerNameEnvName;
        if (providerNameEnvName == null) {
            super.setProviderName(null);
        } else {
            this.providerNameSysPropertyName = null;
            super.setProviderName(System.getenv(providerNameEnvName));
        }
    }


    /**
     * Retrieve the name of the JVM system property which value has been
     * loaded as the provider name.
     * 
     * @since 1.3
     *   
     * @return the name of the property
     */
    public String getProviderNameSysPropertyName() {
        return this.providerNameSysPropertyName;
    }


    /**
     * Set the config object to use the specified JVM system property to
     * load the value for the provider name.
     * 
     * @since 1.3
     * 
     * @param providerNameSysPropertyName the name of the property
     */
    public void setProviderNameSysPropertyName(final String providerNameSysPropertyName) {
        this.providerNameSysPropertyName = providerNameSysPropertyName;
        if (providerNameSysPropertyName == null) {
            super.setProviderName(null);
        } else {
            this.providerNameEnvName = null;
            super.setProviderName(
                    System.getProperty(providerNameSysPropertyName));
        }
    }


    /**
     * Retrieve the name of the environment variable which value has been
     * loaded as the provider class name.
     * 
     * @since 1.3
     *   
     * @return the name of the variable
     */
    public String getProviderClassNameEnvName() {
        return this.providerClassNameEnvName;
    }


    /**
     * <p>
     * Set the config object to use the specified environment variable to
     * load the value for the provider class name.
     * </p>
     * <p>
     * The provider class name which is set here must have a no-argument
     * constructor, so that it can be instantiated and passed to the encryptor.
     * </p>
     * 
     * @since 1.3
     * 
     * @param providerClassNameEnvName the name of the environment variable
     */
    public void setProviderClassNameEnvName(final String providerClassNameEnvName) {
        this.providerClassNameEnvName = providerClassNameEnvName;
        if (providerClassNameEnvName == null) {
            super.setProvider(null);
        } else {
            this.providerClassNameSysPropertyName = null;
            final String providerClassName = System.getenv(providerClassNameEnvName);
            super.setProviderClassName(providerClassName);
        }
    }


    /**
     * Retrieve the name of the JVM system property which value has been
     * loaded as the provider class name.
     * 
     * @since 1.3
     *   
     * @return the name of the property
     */
    public String getProviderClassNameSysPropertyName() {
        return this.providerClassNameSysPropertyName;
    }


    /**
     * <p>
     * Set the config object to use the specified JVM system property to
     * load the value for the provider class name.
     * </p>
     * <p>
     * The provider class name which is set here must have a no-argument
     * constructor, so that it can be instantiated and passed to the encryptor.
     * </p>
     * 
     * @since 1.3
     * 
     * @param providerClassNameSysPropertyName the name of the property
     */
    public void setProviderClassNameSysPropertyName(final String providerClassNameSysPropertyName) {
        this.providerClassNameSysPropertyName = providerClassNameSysPropertyName;
        if (providerClassNameSysPropertyName == null) {
            super.setProvider(null);
        } else {
            this.providerClassNameEnvName = null;
            final String providerClassName = System.getProperty(providerClassNameSysPropertyName);
            super.setProviderClassName(providerClassName);
        }
    }
    
    

    
    
    

    
    


    /**
     * Retrieve the name of the environment variable which value has been
     * loaded as the value for the poolSize
     * property.
     * 
     * @since 1.7
     *   
     * @return the name of the variable
     */
    public String getPoolSizeEnvName() {
        return this.poolSizeEnvName;
    }



    /**
     * <p>
     * Set the config object to use the specified environment variable to
     * load the value for the poolSize
     * property.
     * </p>
     * 
     * @since 1.7
     * 
     * @param poolSizeEnvName the name of the environment variable
     */
    public void setPoolSizeEnvName(final String poolSizeEnvName) {
        this.poolSizeEnvName = poolSizeEnvName;
        if (poolSizeEnvName == null) {
            super.setPoolSize((String)null);
        } else {
            this.poolSizeSysPropertyName = null;
            super.setPoolSize(System.getenv(poolSizeEnvName));
        }
    }



    /**
     * Retrieve the name of the JVM system property which value has been
     * loaded as the value for the poolSize
     * property.
     * 
     * @since 1.7
     *   
     * @return the name of the property
     */
    public String getPoolSizeSysPropertyName() {
        return this.poolSizeSysPropertyName;
    }



    /**
     * <p>
     * Set the config object to use the specified JVM system property to
     * load the value for the useLenientSaltSizeCheck
     * property.
     * </p>
     * 
     * @since 1.7
     * 
     * @param poolSizeSysPropertyName the name of the property
     */
    public void setPoolSizeSysPropertyName(final String poolSizeSysPropertyName) {
        this.poolSizeSysPropertyName = poolSizeSysPropertyName;
        if (poolSizeSysPropertyName == null) {
            super.setPoolSize((String)null);
        } else {
            this.poolSizeEnvName = null;
            super.setPoolSize(System.getProperty(poolSizeSysPropertyName));
        }
    }
    
    
    
    
    
    
    
    

    
    public void setAlgorithm(final String algorithm) {
        this.algorithmEnvName = null;
        this.algorithmSysPropertyName = null;
        super.setAlgorithm(algorithm);
    }



    public void setKeyObtentionIterations(final Integer keyObtentionIterations) {
        this.keyObtentionIterationsEnvName = null;
        this.keyObtentionIterationsSysPropertyName = null;
        super.setKeyObtentionIterations(keyObtentionIterations);
    }


    public void setKeyObtentionIterations(final String keyObtentionIterations) {
        this.keyObtentionIterationsEnvName = null;
        this.keyObtentionIterationsSysPropertyName = null;
        super.setKeyObtentionIterations(keyObtentionIterations);
    }


    public void setPassword(final String password) {
        this.passwordEnvName = null;
        this.passwordSysPropertyName = null;
        super.setPassword(password);
    }

    
    public void setSaltGenerator(final SaltGenerator saltGenerator) {
        this.saltGeneratorClassNameEnvName = null;
        this.saltGeneratorClassNameSysPropertyName = null;
        super.setSaltGenerator(saltGenerator);
    }


    public void setSaltGeneratorClassName(final String saltGeneratorClassName) {
        this.saltGeneratorClassNameEnvName = null;
        this.saltGeneratorClassNameSysPropertyName = null;
        super.setSaltGeneratorClassName(saltGeneratorClassName);
    }


    public void setProviderName(final String providerName) {
        this.providerNameEnvName = null;
        this.providerNameSysPropertyName = null;
        super.setProviderName(providerName);
    }

    
    
    public void setProvider(final Provider provider) {
        this.providerClassNameEnvName = null;
        this.providerClassNameSysPropertyName = null;
        super.setProvider(provider);
    }


    public void setProviderClassName(final String providerClassName) {
        this.providerClassNameEnvName = null;
        this.providerClassNameSysPropertyName = null;
        super.setProviderClassName(providerClassName);
    }


    public void setPoolSize(final Integer poolSize) {
        this.poolSizeEnvName = null;
        this.poolSizeSysPropertyName = null;
        super.setPoolSize(poolSize);
    }


    public void setPoolSize(final String poolSize) {
        this.poolSizeEnvName = null;
        this.poolSizeSysPropertyName = null;
        super.setPoolSize(poolSize);
    }

    
}
