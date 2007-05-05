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

import org.jasypt.exceptions.EncryptionInitializationException;
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
 * @author Daniel Fern&aacute;ndez Garrido
 * 
 */
public class EnvironmentPBEConfig extends SimplePBEConfig {
    
    private String algorithmEnvName = null;
    private String keyObtentionIterationsEnvName = null;
    private String passwordEnvName = null;
    private String saltGeneratorClassNameEnvName = null;
    private String providerNameEnvName = null;
    private String providerClassNameEnvName = null;

    private String algorithmSysPropertyName = null;
    private String keyObtentionIterationsSysPropertyName = null;
    private String passwordSysPropertyName = null;
    private String saltGeneratorClassNameSysPropertyName = null;
    private String providerNameSysPropertyName = null;
    private String providerClassNameSysPropertyName = null;
    

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
        return algorithmEnvName;
    }


    /**
     * Set the config object to use the specified environment variable to
     * load the value for the algorithm.
     * 
     * @param algorithmEnvName the name of the environment variable
     */
    public void setAlgorithmEnvName(String algorithmEnvName) {
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
        return algorithmSysPropertyName;
    }


    /**
     * Set the config object to use the specified JVM system property to
     * load the value for the algorithm.
     * 
     * @param algorithmSysPropertyName the name of the property
     */
    public void setAlgorithmSysPropertyName(String algorithmSysPropertyName) {
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
        return keyObtentionIterationsEnvName;
    }


    /**
     * Set the config object to use the specified environment variable to
     * load the value for the key obtention iteration count.
     * 
     * @param keyObtentionIterationsEnvName the name of the environment variable
     */
    public void setKeyObtentionIterationsEnvName(String keyObtentionIterationsEnvName) {
        this.keyObtentionIterationsEnvName = keyObtentionIterationsEnvName;
        if (keyObtentionIterationsEnvName == null) {
            super.setKeyObtentionIterations(null);
        } else {
            this.keyObtentionIterationsSysPropertyName = null;
            String iterationsStr = System.getenv(keyObtentionIterationsEnvName);
            if (iterationsStr != null) {
                try {
                    super.setKeyObtentionIterations(new Integer(iterationsStr));
                } catch (NumberFormatException e) {
                    throw new EncryptionInitializationException(e);
                }
            }
        }
    }


    /**
     * Retrieve the name of the JVM system property which value has been
     * loaded as the key obtention iteration count.
     *   
     * @return the name of the property
     */
    public String getKeyObtentionIterationsSysPropertyName() {
        return keyObtentionIterationsSysPropertyName;
    }


    /**
     * Set the config object to use the specified JVM system property to
     * load the value for the key obtention iteration count.
     * 
     * @param keyObtentionIterationsSysPropertyName the name of the property
     */
    public void setKeyObtentionIterationsSysPropertyName(String keyObtentionIterationsSysPropertyName) {
        this.keyObtentionIterationsSysPropertyName = keyObtentionIterationsSysPropertyName;
        if (keyObtentionIterationsSysPropertyName == null) {
            super.setKeyObtentionIterations(null);
        } else {
            this.keyObtentionIterationsEnvName = null;
            String iterationsStr = System.getProperty(keyObtentionIterationsSysPropertyName);
            if (iterationsStr != null) {
                try {
                    super.setKeyObtentionIterations(new Integer(iterationsStr));
                } catch (NumberFormatException e) {
                    throw new EncryptionInitializationException(e);
                }
            }
        }
    }


    /**
     * Retrieve the name of the environment variable which value has been
     * loaded as the password.
     *   
     * @return the name of the variable
     */
    public String getPasswordEnvName() {
        return passwordEnvName;
    }


    /**
     * Set the config object to use the specified environment variable to
     * load the value for the password.
     * 
     * @param passwordEnvName the name of the environment variable
     */
    public void setPasswordEnvName(String passwordEnvName) {
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
        return passwordSysPropertyName;
    }


    /**
     * Set the config object to use the specified JVM system property to
     * load the value for the password.
     * 
     * @param passwordSysPropertyName the name of the property
     */
    public void setPasswordSysPropertyName(String passwordSysPropertyName) {
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
        return saltGeneratorClassNameEnvName;
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
    public void setSaltGeneratorClassNameEnvName(String saltGeneratorClassNameEnvName) {
        this.saltGeneratorClassNameEnvName = saltGeneratorClassNameEnvName;
        if (saltGeneratorClassNameEnvName == null) {
            super.setSaltGenerator(null);
        } else {
            this.saltGeneratorClassNameSysPropertyName = null;
            String saltGeneratorClassName = System.getenv(saltGeneratorClassNameEnvName);
            try {
                Class saltGeneratorClass = Class.forName(saltGeneratorClassName);
                SaltGenerator saltGenerator = (SaltGenerator) saltGeneratorClass.newInstance();
                super.setSaltGenerator(saltGenerator);
            } catch (Exception e) {
                throw new EncryptionInitializationException(e);
            }
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
        return saltGeneratorClassNameSysPropertyName;
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
    public void setSaltGeneratorClassNameSysPropertyName(String saltGeneratorClassNameSysPropertyName) {
        this.saltGeneratorClassNameSysPropertyName = saltGeneratorClassNameSysPropertyName;
        if (saltGeneratorClassNameSysPropertyName == null) {
            super.setSaltGenerator(null);
        } else {
            this.saltGeneratorClassNameEnvName = null;
            String saltGeneratorClassName = System.getProperty(saltGeneratorClassNameSysPropertyName);
            try {
                Class saltGeneratorClass = Class.forName(saltGeneratorClassName);
                SaltGenerator saltGenerator = (SaltGenerator) saltGeneratorClass.newInstance();
                super.setSaltGenerator(saltGenerator);
            } catch (Exception e) {
                throw new EncryptionInitializationException(e);
            }
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
        return providerNameEnvName;
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
    public void setProviderNameEnvName(String providerNameEnvName) {
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
        return providerNameSysPropertyName;
    }


    /**
     * Set the config object to use the specified JVM system property to
     * load the value for the provider name.
     * 
     * @since 1.3
     * 
     * @param providerNameSysPropertyName the name of the property
     */
    public void setProviderNameSysPropertyName(String providerNameSysPropertyName) {
        this.providerNameSysPropertyName = providerNameSysPropertyName;
        if (providerNameSysPropertyName == null) {
            super.setProviderName(null);
        } else {
            this.providerNameEnvName = null;
            super.setProviderName(System.getProperty(providerNameSysPropertyName));
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
        return providerClassNameEnvName;
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
    public void setProviderClassNameEnvName(String providerClassNameEnvName) {
        this.providerClassNameEnvName = providerClassNameEnvName;
        if (providerClassNameEnvName == null) {
            super.setProvider(null);
        } else {
            this.providerClassNameSysPropertyName = null;
            String providerClassName = System.getenv(providerClassNameEnvName);
            try {
                Class providerClass = Class.forName(providerClassName);
                Provider provider = (Provider) providerClass.newInstance();
                super.setProvider(provider);
            } catch (Exception e) {
                throw new EncryptionInitializationException(e);
            }
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
        return providerClassNameSysPropertyName;
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
    public void setProviderClassNameSysPropertyName(String providerClassNameSysPropertyName) {
        this.providerClassNameSysPropertyName = providerClassNameSysPropertyName;
        if (providerClassNameSysPropertyName == null) {
            super.setProvider(null);
        } else {
            this.providerClassNameEnvName = null;
            String providerClassName = System.getProperty(providerClassNameSysPropertyName);
            try {
                Class providerClass = Class.forName(providerClassName);
                Provider provider = (Provider) providerClass.newInstance();
                super.setProvider(provider);
            } catch (Exception e) {
                throw new EncryptionInitializationException(e);
            }
        }
    }
    
    

    
    

    
    public void setAlgorithm(String algorithm) {
        this.algorithmEnvName = null;
        this.algorithmSysPropertyName = null;
        super.setAlgorithm(algorithm);
    }



    public void setKeyObtentionIterations(Integer keyObtentionIterations) {
        this.keyObtentionIterationsEnvName = null;
        this.keyObtentionIterationsSysPropertyName = null;
        super.setKeyObtentionIterations(keyObtentionIterations);
    }



    public void setPassword(String password) {
        this.passwordEnvName = null;
        this.passwordSysPropertyName = null;
        super.setPassword(password);
    }

    
    
    public void setSaltGenerator(SaltGenerator saltGenerator) {
        this.saltGeneratorClassNameEnvName = null;
        this.saltGeneratorClassNameSysPropertyName = null;
        super.setSaltGenerator(saltGenerator);
    }


    public void setProviderName(String providerName) {
        this.providerNameEnvName = null;
        this.providerNameSysPropertyName = null;
        super.setProviderName(providerName);
    }

    
    
    public void setProvider(Provider provider) {
        this.providerClassNameEnvName = null;
        this.providerClassNameSysPropertyName = null;
        super.setProvider(provider);
    }


    
}
