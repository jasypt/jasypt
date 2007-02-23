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

import org.jasypt.exceptions.EncryptionInitializationException;

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
    
    private static final long serialVersionUID = -3471444970805905683L;
    
    private String algorithmEnvName = null;
    private String keyObtentionIterationsEnvName = null;
    private String passwordEnvName = null;

    private String algorithmSysPropertyName = null;
    private String keyObtentionIterationsSysPropertyName = null;
    private String passwordSysPropertyName = null;
    

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


    
}
