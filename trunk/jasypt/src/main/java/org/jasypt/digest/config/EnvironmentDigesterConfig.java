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
package org.jasypt.digest.config;

import org.jasypt.exceptions.EncryptionInitializationException;

/**
 * <p>
 * Implementation for {@link DigesterConfig} which can retrieve configuration
 * values from environment variables or system properties.
 * </p>
 * <p>
 * The name of the environment variable or system property (JVM property) to
 * query for each parameter can be set with its corresponding 
 * <tt>setXEnvName</tt> or <tt>setXSysProperty</tt> method.
 * </p>
 * <p>
 * As this class extends {@link SimpleDigesterConfig}, parameter values
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
public class EnvironmentDigesterConfig extends SimpleDigesterConfig {

    private static final long serialVersionUID = -4238368733679817880L;
    
    private String algorithmEnvName = null;
    private String iterationsEnvName = null;
    private String saltSizeBytesEnvName = null;

    private String algorithmSysPropertyName = null;
    private String iterationsSysPropertyName = null;
    private String saltSizeBytesSysPropertyName = null;
    

    /**
     * <p>
     * Creates a new <tt>EnvironmentDigesterConfig</tt> instance.
     * </p>
     */
    public EnvironmentDigesterConfig() {
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
     * loaded as the iteration count.
     *   
     * @return the name of the variable
     */
    public String getIterationsEnvName() {
        return iterationsEnvName;
    }


    /**
     * Set the config object to use the specified environment variable to
     * load the value for the iteration count.
     * 
     * @param iterationsEnvName the name of the environment variable
     */
    public void setIterationsEnvName(String iterationsEnvName) {
        this.iterationsEnvName = iterationsEnvName;
        if (iterationsEnvName == null) {
            super.setIterations(null);
        } else {
            this.iterationsSysPropertyName = null;
            String iterationsStr = System.getenv(iterationsEnvName);
            if (iterationsStr != null) {
                try {
                    super.setIterations(new Integer(iterationsStr));
                } catch (NumberFormatException e) {
                    throw new EncryptionInitializationException(e);
                }
            }
        }
    }


    /**
     * Retrieve the name of the JVM system property which value has been
     * loaded as the iteration count.
     *   
     * @return the name of the property
     */
    public String getIterationsSysPropertyName() {
        return iterationsSysPropertyName;
    }


    /**
     * Set the config object to use the specified JVM system property to
     * load the value for the iteration count.
     * 
     * @param iterationsSysPropertyName the name of the property
     */
    public void setIterationsSysPropertyName(String iterationsSysPropertyName) {
        this.iterationsSysPropertyName = iterationsSysPropertyName;
        if (iterationsSysPropertyName == null) {
            super.setIterations(null);
        } else {
            this.iterationsEnvName = null;
            String iterationsStr = System.getProperty(iterationsSysPropertyName);
            if (iterationsStr != null) {
                try {
                    super.setIterations(new Integer(iterationsStr));
                } catch (NumberFormatException e) {
                    throw new EncryptionInitializationException(e);
                }
            }
        }
    }


    /**
     * Retrieve the name of the environment variable which value has been
     * loaded as the salt size in bytes.
     *   
     * @return the name of the variable
     */
    public String getSaltSizeBytesEnvName() {
        return saltSizeBytesEnvName;
    }


    /**
     * Set the config object to use the specified environment variable to
     * load the value for the salt size in bytes.
     * 
     * @param saltSizeBytesEnvName the name of the environment variable
     */
    public void setSaltSizeBytesEnvName(String saltSizeBytesEnvName) {
        this.saltSizeBytesEnvName = saltSizeBytesEnvName;
        if (saltSizeBytesEnvName == null) {
            super.setSaltSizeBytes(null);
        } else {
            this.saltSizeBytesSysPropertyName = null;
            String saltSizeBytesStr = System.getenv(saltSizeBytesEnvName);
            if (saltSizeBytesStr != null) {
                try {
                    super.setSaltSizeBytes(new Integer(saltSizeBytesStr));
                } catch (NumberFormatException e) {
                    throw new EncryptionInitializationException(e);
                }
            }
        }
    }


    /**
     * Retrieve the name of the JVM system property which value has been
     * loaded as the salt size in bytes.
     *   
     * @return the name of the property
     */
    public String getSaltSizeBytesSysPropertyName() {
        return saltSizeBytesSysPropertyName;
    }


    /**
     * Set the config object to use the specified JVM system property to
     * load the value for the salt size in bytes.
     * 
     * @param saltSizeBytesSysPropertyName the name of the property
     */
    public void setSaltSizeBytesSysPropertyName(String saltSizeBytesSysPropertyName) {
        this.saltSizeBytesSysPropertyName = saltSizeBytesSysPropertyName;
        if (saltSizeBytesSysPropertyName == null) {
            super.setSaltSizeBytes(null);
        } else {
            this.saltSizeBytesEnvName = null;
            String saltSizeBytesStr = System.getProperty(saltSizeBytesSysPropertyName);
            if (saltSizeBytesStr != null) {
                try {
                    super.setSaltSizeBytes(new Integer(saltSizeBytesStr));
                } catch (NumberFormatException e) {
                    throw new EncryptionInitializationException(e);
                }
            }
        }
    }
    
    


    
    public void setAlgorithm(String algorithm) {
        this.algorithmEnvName = null;
        this.algorithmSysPropertyName = null;
        super.setAlgorithm(algorithm);
    }



    public void setIterations(Integer iterations) {
        this.iterationsEnvName = null;
        this.iterationsSysPropertyName = null;
        super.setIterations(iterations);
    }



    public void setSaltSizeBytes(Integer saltSizeBytes) {
        this.saltSizeBytesEnvName = null;
        this.saltSizeBytesSysPropertyName = null;
        super.setSaltSizeBytes(saltSizeBytes);
    }


    
}
