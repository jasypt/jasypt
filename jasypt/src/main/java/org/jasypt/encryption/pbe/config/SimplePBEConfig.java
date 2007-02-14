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
    
    private static final long serialVersionUID = -5536955400809738920L;
    
    private String algorithm = null;
    private String password = null;
    private Integer keyObtentionIterations = null;
    


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
     * This algorithm has to be supported by your Java Virtual Machine, and
     * it must be one of the algorithms registered at 
     * {@link org.jasypt.encryption.pbe.algorithms.PBEAlgorithms}.
     * </p>
     * 
     * @param algorithm the name of the algorithm to be used
     * @see org.jasypt.encryption.pbe.algorithms.PBEAlgorithms
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
    
    
    public String getAlgorithm() {
        return algorithm;
    }

    
    public String getPassword() {
        return password;
    }

    
    public Integer getKeyObtentionIterations() {
        return keyObtentionIterations;
    }

    
}
