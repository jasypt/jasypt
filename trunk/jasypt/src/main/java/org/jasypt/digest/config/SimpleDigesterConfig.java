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
 * 
 * @since 1.0
 * 
 * @author Daniel Fern&aacute;ndez Garrido
 * 
 */
public class SimpleDigesterConfig implements DigesterConfig {

    private static final long serialVersionUID = 7854221035086673697L;
    
    private String algorithm = null;
    private Integer iterations = null;
    private Integer saltSizeBytes = null; 
    

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
     * This algorithm has to be supported by your Java Virtual Machine, and
     * it should be allowed as an algorithm for creating
     * java.security.MessageDigest instances.
     * </p>
     * <p>
     * For valid names, see <a target="_blank" 
     *         href="http://java.sun.com/j2se/1.5.0/docs/guide/security/CryptoSpec.html#AppA">Java 
     *         Cryptography Architecture API Specification & 
     *         Reference</a>.
     * </p>
     * <p>
     * If not set, null will returned.
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
     * If not set, null will returned.
     * </p>
     * 
     * @param iterations the number of iterations.
     */
    public void setIterations(Integer iterations) {
        this.iterations = iterations;
    }

    
    /**
     * <p>
     * Size in bytes of the random salt to be used.
     * </p>
     * <p>
     * If not set, null will returned.
     * </p>
     * 
     * @param saltSizeBytes the size of the random salt, in bytes.
     */
    public void setSaltSizeBytes(Integer saltSizeBytes) {
        this.saltSizeBytes = saltSizeBytes;
    }

    
    public String getAlgorithm() {
        return algorithm;
    }

    
    public Integer getIterations() {
        return iterations;
    }

    
    public Integer getSaltSizeBytes() {
        return saltSizeBytes;
    }

    
}
