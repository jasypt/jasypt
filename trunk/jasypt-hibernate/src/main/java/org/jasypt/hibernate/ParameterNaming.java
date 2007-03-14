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
package org.jasypt.hibernate;

/**
 * <p>
 * Constant names of the parameters that can be used by a jasypt type's
 * typedef declaration in a Hibernate mapping.
 * </p>
 * 
 * @since 1.0
 * 
 * @author Daniel Fern&aacute;ndez Garrido
 * 
 */
public class ParameterNaming {

    /**
     * <p>
     * The registered name of an encryptor previously registered at the 
     * {@link org.jasypt.hibernate.encryptor.HibernatePBEEncryptorRegistry}.
     * </p>
     * <p>
     * Value = <tt>encryptorRegisteredName</tt>
     * </p>
     */
    public static final String ENCRYPTOR_NAME = "encryptorRegisteredName";
    
    /**
     * <p>
     * The encryption algorithm.
     * </p>
     * <p>
     * Value = <tt>algorithm</tt>
     * </p>
     */
    public static final String ALGORITHM = "algorithm";
    
    /**
     * <p>
     * The encryption password.
     * </p>
     * <p>
     * Value = <tt>password</tt>
     * </p>
     */
    public static final String PASSWORD = "password";
    
    /**
     * <p>
     * The number of hashing iterations to be applied for obtaining the 
     * encryption key.
     * </p>
     * <p>
     * Value = <tt>keyObtentionIterations</tt>
     * </p>
     */
    public static final String KEY_OBTENTION_ITERATIONS = 
        "keyObtentionIterations";
    
    
    
    private ParameterNaming() {}
    
}
