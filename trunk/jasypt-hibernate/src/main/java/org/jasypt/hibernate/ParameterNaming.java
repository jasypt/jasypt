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
 * Constant parameter names that can be used by an
 * {@link EncryptedTextType} typedef declaration in a Hibernate mapping.
 * </p>
 * 
 * @since 1.0
 * 
 * @author Daniel Fern&aacute;ndez Garrido
 * 
 */
public class ParameterNaming {

    /**
     * The registered name of an encryptor previously registered at the 
     * {@link HibernatePBEEncryptorRegistry}.
     */
    public static final String ENCRYPTOR_NAME = "encryptorRegisteredName";
    
    /**
     * The encryption algorithm.
     */
    public static final String ALGORITHM = "algorithm";
    
    /**
     * The encryption password.
     */
    public static final String PASSWORD = "password";
    
    /**
     * The number of hashing iterations to be applied for obtaining the 
     * encryption key.
     */
    public static final String KEY_OBTENTION_ITERATIONS = 
        "keyObtentionIterations";
    
    
    
    private ParameterNaming() {}
    
}
