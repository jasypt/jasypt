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
package org.jasypt.encryption.pbe;

import org.jasypt.encryption.StringEncryptor;

/**
 * <p>
 * Common interface for all Password Based Encryptors which receive a 
 * Strig message and return a String result.
 * </p>
 * <p>
 * For a default implementation, see {@link StandardPBEStringEncryptor}.
 * </p>
 * 
 * @since 1.0
 * 
 * @author Daniel Fern&aacute;ndez Garrido
 * 
 */
public interface PBEStringEncryptor extends StringEncryptor {

    /**
     * <p>
     * Sets a password to be used by the encryptor.
     * </p>
     * 
     * @param password the password to be used.
     */
    public void setPassword(String password);
    
}
