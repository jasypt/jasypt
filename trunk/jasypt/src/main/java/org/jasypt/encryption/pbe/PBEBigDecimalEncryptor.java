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

import org.jasypt.encryption.BigDecimalEncryptor;

/**
 * <p>
 * Common interface for all Password Based Encryptors which receive a 
 * BigDecimal message and return a BigDecimal result.
 * </p>
 * <p>
 * <b>Important</b>: The size of the result of encrypting a number, depending
 * on the algorithm, may be much bigger (in bytes) than the size of the 
 * encrypted number itself. For example, encrypting a 4-byte integer can
 * result in an encrypted 16-byte number. This can lead the user into 
 * problems if the encrypted values are to be stored and not enough room 
 * has been provided.
 * </p>
 * <p>
 * For a default implementation, see {@link StandardPBEBigDecimalEncryptor}.
 * </p>
 * 
 * @since 1.2
 * 
 * @author Daniel Fern&aacute;ndez Garrido
 * 
 */
public interface PBEBigDecimalEncryptor 
        extends BigDecimalEncryptor, PasswordBased {

    
}
