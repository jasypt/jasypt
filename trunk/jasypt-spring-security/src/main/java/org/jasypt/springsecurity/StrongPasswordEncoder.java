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
package org.jasypt.springsecurity;

import org.acegisecurity.providers.encoding.PasswordEncoder;
import org.jasypt.util.StrongPasswordEncryptor;

/**
 * <p>
 * </p>
 * <p>
 * This class is <i>thread-safe</i>
 * </p>
 * 
 * @since 1.1
 * 
 * @author Daniel Fern&aacute;ndez Garrido
 * 
 */
public class StrongPasswordEncoder implements PasswordEncoder {

    private StrongPasswordEncryptor passwordEncryptor = null;
    
    
    public StrongPasswordEncoder() {
        this.passwordEncryptor = new StrongPasswordEncryptor();
    }
    
    
    public StrongPasswordEncoder(StrongPasswordEncryptor passwordEncryptor) {
        this.passwordEncryptor = passwordEncryptor;
    }

    
    public void setStrongPasswordEncryptor(
            StrongPasswordEncryptor passwordEncryptor) {
        this.passwordEncryptor = passwordEncryptor;
    }
    
    public String encodePassword(String rawPass, Object salt) {
        return passwordEncryptor.encryptPassword(rawPass);
    }

    public boolean isPasswordValid(String encPass, String rawPass, Object salt) {
        return passwordEncryptor.checkPassword(rawPass, encPass);
    }

}
