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
 * This class implements the Spring Security (ACEGI) 
 * <tt>org.acegisecurity.providers.encoding.PasswordEncoder</tt>
 * interface, allowing Spring Security-enabled applications to use JASYPT 
 * for password encryption.
 * </p>
 * <p>
 * Objects of this class will internally hold an object of type
 * <tt>org.jasypt.util.StrongPasswordEncryptor</tt>, which can be set at 
 * creation time (by using
 * the appropiate constructor) or by calling 
 * {@link #setStrongPasswordEncryptor(StrongPasswordEncryptor)} after 
 * creation. If a <tt>StrongPasswordEncryptor</tt> is not set in either way, 
 * a new one is created and internally used.
 * </p>
 * <p>
 * Important: <b>This implementation ignores any salt provided through
 * the interface methods</b>, as the internal Jasypt <tt>StrongPasswordEncryptor</tt>
 * object uses a random one. This means that salt can be safely passed as 
 * <tt>null</tt>.
 * </p>
 * <p>
 * <b><u>Usage</u></b>
 * </p>
 * <p>
 * This class can be used like this from your Spring XML resource files:
 * </p>
 * <pre>
 *  ...
 *  &lt;!-- Your application may use the StrongPasswordEncryptor in several   --> 
 *  &lt;!-- places, like for example at new user sign-up.                     --> 
 *  &lt;bean id="jasyptStrongPasswordEncryptor" class="org.jasypt.util.StrongPasswordEncryptor" />
 *  ...
 *  ...
 *  &lt;!-- This Spring Security-friendly PasswordEncoder implementation will -->
 *  &lt;!-- wrap the StrongPasswordEncryptor instance so that it can be used  -->
 *  &lt;!-- from the security framework.                                      -->
 *  &lt;bean id="passwordEncoder" class="org.jasypt.springsecurity.StrongPasswordEncoder">
 *    &lt;property name="strongPasswordEncryptor">
 *      &lt;ref bean="jasyptStrongPasswordEncryptor" />
 *    &lt;/property>
 *  &lt;/bean>
 *  ...
 *  ...
 *  &lt;!-- Your DaoAuthenticationProvider will then use it like with any     -->
 *  &lt;!-- other implementation of the PasswordEncoder interface.            -->
 *  &lt;bean id="daoAuthenticationProvider" class="org.acegisecurity.providers.dao.DaoAuthenticationProvider">
 *      &lt;property name="userDetailsService" ref="userDetailsService"/>
 *      &lt;property name="passwordEncoder">
 *        &lt;ref bean="passwordEncoder" />
 *      &lt;/property>
 *  &lt;/bean>
 *  ...
 * </pre>
 * <p>
 * This class is <i>thread-safe</i>
 * </p>
 * 
 * @since 1.1
 * @deprecated Replaced by {@link org.jasypt.springsecurity.PasswordEncoder}
 *             and will be removed in version 1.3. 
 * 
 * @author Daniel Fern&aacute;ndez Garrido
 * 
 */
public class StrongPasswordEncoder implements PasswordEncoder {

    // The strong password encryptor to be internally used
    private StrongPasswordEncryptor strongPasswordEncryptor = null;
    
    
    /**
     * Creates a new instance of <tt>StrongPasswordEncoder</tt>
     *
     */
    public StrongPasswordEncoder() {
        this.strongPasswordEncryptor = new StrongPasswordEncryptor();
    }
    
    
    /**
     * Creates a new instance of <tt>StrongPasswordEncoder</tt>, setting
     * a specific <tt>StrongPasswordEncryptor</tt> instance to be used.
     *
     * @param strongPasswordEncryptor the <tt>StrongPasswordEncryptor</tt> 
     *        instance to be used.
     */
    public StrongPasswordEncoder(StrongPasswordEncryptor strongPasswordEncryptor) {
        this.strongPasswordEncryptor = strongPasswordEncryptor;
    }

    
    /**
     * Sets the strong password encryptor instance to be used.
     * 
     * @param strongPasswordEncryptor the strong password encryptor instance 
     *        to be used.
     */
    public void setStrongPasswordEncryptor(
            StrongPasswordEncryptor strongPasswordEncryptor) {
        this.strongPasswordEncryptor = strongPasswordEncryptor;
    }
    
    
    /**
     * Encodes a password. This implementation completely ignores salt, 
     * as jasypt's <tt>StrongPasswordEncryptor</tt> uses a random one. Thus, it 
     * can be safely passed as <tt>null</tt>.
     * 
     * @param rawPass The password to be encoded.
     * @param salt The salt, which will be ignored. It can be null.
     */
    public String encodePassword(String rawPass, Object salt) {
        return strongPasswordEncryptor.encryptPassword(rawPass);
    }

    
    /**
     * Checks a password's validity. This implementation completely ignores
     * salt, as jasypt's <tt>StrongPasswordEncryptor</tt> uses a random one. 
     * Thus, it can be safely passed as <tt>null</tt>.
     * 
     * @param encPass The encrypted password (digest) against which to check.
     * @param rawPass The password to be checked.
     * @param salt The salt, which will be ignored. It can be null.
     */
    public boolean isPasswordValid(String encPass, String rawPass, Object salt) {
        return strongPasswordEncryptor.checkPassword(rawPass, encPass);
    }

}
