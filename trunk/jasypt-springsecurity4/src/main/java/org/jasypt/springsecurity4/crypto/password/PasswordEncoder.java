/*
 * =============================================================================
 * 
 *   Copyright (c) 2007-2010, The JASYPT team (http://www.jasypt.org)
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
package org.jasypt.springsecurity4.crypto.password;

import org.jasypt.digest.StringDigester;
import org.jasypt.exceptions.EncryptionInitializationException;
import org.jasypt.util.password.BasicPasswordEncryptor;
import org.jasypt.util.password.PasswordEncryptor;

/**
 * <p>
 * This class implements the Spring Security 4.x 
 * <tt>org.springframework.security.crypto.password.PasswordEncoder</tt>
 * interface, allowing Spring Security-enabled applications to use JASYPT 
 * for password encryption.
 * </p>
 * <p>
 * Objects of this class will internally hold either an object of type
 * <tt>org.jasypt.util.password.PasswordEncryptor</tt> or an object of type
 * <tt>org.jasypt.digest.StringDigester</tt> (only one of them),
 * which should be set by respectively calling 
 * {@link #setPasswordEncryptor(PasswordEncryptor)} or
 * {@link #setStringDigester(StringDigester)}
 * after creation. If neither a <tt>PasswordEncryptor</tt> nor
 * a <tt>StringDigester</tt> are set, a new 
 * <tt>org.jasypt.util.password.BasicPasswordEncryptor</tt> object is
 * created and internally used.
 * </p>
 * <p>
 * <b><u>Usage with a PasswordEncryptor</u></b>
 * </p>
 * <p>
 * This class can be used like this from your Spring XML resource files:
 * </p>
 * <pre>
 *  ...
 *  &lt;!-- Your application may use the PasswordEncryptor in several places, --> 
 *  &lt;!-- like for example at new user sign-up.                             --> 
 *  &lt;bean id="jasyptPasswordEncryptor" class="org.jasypt.util.password.StrongPasswordEncryptor" />
 *  ...
 *  ...
 *  &lt;!-- This Spring Security-friendly PasswordEncoder implementation will -->
 *  &lt;!-- wrap the PasswordEncryptor instance so that it can be used from   -->
 *  &lt;!-- the security framework.                                           -->
 *  &lt;bean id="passwordEncoder" class="org.jasypt.springsecurity4.springsecurity4.crypto.password.PasswordEncoder">
 *    &lt;property name="passwordEncryptor">
 *      &lt;ref bean="jasyptPasswordEncryptor" />
 *    &lt;/property>
 *  &lt;/bean>
 *  ...
 *  ...
 *  &lt;!-- Your DaoAuthenticationProvider will then use it like with any     -->
 *  &lt;!-- other implementation of the PasswordEncoder interface.            -->
 *  &lt;bean id="daoAuthenticationProvider" class="org.springframework.security.authentication.dao.DaoAuthenticationProvider">
 *      &lt;property name="userDetailsService" ref="userDetailsService"/>
 *      &lt;property name="passwordEncoder">
 *        &lt;ref bean="passwordEncoder" />
 *      &lt;/property>
 *  &lt;/bean>
 *  ...
 * </pre>
 * <p>
 * <b><u>Usage with a StringDigester</u></b>
 * </p>
 * <p>
 * This class can be used like this from your Spring XML resource files:
 * </p>
 * <pre>
 *  ...
 *  &lt;!-- Your application may use the StringDigester in several places,    --> 
 *  &lt;!-- like for example at new user sign-up.                             --> 
 *  &lt;bean id="jasyptStringDigester" class="org.jasypt.digest.StandardStringDigester" >
 *    &lt;property name="algorithm" value="SHA-1" />
 *    &lt;property name="iterations" value="100000" />
 *  &lt;/bean>
 *  ...
 *  ...
 *  &lt;!-- This Spring Security-friendly PasswordEncoder implementation will -->
 *  &lt;!-- wrap the StringDigester instance so that it can be used from      -->
 *  &lt;!-- the security framework.                                           -->
 *  &lt;bean id="passwordEncoder" class="org.jasypt.springsecurity4.crypto.password.PasswordEncoder">
 *    &lt;property name="stringDigester">
 *      &lt;ref bean="jasyptStringDigester" />
 *    &lt;/property>
 *  &lt;/bean>
 *  ...
 *  ...
 *  &lt;!-- Your DaoAuthenticationProvider will then use it like with any     -->
 *  &lt;!-- other implementation of the PasswordEncoder interface.            -->
 *  &lt;bean id="daoAuthenticationProvider" class="org.springframework.security.authentication.dao.DaoAuthenticationProvider">
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
 * @since 1.9.3
 * 
 * @author Hoki Torres
 * 
 */
public final class PasswordEncoder 
        implements org.springframework.security.crypto.password.PasswordEncoder {

    // The password encryptor or string digester to be internally used
    private PasswordEncryptor passwordEncryptor = null;
    private StringDigester stringDigester = null;
    private Boolean useEncryptor = null;
    
    
    /**
     * Creates a new instance of <tt>PasswordEncoder</tt>
     */
    public PasswordEncoder() {
        super();
    }
    

    /**
     * Sets a password encryptor to be used. Only one of 
     * <tt>setPasswordEncryptor</tt> or <tt>setStringDigester</tt> should be
     * called. If both are, the last call will define which method will be
     * used.
     * 
     * @param passwordEncryptor the password encryptor instance to be used.
     */
    public void setPasswordEncryptor(final PasswordEncryptor passwordEncryptor) {
        this.passwordEncryptor = passwordEncryptor;
        this.useEncryptor = Boolean.TRUE;
    }

    /**
     * Sets a string digester to be used. Only one of 
     * <tt>setPasswordEncryptor</tt> or <tt>setStringDigester</tt> should be
     * called. If both are, the last call will define which method will be
     * used.
     * 
     * @param stringDigester the string digester instance to be used.
     */
    public void setStringDigester(final StringDigester stringDigester) {
        this.stringDigester = stringDigester;
        this.useEncryptor = Boolean.FALSE;
    }

    
    /**
     * Encodes a password.
     * 
     * @param rawPassword The password to be encoded.
     */
    public String encode(CharSequence rawPassword) {
        checkInitialization();
        if (this.useEncryptor.booleanValue()) {
            return this.passwordEncryptor.encryptPassword(rawPassword.toString());
        }
        return this.stringDigester.digest(rawPassword.toString());
    }


    /**
     * Checks a password's validity.
     * 
     * @param encodedPassword The encrypted password (digest) against which to check.
     * @param rawPassword The password to be checked.
     */
    public boolean matches(CharSequence rawPassword, String encodedPassword) {
        checkInitialization();
        if (this.useEncryptor.booleanValue()) {
            return this.passwordEncryptor.checkPassword(rawPassword.toString(), encodedPassword);
        }
        return this.stringDigester.matches(rawPassword.toString(), encodedPassword);
    }


    /*
     * Checks that the PasswordEncoder has been correctly initialized
     * (either a password encryptor or a string digester has been set).
     */
    private synchronized void checkInitialization() {
        if (this.useEncryptor == null) {
            this.passwordEncryptor = new BasicPasswordEncryptor();
            this.useEncryptor = Boolean.TRUE;
        } else {
            if (this.useEncryptor.booleanValue()) {
                if (this.passwordEncryptor == null) {
                    throw new EncryptionInitializationException(
                            "Password encoder not initialized: password " +
                            "encryptor is null");
                }
            } else {
                if (this.stringDigester == null) {
                    throw new EncryptionInitializationException(
                            "Password encoder not initialized: string " +
                            "digester is null");
                }
            }
        }
    }
    
}
