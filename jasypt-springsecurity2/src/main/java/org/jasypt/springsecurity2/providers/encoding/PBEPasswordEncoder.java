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
package org.jasypt.springsecurity2.providers.encoding;

import org.jasypt.encryption.pbe.PBEStringEncryptor;
import org.jasypt.exceptions.EncryptionInitializationException;
import org.jasypt.util.text.BasicTextEncryptor;
import org.jasypt.util.text.TextEncryptor;

/**
 * <p>
 * This class implements the Spring Security 2.x 
 * <tt>org.springframework.security.providers.encoding.PasswordEncoder</tt>
 * interface, allowing Spring Security-enabled applications to use JASYPT 
 * for password encryption.
 * </p>
 * <p>
 * <b>Important</b>: This class allows bi-directional password-based encryption
 * of user passwords
 * in Spring Security using Jasypt. But please note that passwords <b>should not be
 * encrypted in a bi-directional way</b>, but instead as uni-directional
 * digests (hashes). Encrypting passwords in a way they can be decrypted
 * can be a severe security issue, and should only be considered in legacy
 * or complex inter-application integration scenarios. 
 * </p>
 * <p>
 * Objects of this class will internally hold either an object of type
 * <tt>org.jasypt.util.text.TextEncryptor</tt> or an object of type
 * <tt>org.jasypt.encryption.pbe.PBEStringEncryptor</tt> (only one of them),
 * which should be set by respectively calling 
 * {@link #setTextEncryptor(TextEncryptor)} or
 * {@link #setPbeStringEncryptor(PBEStringEncryptor)}
 * after creation. If neither a <tt>TextEncryptor</tt> nor
 * a <tt>PBEStringEncryptor</tt> are set, a new 
 * <tt>org.jasypt.util.text.BasicTextEncryptor</tt> object is
 * created and internally used.
 * </p>
 * <p>
 * Important: <b>This implementation ignores any salt provided through
 * the interface methods</b>, as the internal Jasypt 
 * <tt>TextEncryptor</tt> or <tt>PBEStringEncryptor</tt> objects normally use a 
 * random one. This means that salt can be safely passed as 
 * <tt>null</tt>.
 * </p>
 * <p>
 * <b><u>Usage with a TextEncryptor</u></b>
 * </p>
 * <p>
 * This class can be used like this from your Spring XML resource files:
 * </p>
 * <pre>
 *  ...
 *  &lt;!-- Your application may use the TextEncryptor in several places,     --> 
 *  &lt;!-- like for example at new user sign-up.                             --> 
 *  &lt;bean id="jasyptTextEncryptor" class="org.jasypt.util.text.StrongTextEncryptor" >
 *    &lt;property name="password" value="myPassword" />
 *  &lt;/bean>
 *  ...
 *  ...
 *  &lt;!-- This Spring Security-friendly PasswordEncoder implementation will -->
 *  &lt;!-- wrap the TextEncryptor instance so that it can be used from       -->
 *  &lt;!-- the security framework.                                           -->
 *  &lt;bean id="passwordEncoder" class="org.jasypt.spring.security2.PBEPasswordEncoder">
 *    &lt;property name="textEncryptor">
 *      &lt;ref bean="jasyptTextEncryptor" />
 *    &lt;/property>
 *  &lt;/bean>
 *  ...
 *  ...
 *  &lt;!-- Your DaoAuthenticationProvider will then use it like with any     -->
 *  &lt;!-- other implementation of the PasswordEncoder interface.            -->
 *  &lt;bean id="daoAuthenticationProvider" class="org.springframework.security.providers.dao.DaoAuthenticationProvider">
 *      &lt;property name="userDetailsService" ref="userDetailsService"/>
 *      &lt;property name="passwordEncoder">
 *        &lt;ref bean="passwordEncoder" />
 *      &lt;/property>
 *  &lt;/bean>
 *  ...
 * </pre>
 * <p>
 * <b><u>Usage with a PBEStringEncryptor</u></b>
 * </p>
 * <p>
 * This class can be used like this from your Spring XML resource files:
 * </p>
 * <pre>
 *  ...
 *  &lt;!-- Your application may use the PBEStringEncryptor in several places,--> 
 *  &lt;!-- like for example at new user sign-up.                             --> 
 *  &lt;bean id="jasyptPBEStringEncryptor" class="org.jasypt.encryption.pbe.StandardPBEStringEncryptor" >
 *    &lt;property name="algorithm" value="PBEWithMD5AndTripleDES" />
 *    &lt;property name="password" value="myPassword" />
 *  &lt;/bean>
 *  ...
 *  ...
 *  &lt;!-- This Spring Security-friendly PasswordEncoder implementation will -->
 *  &lt;!-- wrap the PBEStringEncryptor instance so that it can be used from  -->
 *  &lt;!-- the security framework.                                           -->
 *  &lt;bean id="passwordEncoder" class="org.jasypt.spring.security2.PBEPasswordEncoder">
 *    &lt;property name="pbeStringEncryptor">
 *      &lt;ref bean="jasyptPBEStringEncryptor" />
 *    &lt;/property>
 *  &lt;/bean>
 *  ...
 *  ...
 *  &lt;!-- Your DaoAuthenticationProvider will then use it like with any     -->
 *  &lt;!-- other implementation of the PasswordEncoder interface.            -->
 *  &lt;bean id="daoAuthenticationProvider" class="org.springframework.security.providers.dao.DaoAuthenticationProvider">
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
 * @since 1.9.0 (existed as org.jasypt.spring.security2.PasswordEncoder since 1.5)
 * 
 * @author Daniel Fern&aacute;ndez
 * 
 */
public final class PBEPasswordEncoder 
        implements org.springframework.security.providers.encoding.PasswordEncoder {

    // The text encryptor or PBE string encryptor to be internally used
    private TextEncryptor textEncryptor = null;
    private PBEStringEncryptor pbeStringEncryptor = null;
    private Boolean useTextEncryptor = null;
    
    
    /**
     * Creates a new instance of <tt>PBEPasswordEncoder</tt>
     */
    public PBEPasswordEncoder() {
        super();
    }
    

    /**
     * Sets a text encryptor to be used. Only one of 
     * <tt>setTextEncryptor</tt> or <tt>setPBEStringEncryptor</tt> should be
     * called. If both are, the last call will define which method will be
     * used.
     * 
     * @param textEncryptor the text encryptor instance to be used.
     */
    public void setTextEncryptor(final TextEncryptor textEncryptor) {
        this.textEncryptor = textEncryptor;
        this.useTextEncryptor = Boolean.TRUE;
    }

    /**
     * Sets a string digester to be used. Only one of 
     * <tt>setTextEncryptor</tt> or <tt>setPBEStringEncryptor</tt> should be
     * called. If both are, the last call will define which method will be
     * used.
     * 
     * @param pbeStringEncryptor the PBE string encryptor instance to be used.
     */
    public void setPbeStringEncryptor(final PBEStringEncryptor pbeStringEncryptor) {
        this.pbeStringEncryptor = pbeStringEncryptor;
        this.useTextEncryptor = Boolean.FALSE;
    }

    
    /**
     * Encodes a password. This implementation completely ignores salt, 
     * as jasypt's <tt>TextEncryptor</tt> and <tt>PBEStringEncryptor</tt> 
     * normally use a random one. Thus, it can be safely passed as <tt>null</tt>.
     * 
     * @param rawPass The password to be encoded.
     * @param salt The salt, which will be ignored. It can be null.
     */
    public String encodePassword(final String rawPass, final Object salt) {
        checkInitialization();
        if (this.useTextEncryptor.booleanValue()) {
            return this.textEncryptor.encrypt(rawPass);
        }
        return this.pbeStringEncryptor.encrypt(rawPass);
    }


    /**
     * Checks a password's validity. This implementation completely ignores
     * salt, as jasypt's <tt>TextEncryptor</tt> and <tt>PBEStringEncryptor</tt>
     * normally use a random one. Thus, it can be safely passed as <tt>null</tt>.
     * 
     * @param encPass The encrypted password against which to check.
     * @param rawPass The password to be checked.
     * @param salt The salt, which will be ignored. It can be null.
     */
    public boolean isPasswordValid(final String encPass, final String rawPass, final Object salt) {
        checkInitialization();
        String decPassword = null;
        if (this.useTextEncryptor.booleanValue()) {
            decPassword = this.textEncryptor.decrypt(encPass);
        } else {
            decPassword = this.pbeStringEncryptor.decrypt(encPass);
        }
        if ((decPassword == null) || (rawPass == null)) {
            return (decPassword == rawPass);
        }
        return decPassword.equals(rawPass);
    }


    /*
     * Checks that the PasswordEncoder has been correctly initialized
     * (either a text encryptor or a PBE string encryptor has been set).
     */
    private synchronized void checkInitialization() {
        if (this.useTextEncryptor == null) {
            this.textEncryptor = new BasicTextEncryptor();
            this.useTextEncryptor = Boolean.TRUE;
        } else {
            if (this.useTextEncryptor.booleanValue()) {
                if (this.textEncryptor == null) {
                    throw new EncryptionInitializationException(
                            "PBE Password encoder not initialized: text " +
                            "encryptor is null");
                }
            } else {
                if (this.pbeStringEncryptor == null) {
                    throw new EncryptionInitializationException(
                            "PBE Password encoder not initialized: PBE " +
                            "string encryptor is null");
                }
            }
        }
    }
    
}
