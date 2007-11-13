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
package org.jasypt.hibernate.encryptor;

import java.math.BigInteger;

import org.jasypt.encryption.pbe.PBEBigIntegerEncryptor;
import org.jasypt.encryption.pbe.StandardPBEBigIntegerEncryptor;
import org.jasypt.encryption.pbe.config.PBEConfig;
import org.jasypt.exceptions.EncryptionInitializationException;
import org.jasypt.salt.SaltGenerator;

/**
 * <p>
 * Placeholder class for <tt>PBEBigIntegerEncryptor</tt> objects which are
 * eligible for use from Hibernate. 
 * </p>
 * <p>
 * This class acts as a wrapper on a <tt>PBEBigIntegerEncryptor</tt>, allowing
 * to be set a <b>registered name</b> (see {@link #setRegisteredName(String)})
 * and performing the needed registry operations against the 
 * {@link HibernatePBEEncryptorRegistry}.
 * </p>
 * <p>
 * <b>It is not mandatory that a <tt>PBEBigIntegerEncryptor</tt> be explicitly set
 * with {@link #setEncryptor(PBEBigIntegerEncryptor)}</b>. If not, a
 * <tt>StandardPBEBigIntegerEncryptor</tt> object will be created internally
 * and it will be configurable with the {@link #setPassword(String)},
 * {@link #setAlgorithm(String)}, {@link #setKeyObtentionIterations(int)},
 * {@link #setSaltGenerator(SaltGenerator)}
 * and  {@link #setConfig(PBEConfig)} methods.
 * </p>
 * <p>
 * This class is mainly intended for use from Spring Framework or some other
 * IoC container (if you are not using a container of this kind, please see 
 * {@link HibernatePBEEncryptorRegistry}). The steps to be performed are 
 * the following:
 * <ol>
 *   <li>Create an object of this class (declaring it).</li>
 *   <li>Set its <tt>registeredName</tt> and, either its 
 *       wrapped <tt>encryptor</tt> or its <tt>password</tt>, 
 *       <tt>algorithm</tt>, <tt>keyObtentionIterations</tt>,
 *       <tt>saltGenerator</tt> and <tt>config</tt> properties.</li>
 *   <li>Declare a <i>typedef</i> in a Hibernate mapping giving its
 *       <tt>encryptorRegisteredName</tt> parameter the same value specified
 *       to this object in <tt>registeredName</tt>.</li>
 * </ol>
 * </p>
 * <p>
 * This in a Spring config file would look like:
 * </p>
 * <p>
 * <pre> 
 *  ...
 *  &lt;-- Optional, as the hibernateEncryptor could be directly set an     -->
 *  &lt;-- algorithm and password.                                          -->
 *  &lt;bean id="bigIntegerEncryptor"
 *    class="org.jasypt.encryption.pbe.StandardPBEBigIntegerEncryptor">
 *    &lt;property name="algorithm">
 *        &lt;value>PBEWithMD5AndDES&lt;/value>
 *    &lt;/property>
 *    &lt;property name="password">
 *        &lt;value>XXXXX&lt;/value>
 *    &lt;/property>
 *  &lt;/bean>
 *  
 *  &lt;bean id="hibernateEncryptor"
 *    class="org.jasypt.hibernate.encryptor.HibernatePBEBigIntegerEncryptor">
 *    &lt;property name="registeredName">
 *        &lt;value><b>myHibernateBigIntegerEncryptor</b>&lt;/value>
 *    &lt;/property>
 *    &lt;property name="encryptor">
 *        &lt;ref bean="bigIntegerEncryptor" />
 *    &lt;/property>
 *  &lt;/bean>
 *  ...
 * </pre>
 * </p>
 * <p>
 * And then in the Hibernate mapping file:
 * </p>
 * <p>
 * <pre>
 *    &lt;typedef name="encrypted" class="org.jasypt.hibernate.type.EncryptedBigIntegerType">
 *      &lt;param name="encryptorRegisteredName"><b>myHibernateBigIntegerEncryptor</b>&lt;/param>
 *    &lt;/typedef>
 * </pre>
 * </p>
 * <p>
 * An important thing to note is that, when using <tt>HibernatePBEBigIntegerEncryptor</tt>
 * objects this way to wrap <tt>PBEBigIntegerEncryptor</tt>s, <u>it is not
 * necessary to deal with {@link HibernatePBEEncryptorRegistry}</u>, 
 * because <tt>HibernatePBEBigIntegerEncryptor</tt> objects get automatically registered
 * in the encryptor registry when their {@link #setRegisteredName(String)}
 * method is called.
 * </p>
 * 
 * @since 1.2
 * 
 * @author Daniel Fern&aacute;ndez Garrido
 * 
 */
public final class HibernatePBEBigIntegerEncryptor {

    private String registeredName = null;
    private PBEBigIntegerEncryptor encryptor = null;
    private boolean encryptorSet = false;
    
    
    
    /**
     * Creates a new instance of <tt>HibernatePBEBigIntegerEncryptor</tt> It also
     * creates a <tt>StandardPBEBigIntegerEncryptor</tt> for internal use, which
     * can be overriden by calling <tt>setEncryptor(...)</tt>.  
     */
    public HibernatePBEBigIntegerEncryptor() {
        super();
        this.encryptor = new StandardPBEBigIntegerEncryptor();
        this.encryptorSet = false;
    }


    /*
     * For internal use only, by the Registry, when a PBEBigIntegerEncryptor
     * is registered programmatically.
     */
    HibernatePBEBigIntegerEncryptor(String registeredName, 
            PBEBigIntegerEncryptor encryptor) {
        this.encryptor = encryptor;
        this.registeredName = registeredName;
        this.encryptorSet = true;
    }


    /**
     * Returns the encryptor which this object wraps.
     * 
     * @return the encryptor.
     */
    public PBEBigIntegerEncryptor getEncryptor() {
        return this.encryptor;
    }
    
    
    /**
     * Sets the <tt>PBEBigIntegerEncryptor</tt> to be held (wrapped) by this
     * object. This method is optional and can be only called once.
     * 
     * @param encryptor the encryptor.
     */
    public void setEncryptor(PBEBigIntegerEncryptor encryptor) {
        if (this.encryptorSet) {
            throw new EncryptionInitializationException(
                    "An encryptor has been already set: no " +
                    "further configuration possible on hibernate wrapper");
        }
        this.encryptor = encryptor;
        this.encryptorSet = true;
    }


    /**
     * Sets the password to be used by the internal encryptor, if a specific
     * encryptor has not been set with <tt>setEncryptor(...)</tt>.
     * 
     * @param password the password to be set for the internal encryptor
     */
    public void setPassword(String password) {
        if (this.encryptorSet) {
            throw new EncryptionInitializationException(
                    "An encryptor has been already set: no " +
                    "further configuration possible on hibernate wrapper");
        }
        StandardPBEBigIntegerEncryptor standardPBEBigIntegerEncryptor =
            (StandardPBEBigIntegerEncryptor) this.encryptor;
        standardPBEBigIntegerEncryptor.setPassword(password);
    }


    /**
     * Sets the algorithm to be used by the internal encryptor, if a specific
     * encryptor has not been set with <tt>setEncryptor(...)</tt>.
     * 
     * @param algorithm the algorithm to be set for the internal encryptor
     */
    public void setAlgorithm(String algorithm) {
        if (this.encryptorSet) {
            throw new EncryptionInitializationException(
                    "An encryptor has been already set: no " +
                    "further configuration possible on hibernate wrapper");
        }
        StandardPBEBigIntegerEncryptor standardPBEBigIntegerEncryptor =
            (StandardPBEBigIntegerEncryptor) this.encryptor;
        standardPBEBigIntegerEncryptor.setAlgorithm(algorithm);
    }
    

    /**
     * Sets the key obtention iterations to be used by the internal encryptor, 
     * if a specific encryptor has not been set with <tt>setEncryptor(...)</tt>.
     * 
     * @param keyObtentionIterations to be set for the internal encryptor
     */
    public void setKeyObtentionIterations(int keyObtentionIterations) {
        if (this.encryptorSet) {
            throw new EncryptionInitializationException(
                    "An encryptor has been already set: no " +
                    "further configuration possible on hibernate wrapper");
        }
        StandardPBEBigIntegerEncryptor standardPBEBigIntegerEncryptor =
            (StandardPBEBigIntegerEncryptor) this.encryptor;
        standardPBEBigIntegerEncryptor.setKeyObtentionIterations(
                keyObtentionIterations);
    }
    

    /**
     * Sets the salt generator to be used by the internal encryptor, 
     * if a specific encryptor has not been set with <tt>setEncryptor(...)</tt>.
     * 
     * @param saltGenerator the salt generator to be set for the internal
     *                      encryptor.
     */
    public void setSaltGenerator(SaltGenerator saltGenerator) {
        if (this.encryptorSet) {
            throw new EncryptionInitializationException(
                    "An encryptor has been already set: no " +
                    "further configuration possible on hibernate wrapper");
        }
        StandardPBEBigIntegerEncryptor standardPBEBigIntegerEncryptor =
            (StandardPBEBigIntegerEncryptor) this.encryptor;
        standardPBEBigIntegerEncryptor.setSaltGenerator(saltGenerator);
    }


    /**
     * Sets the PBEConfig to be used by the internal encryptor, 
     * if a specific encryptor has not been set with <tt>setEncryptor(...)</tt>.
     * 
     * @param config the PBEConfig to be set for the internal encryptor
     */
    public void setConfig(PBEConfig config) {
        if (this.encryptorSet) {
            throw new EncryptionInitializationException(
                    "An encryptor has been already set: no " +
                    "further configuration possible on hibernate wrapper");
        }
        StandardPBEBigIntegerEncryptor standardPBEBigIntegerEncryptor =
            (StandardPBEBigIntegerEncryptor) this.encryptor;
        standardPBEBigIntegerEncryptor.setConfig(config);
    }


    /**
     * Encrypts a message, delegating to wrapped encryptor.
     * 
     * @param message the message to be encrypted.
     * @return the encryption result.
     */
    public BigInteger encrypt(BigInteger message) {
        if (this.encryptor == null) {
            throw new EncryptionInitializationException(
                    "Encryptor has not been set into Hibernate wrapper");
        }
        return this.encryptor.encrypt(message);
    }

    
    /**
     * Decypts a message, delegating to wrapped encryptor
     * 
     * @param encryptedMessage the message to be decrypted.
     * @return the result of decryption.
     */
    public BigInteger decrypt(BigInteger encryptedMessage) {
        if (this.encryptor == null) {
            throw new EncryptionInitializationException(
                    "Encryptor has not been set into Hibernate wrapper");
        }
        return this.encryptor.decrypt(encryptedMessage);
    }
    

    
    /**
     * Sets the registered name of the encryptor and adds it to the registry.
     * 
     * @param registeredName the name with which the encryptor will be
     *                       registered.
     */
    public void setRegisteredName(String registeredName) {
        if (this.registeredName != null) {
            // It had another name before, we have to clean
            HibernatePBEEncryptorRegistry.getInstance().
                    unregisterHibernatePBEBigIntegerEncryptor(this.registeredName);
        }
        this.registeredName = registeredName;
        HibernatePBEEncryptorRegistry.getInstance().
                registerHibernatePBEBigIntegerEncryptor(this);
    }

    /**
     * Returns the name with which the wrapped encryptor is registered at
     * the registry.
     * 
     * @return the registered name.
     */
    public String getRegisteredName() {
        return this.registeredName;
    }
    
}
