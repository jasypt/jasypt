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

import java.util.HashMap;

import org.jasypt.encryption.pbe.PBEStringEncryptor;

/**
 * <p>
 * Registry for all the <tt>PBEStringEncryptor</tt> which are eligible for
 * use from Hibernate.
 * </p>
 * <p>
 * This class is intended to be directly used in applications where
 * an IoC container (like Spring Framework) is not present. If it is, 
 * it is better to do with {@link HibernatePBEEncryptor} instead.
 * </p>
 * <p>
 * This <i>registry</i> is a <b>singleton</b> which maintains a registry
 * of <tt>PBEStringEncryptor</tt> objects which can be used from Hibernate,
 * by using its <tt>registeredName</tt> to reference them from mappings.
 * </p>
 * <p>
 * The steps would be:
 * <ol>
 *   <li>Obtain the registry instance ({@link #getInstance()}).</li>
 *   <li>Register the encryptor, giving it a <i>registered name</i> 
 *       ({@link #registerPBEEncryptor(String, PBEStringEncryptor)}).</li>
 *   <li>Declare a <i>typedef</i> in a Hibernate mapping giving its
 *       <tt>encryptorRegisteredName</tt> parameter the same value specified
 *       when registering the encryptor.</li>
 * </ol>
 * </p>
 * <p>
 * This is, first register the encryptor:
 * </p>
 * <p>
 * <pre>
 *  StandardPBEStringEncryptor strongEncryptor = new StandardPBEStringEncryptor();
 *  ...
 *  HibernatePBEEncryptorRegistry registry =
 *      HibernatePBEEncryptorRegistry.getInstance();
 *  registry.registerPBEEncryptor("<b>strongHibernateEncryptor</b>", strongEncryptor);
 * </pre>
 * </p>
 * <p>
 * And then, reference it from a Hibernate mapping file:
 * </p>
 * <p>
 * <pre>
 *    &lt;typedef name="encrypted" class="org.jasypt.hibernate.EncryptedTextType">
 *      &lt;param name="encryptorRegisteredName"><b>strongHibernateEncryptor</b>&lt;/param>
 *    &lt;/typedef>
 * </pre>
 * </p>
 *
 * 
 * @since 1.0
 * 
 * @author Daniel Fern&aacute;ndez Garrido
 * 
 */
public class HibernatePBEEncryptorRegistry {

    
    // The singleton instance
    private static HibernatePBEEncryptorRegistry instance = 
        new HibernatePBEEncryptorRegistry();
    
    
    // Registry map
    private HashMap configs = new HashMap();
    
    
    /**
     * Returns the singleton instance of the registry.
     * 
     * @return the registry.
     */
    public static HibernatePBEEncryptorRegistry getInstance() {
        return instance;
    }
    
    // The registry cannot be externally instantiated.
    private HibernatePBEEncryptorRegistry() { }
 

    /**
     * Registers a <tt>PBEStringEncryptor</tt> object with the specified
     * name.
     * 
     * @param registeredName the registered name.
     * @param encryptor the encryptor to be registered.
     */
    public synchronized void registerPBEEncryptor(
            String registeredName, PBEStringEncryptor encryptor) {
        HibernatePBEEncryptor hibernateEncryptor = 
            new HibernatePBEEncryptor(registeredName, encryptor);
        this.configs.put(registeredName, hibernateEncryptor);
    }

    
    // Not public: this is used from HibernatePBEEncryptor.setRegisteredName.
    synchronized void registerHibernatePBEEncryptor(
            HibernatePBEEncryptor hibernateEncryptor) {
        this.configs.put(
                hibernateEncryptor.getRegisteredName(), 
                hibernateEncryptor);
    }

    
    // Not public: this is used from HibernatePBEEncryptor.setRegisteredName.
    synchronized void unregisterHibernatePBEEncryptor(String name) {
        this.configs.remove(name);
    }

    
    /**
     * Returns the <tt>PBEStringEncryptor</tt> registered with the specified
     * name (if exists).
     * 
     * @param name the name of the desired encryptor.
     * @return the encryptor, or null if no encryptor has been registered with
     *         that name.
     */
    public synchronized HibernatePBEEncryptor getHibernatePBEEncryptor(
            String name) {
        return (HibernatePBEEncryptor) configs.get(name);
    }
    
}
