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

import java.util.HashMap;

import org.jasypt.encryption.pbe.PBEBigDecimalEncryptor;
import org.jasypt.encryption.pbe.PBEBigIntegerEncryptor;
import org.jasypt.encryption.pbe.PBEByteEncryptor;
import org.jasypt.encryption.pbe.PBEStringEncryptor;

/**
 * <p>
 * Registry for all the <tt>PBE*Encryptor</tt> which are eligible for
 * use from Hibernate.
 * </p>
 * <p>
 * This class is intended to be directly used in applications where
 * an IoC container (like Spring Framework) is not present. If it is, 
 * it is better to use the <tt>HibernatePBE*Encryptor</tt> classes
 * directly, instead.
 * </p>
 * <p>
 * This <i>registry</i> is a <b>singleton</b> which maintains a registry
 * of <tt>PBE*Encryptor</tt> objects which can be used from Hibernate,
 * by using its <tt>registeredName</tt> to reference them from mappings.
 * </p>
 * <p>
 * The steps would be:
 * <ol>
 *   <li>Obtain the registry instance ({@link #getInstance()}).</li>
 *   <li>Register the encryptor, giving it a <i>registered name</i> 
 *       (<tt>registerPBE*Encryptor(String, PBE*Encryptor</tt>).</li>
 *   <li>Declare a <i>typedef</i> in a Hibernate mapping giving its
 *       <tt>encryptorRegisteredName</tt> parameter the same value specified
 *       when registering the encryptor.</li>
 * </ol>
 * </p>
 * <p>
 * This is, first register the encryptor (example with a String encryptor):
 * </p>
 * <p>
 * <pre>
 *  StandardPBEStringEncryptor myEncryptor = new StandardPBEStringEncryptor();
 *  ...
 *  HibernatePBEEncryptorRegistry registry =
 *      HibernatePBEEncryptorRegistry.getInstance();
 *  registry.registerPBEStringEncryptor("<b>myHibernateEncryptor</b>", myEncryptor);
 * </pre>
 * </p>
 * <p>
 * And then, reference it from a Hibernate mapping file:
 * </p>
 * <p>
 * <pre>
 *    &lt;typedef name="encryptedString" class="org.jasypt.hibernate.type.EncryptedStringType">
 *      &lt;param name="encryptorRegisteredName"><b>myHibernateEncryptor</b>&lt;/param>
 *    &lt;/typedef>
 * </pre>
 * </p>
 *
 * 
 * @since 1.2 (class existed as 
 *            org.jasypt.hibernate.HibernatePBEEncryptorRegistry since 1.0)
 * 
 * @author Daniel Fern&aacute;ndez Garrido
 * 
 */
public final class HibernatePBEEncryptorRegistry {

    
    // The singleton instance
    private static HibernatePBEEncryptorRegistry instance = 
        new HibernatePBEEncryptorRegistry();
    
    
    // Registry maps
    private HashMap stringEncryptors = new HashMap();
    private HashMap bigIntegerEncryptors = new HashMap();
    private HashMap bigDecimalEncryptors = new HashMap();
    private HashMap byteEncryptors = new HashMap();
    
    
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
    public synchronized void registerPBEStringEncryptor(
            String registeredName, PBEStringEncryptor encryptor) {
        HibernatePBEStringEncryptor hibernateEncryptor = 
            new HibernatePBEStringEncryptor(registeredName, encryptor);
        this.stringEncryptors.put(registeredName, hibernateEncryptor);
    }


    
    // Not public: this is used from 
    // HibernatePBEStringEncryptor.setRegisteredName.
    synchronized void registerHibernatePBEStringEncryptor(
            HibernatePBEStringEncryptor hibernateEncryptor) {
        this.stringEncryptors.put(
                hibernateEncryptor.getRegisteredName(), 
                hibernateEncryptor);
    }

    
    // Not public: this is used from 
    // HibernatePBEStringEncryptor.setRegisteredName.
    synchronized void unregisterHibernatePBEStringEncryptor(String name) {
        this.stringEncryptors.remove(name);
    }

    
    /**
     * Returns the <tt>PBEStringEncryptor</tt> registered with the specified
     * name (if exists).
     * 
     * @param registeredName the name with which the desired encryptor was 
     *        registered.
     * @return the encryptor, or null if no encryptor has been registered with
     *         that name.
     */
    public synchronized PBEStringEncryptor getPBEStringEncryptor(
            String registeredName) {
        HibernatePBEStringEncryptor hibernateEncryptor = 
            (HibernatePBEStringEncryptor) stringEncryptors.get(registeredName);
        if (hibernateEncryptor == null) {
            return null;
        }
        return hibernateEncryptor.getEncryptor();
    }

    


    
    // Not public: this is used from 
    // HibernatePBEBigIntegerEncryptor.setRegisteredName.
    synchronized void registerHibernatePBEBigIntegerEncryptor(
            HibernatePBEBigIntegerEncryptor hibernateEncryptor) {
        this.bigIntegerEncryptors.put(
                hibernateEncryptor.getRegisteredName(), 
                hibernateEncryptor);
    }

    
    // Not public: this is used from 
    // HibernatePBEBigIntegerEncryptor.setRegisteredName.
    synchronized void unregisterHibernatePBEBigIntegerEncryptor(String name) {
        this.bigIntegerEncryptors.remove(name);
    }

    
    /**
     * Returns the <tt>PBEBigIntegerEncryptor</tt> registered with the specified
     * name (if exists).
     * 
     * @param registeredName the name with which the desired encryptor was 
     *        registered.
     * @return the encryptor, or null if no encryptor has been registered with
     *         that name.
     */
    public synchronized PBEBigIntegerEncryptor getPBEBigIntegerEncryptor(
            String registeredName) {
        HibernatePBEBigIntegerEncryptor hibernateEncryptor = 
            (HibernatePBEBigIntegerEncryptor) bigIntegerEncryptors.get(registeredName);
        if (hibernateEncryptor == null) {
            return null;
        }
        return hibernateEncryptor.getEncryptor();
    }

    

    


    
    // Not public: this is used from 
    // HibernatePBEBigDecimalEncryptor.setRegisteredName.
    synchronized void registerHibernatePBEBigDecimalEncryptor(
            HibernatePBEBigDecimalEncryptor hibernateEncryptor) {
        this.bigDecimalEncryptors.put(
                hibernateEncryptor.getRegisteredName(), 
                hibernateEncryptor);
    }

    
    // Not public: this is used from 
    // HibernatePBEBigDecimalEncryptor.setRegisteredName.
    synchronized void unregisterHibernatePBEBigDecimalEncryptor(String name) {
        this.bigDecimalEncryptors.remove(name);
    }

    
    /**
     * Returns the <tt>PBEBigDecimalEncryptor</tt> registered with the specified
     * name (if exists).
     * 
     * @param registeredName the name with which the desired encryptor was 
     *        registered.
     * @return the encryptor, or null if no encryptor has been registered with
     *         that name.
     */
    public synchronized PBEBigDecimalEncryptor getPBEBigDecimalEncryptor(
            String registeredName) {
        HibernatePBEBigDecimalEncryptor hibernateEncryptor = 
            (HibernatePBEBigDecimalEncryptor) bigDecimalEncryptors.get(registeredName);
        if (hibernateEncryptor == null) {
            return null;
        }
        return hibernateEncryptor.getEncryptor();
    }

    

    


    
    // Not public: this is used from 
    // HibernatePBEByteEncryptor.setRegisteredName.
    synchronized void registerHibernatePBEByteEncryptor(
            HibernatePBEByteEncryptor hibernateEncryptor) {
        this.byteEncryptors.put(
                hibernateEncryptor.getRegisteredName(), 
                hibernateEncryptor);
    }

    
    // Not public: this is used from 
    // HibernatePBEByteEncryptor.setRegisteredName.
    synchronized void unregisterHibernatePBEByteEncryptor(String name) {
        this.byteEncryptors.remove(name);
    }

    
    /**
     * Returns the <tt>PBEByteEncryptor</tt> registered with the specified
     * name (if exists).
     * 
     * @param registeredName the name with which the desired encryptor was 
     *        registered.
     * @return the encryptor, or null if no encryptor has been registered with
     *         that name.
     */
    public synchronized PBEByteEncryptor getPBEByteEncryptor(
            String registeredName) {
        HibernatePBEByteEncryptor hibernateEncryptor = 
            (HibernatePBEByteEncryptor) byteEncryptors.get(registeredName);
        if (hibernateEncryptor == null) {
            return null;
        }
        return hibernateEncryptor.getEncryptor();
    }
    
}
