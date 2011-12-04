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
 * @author Daniel Fern&aacute;ndez
 * 
 */
public final class HibernatePBEEncryptorRegistry {

    
    // The singleton instance
    private static final HibernatePBEEncryptorRegistry instance = 
        new HibernatePBEEncryptorRegistry();
    
    
    // Registry maps
    private final HashMap stringEncryptors = new HashMap();
    private final HashMap bigIntegerEncryptors = new HashMap();
    private final HashMap bigDecimalEncryptors = new HashMap();
    private final HashMap byteEncryptors = new HashMap();
    
    
    /**
     * Returns the singleton instance of the registry.
     * 
     * @return the registry.
     */
    public static HibernatePBEEncryptorRegistry getInstance() {
        return instance;
    }
    
    // The registry cannot be externally instantiated.
    private HibernatePBEEncryptorRegistry() { 
        super();
    }
 

    /**
     * Registers a <tt>PBEStringEncryptor</tt> object with the specified
     * name.
     * 
     * @param registeredName the registered name.
     * @param encryptor the encryptor to be registered.
     */
    public synchronized void registerPBEStringEncryptor(
            final String registeredName, final PBEStringEncryptor encryptor) {
        final HibernatePBEStringEncryptor hibernateEncryptor = 
            new HibernatePBEStringEncryptor(registeredName, encryptor);
        this.stringEncryptors.put(registeredName, hibernateEncryptor);
    }


    
    // Not public: this is used from 
    // HibernatePBEStringEncryptor.setRegisteredName.
    synchronized void registerHibernatePBEStringEncryptor(
            final HibernatePBEStringEncryptor hibernateEncryptor) {
        this.stringEncryptors.put(
                hibernateEncryptor.getRegisteredName(), 
                hibernateEncryptor);
    }

    
    // Not public: this is used from 
    // HibernatePBEStringEncryptor.setRegisteredName.
    synchronized void unregisterHibernatePBEStringEncryptor(final String name) {
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
            final String registeredName) {
        final HibernatePBEStringEncryptor hibernateEncryptor = 
            (HibernatePBEStringEncryptor) this.stringEncryptors.get(registeredName);
        if (hibernateEncryptor == null) {
            return null;
        }
        return hibernateEncryptor.getEncryptor();
    }

    


    /**
     * Registers a <tt>PBEBigIntegerEncryptor</tt> object with the specified
     * name.
     * 
     * @since 1.6
     * 
     * @param registeredName the registered name.
     * @param encryptor the encryptor to be registered.
     */
    public synchronized void registerPBEBigIntegerEncryptor(
            final String registeredName, final PBEBigIntegerEncryptor encryptor) {
        final HibernatePBEBigIntegerEncryptor hibernateEncryptor = 
            new HibernatePBEBigIntegerEncryptor(registeredName, encryptor);
        this.bigIntegerEncryptors.put(registeredName, hibernateEncryptor);
    }


    
    // Not public: this is used from 
    // HibernatePBEBigIntegerEncryptor.setRegisteredName.
    synchronized void registerHibernatePBEBigIntegerEncryptor(
            final HibernatePBEBigIntegerEncryptor hibernateEncryptor) {
        this.bigIntegerEncryptors.put(
                hibernateEncryptor.getRegisteredName(), 
                hibernateEncryptor);
    }

    
    // Not public: this is used from 
    // HibernatePBEBigIntegerEncryptor.setRegisteredName.
    synchronized void unregisterHibernatePBEBigIntegerEncryptor(final String name) {
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
            final String registeredName) {
        final HibernatePBEBigIntegerEncryptor hibernateEncryptor = 
            (HibernatePBEBigIntegerEncryptor) this.bigIntegerEncryptors.get(registeredName);
        if (hibernateEncryptor == null) {
            return null;
        }
        return hibernateEncryptor.getEncryptor();
    }



    /**
     * Registers a <tt>PBEBigDecimalEncryptor</tt> object with the specified
     * name.
     * 
     * @since 1.6
     * 
     * @param registeredName the registered name.
     * @param encryptor the encryptor to be registered.
     */
    public synchronized void registerPBEBigDecimalEncryptor(
            final String registeredName, final PBEBigDecimalEncryptor encryptor) {
        final HibernatePBEBigDecimalEncryptor hibernateEncryptor = 
            new HibernatePBEBigDecimalEncryptor(registeredName, encryptor);
        this.bigDecimalEncryptors.put(registeredName, hibernateEncryptor);
    }


    
    // Not public: this is used from 
    // HibernatePBEBigDecimalEncryptor.setRegisteredName.
    synchronized void registerHibernatePBEBigDecimalEncryptor(
            final HibernatePBEBigDecimalEncryptor hibernateEncryptor) {
        this.bigDecimalEncryptors.put(
                hibernateEncryptor.getRegisteredName(), 
                hibernateEncryptor);
    }

    
    // Not public: this is used from 
    // HibernatePBEBigDecimalEncryptor.setRegisteredName.
    synchronized void unregisterHibernatePBEBigDecimalEncryptor(final String name) {
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
            final String registeredName) {
        final HibernatePBEBigDecimalEncryptor hibernateEncryptor = 
            (HibernatePBEBigDecimalEncryptor) this.bigDecimalEncryptors.get(registeredName);
        if (hibernateEncryptor == null) {
            return null;
        }
        return hibernateEncryptor.getEncryptor();
    }

    



    /**
     * Registers a <tt>PBEByteEncryptor</tt> object with the specified
     * name.
     * 
     * @since 1.6
     * 
     * @param registeredName the registered name.
     * @param encryptor the encryptor to be registered.
     */
    public synchronized void registerPBEByteEncryptor(
            final String registeredName, final PBEByteEncryptor encryptor) {
        final HibernatePBEByteEncryptor hibernateEncryptor = 
            new HibernatePBEByteEncryptor(registeredName, encryptor);
        this.byteEncryptors.put(registeredName, hibernateEncryptor);
    }

    


    
    // Not public: this is used from 
    // HibernatePBEByteEncryptor.setRegisteredName.
    synchronized void registerHibernatePBEByteEncryptor(
            final HibernatePBEByteEncryptor hibernateEncryptor) {
        this.byteEncryptors.put(
                hibernateEncryptor.getRegisteredName(), 
                hibernateEncryptor);
    }

    
    // Not public: this is used from 
    // HibernatePBEByteEncryptor.setRegisteredName.
    synchronized void unregisterHibernatePBEByteEncryptor(final String name) {
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
            final String registeredName) {
        final HibernatePBEByteEncryptor hibernateEncryptor = 
            (HibernatePBEByteEncryptor) this.byteEncryptors.get(registeredName);
        if (hibernateEncryptor == null) {
            return null;
        }
        return hibernateEncryptor.getEncryptor();
    }
    
}
