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

import java.io.Serializable;
import java.sql.PreparedStatement;
import java.sql.ResultSet;
import java.sql.SQLException;
import java.util.Properties;

import org.hibernate.Hibernate;
import org.hibernate.HibernateException;
import org.hibernate.type.NullableType;
import org.hibernate.usertype.ParameterizedType;
import org.hibernate.usertype.UserType;
import org.hibernate.util.EqualsHelper;
import org.jasypt.encryption.pbe.PBEStringEncryptor;
import org.jasypt.encryption.pbe.StandardPBEStringEncryptor;
import org.jasypt.exceptions.EncryptionInitializationException;

/**
 * <p>
 * A <b>Hibernate 3</b> <tt>UserType</tt> implementation which allows transparent 
 * encryption of text values during persistence of entities.
 * </p>
 * <p>
 * <i>This class is intended only for declarative use from a Hibernate mapping
 * file. Do not use it directly from your <tt>.java</tt> files.</i>
 * </p>
 * <p>
 * To use this Hibernate type in one of your Hibernate mappings, you can
 * add it like this:
 * </p>
 * <p>
 * <pre>
 *  &lt;hibernate-mapping package="myapp">
 *    ...
 *    &lt;typedef name="<b>encrypted</b>" class="org.jasypt.hibernate.EncryptedTextType">
 *      &lt;param name="encryptorRegisteredName"><b><i>strongHibernateEncryptor</i></b>&lt;/param>
 *    &lt;/typedef>
 *    ...
 *    &lt;class name="UserData" table="USER_DATA">
 *      ...
 *      &lt;property name="address" column="ADDRESS" type="<b>encrypted</b>" />
 *      ...
 *    &lt;class>
 *    ...
 *  &lt;hibernate-mapping>
 * </pre>
 * </p>
 * <p>
 * ...where an encryptor should have been previously registered to be used
 * from Hibernate with name <tt>strongHibernateEncryptor</tt> (see
 * {@link HibernatePBEEncryptor} and {@link HibernatePBEEncryptorRegistry}). 
 * </p>
 * <p>
 * Or, if you prefer to avoid registration of encryptors, you can configure
 * your encryptor directly in the mapping file (although not recommended), 
 * like this:
 * </p>
 * <p>
 * <pre>
 *  &lt;hibernate-mapping package="myapp">
 *    ...
 *    &lt;typedef name="<b>encrypted</b>" class="org.jasypt.hibernate.EncryptedTextType">
 *      &lt;param name="algorithm"><b><i>PBEWithMD5AndTripleDES</i></b>&lt;/param>
 *      &lt;param name="password"><b><i>jasypt</i></b>&lt;/param>
 *      &lt;param name="keyObtentionIterations"><b><i>1000</i></b>&lt;/param>
 *    &lt;/typedef>
 *    ...
 *    &lt;class name="UserData" table="USER_DATA">
 *      ...
 *      &lt;property name="address" column="ADDRESS" type="<b>encrypted</b>" />
 *      ...
 *    &lt;class>
 *    ...
 *  &lt;hibernate-mapping>
 * </pre>
 * </p>
 * <p>
 * To learn more about usage of user-defined types, please refer to the
 * <a href="http://www.hibernate.org" target="_blank">Hibernate Reference
 * Documentation</a>.
 * </p>
 * 
 * 
 * @since 1.0
 * @deprecated Replaced by {@link org.jasypt.hibernate.type.EncryptedStringType}
 *             and will be removed in version 1.3. 
 * 
 * @author Daniel Fern&aacute;ndez Garrido 
 * 
 */
public final class EncryptedTextType implements UserType, ParameterizedType {

    private static NullableType nullableType = Hibernate.STRING;
    private static int sqlType = nullableType.sqlType();
    private static int[] sqlTypes = new int[]{ sqlType };
    
    private boolean initialized = false;
    private boolean useEncryptorName = false;
    
    private String encryptorName = null;
    private String algorithm = null;
    private String password = null;
    private Integer keyObtentionIterations = null;
    
    private PBEStringEncryptor encryptor = null;

    
    public int[] sqlTypes() {
        return sqlTypes;
    }

    
    public Class returnedClass() {
        return String.class;
    }

    
    public boolean equals(Object x, Object y) 
            throws HibernateException {
        return EqualsHelper.equals(x, y);
    }
    
    
    public Object deepCopy(Object value)
            throws HibernateException {
        return value;
    }
    
    
    public Object assemble(Serializable cached, Object owner)
            throws HibernateException {
        if (cached == null) {
            return null;
        } else {
            return deepCopy(cached);
        }
    }

    
    public Serializable disassemble(Object value) 
            throws HibernateException {
        if (value == null) {
            return null;
        } else {
            return (Serializable) deepCopy(value);
        }
    }

    
    public boolean isMutable() {
        return false;
    }


    public int hashCode(Object x)
            throws HibernateException {
        return x.hashCode();
    }

    
    public Object replace(Object original, Object target, Object owner) 
            throws HibernateException {
        return original;
    }

    
    public Object nullSafeGet(ResultSet rs, String[] names, Object owner)
            throws HibernateException, SQLException {
        checkInitialization();
        String message = rs.getString(names[0]);
        return rs.wasNull() ? null : this.encryptor.decrypt(message);
    }

    
    public void nullSafeSet(PreparedStatement st, Object value, int index)
            throws HibernateException, SQLException {
        checkInitialization();
        if (value == null) {
            st.setNull(index, sqlType);
        } else {
            st.setString(index, this.encryptor.encrypt((String) value));
        }
    }

    
    public synchronized void setParameterValues(Properties parameters) {
        
        String paramEncryptorName =
            parameters.getProperty(ParameterNaming.ENCRYPTOR_NAME);
        String paramAlgorithm =
            parameters.getProperty(ParameterNaming.ALGORITHM);
        String paramPassword =
            parameters.getProperty(ParameterNaming.PASSWORD);
        String paramKeyObtentionIterations =
            parameters.getProperty(ParameterNaming.KEY_OBTENTION_ITERATIONS);
        
        this.useEncryptorName = false;
        if (paramEncryptorName != null) {
            
            if ((paramAlgorithm != null) ||
                (paramPassword != null) ||
                (paramKeyObtentionIterations != null)) {
                
                throw new EncryptionInitializationException(
                        "If \"" + ParameterNaming.ENCRYPTOR_NAME + 
                        "\" is specified, none of \"" +
                        ParameterNaming.ALGORITHM + "\", \"" +
                        ParameterNaming.PASSWORD + "\" or \"" + 
                        ParameterNaming.KEY_OBTENTION_ITERATIONS + "\" " +
                        "can be specified");
                
            }
            this.encryptorName = paramEncryptorName;
            this.useEncryptorName = true;
            
        } else if ((paramPassword != null)) {

            this.password = paramPassword;
            
            if (paramAlgorithm != null) {
                this.algorithm = paramAlgorithm;
            }
            
            if (paramKeyObtentionIterations != null) {

                try {
                    this.keyObtentionIterations = 
                        new Integer(
                                Integer.parseInt(paramKeyObtentionIterations));
                } catch (NumberFormatException e) {
                    throw new EncryptionInitializationException(
                            "Value specified for \"" + 
                            ParameterNaming.KEY_OBTENTION_ITERATIONS + 
                            "\" is not a valid integer");
                }
                
            }
            
        } else {
            
            throw new EncryptionInitializationException(
                    "If \"" + ParameterNaming.ENCRYPTOR_NAME + 
                    "\" is not specified, then \"" +
                    ParameterNaming.PASSWORD + "\" (and optionally \"" +
                    ParameterNaming.ALGORITHM + "\" and \"" + 
                    ParameterNaming.KEY_OBTENTION_ITERATIONS + "\") " +
                    "must be specified");
            
        }
    }

    
    
    private synchronized void checkInitialization() {
        
        if (!this.initialized) {
            
            if (this.useEncryptorName) {

                HibernatePBEEncryptorRegistry registry = 
                    HibernatePBEEncryptorRegistry.getInstance();
                HibernatePBEEncryptor hibernateEncryptor = 
                    registry.getHibernatePBEEncryptor(encryptorName);
                if (hibernateEncryptor == null) {
                    throw new EncryptionInitializationException(
                            "No encryptor registered for hibernate with " +
                            "name \"" + encryptorName + "\"");
                }
                this.encryptor = hibernateEncryptor.getEncryptor();
                
            } else {
                
                StandardPBEStringEncryptor newEncryptor = 
                    new StandardPBEStringEncryptor();
                
                newEncryptor.setPassword(this.password);
                
                if (this.algorithm != null) {
                    newEncryptor.setAlgorithm(this.algorithm);
                }
                
                if (this.keyObtentionIterations != null) {
                    newEncryptor.setKeyObtentionIterations(
                            this.keyObtentionIterations.intValue());
                }
                
                newEncryptor.initialize();
                
                this.encryptor = newEncryptor;
                
            }
            
            this.initialized = true;
        }
        
    }
    
    
}
