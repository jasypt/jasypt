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
package org.jasypt.hibernate.type;

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
import org.jasypt.hibernate.encryptor.HibernatePBEEncryptorRegistry;

/**
 *
 * Base class for <b>Hibernate 3</b> <tt>UserType</tt>s to store 
 * values as encrypted strings.
 * 
 * @since 1.2
 * @author Daniel Fern&aacute;ndez Garrido
 * @author Iv&aacute;n Garc&iacute;a S&aacute;inz-Aja
 * 
 */
public abstract class AbstractEncryptedAsStringType 
        implements UserType, ParameterizedType {

    protected static NullableType nullableType = Hibernate.STRING;
    protected static int sqlType = nullableType.sqlType();
    protected static int[] sqlTypes = new int[]{ sqlType };
    
    private boolean initialized = false;
    private boolean useEncryptorName = false;
    
    private String encryptorName = null;
    private String algorithm = null;
    private String providerName = null;
    private String password = null;
    private Integer keyObtentionIterations = null;
    private String stringOutputType = null;
    
    protected PBEStringEncryptor encryptor = null;

    /**
     * Converts given String to its Object form.
     * @param string the string value
     * @return the object form of the passed String
     */
    protected abstract Object convertToObject(String string);
    
    /**
     * Converts given Object to its String form.
     * @param object the object value
     * @return the string form of the passes Object
     */
    protected String convertToString(Object object) {
        return object == null? null : object.toString();
    }
    
    public int[] sqlTypes() {
        return sqlTypes;
    }

    
    public abstract Class returnedClass();

    
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
        }
        return deepCopy(cached);
    }

    
    public Serializable disassemble(Object value) 
            throws HibernateException {
        if (value == null) {
            return null;
        }
        return (Serializable) deepCopy(value);
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
        return rs.wasNull() ? null : convertToObject(this.encryptor.decrypt(message));
    }

    
    public void nullSafeSet(PreparedStatement st, Object value, int index)
            throws HibernateException, SQLException {
        checkInitialization();
        if (value == null) {
            st.setNull(index, sqlType);
        } else {
            st.setString(index, this.encryptor.encrypt(convertToString(value)));
        }
    }

    
    public synchronized void setParameterValues(Properties parameters) {
        
        String paramEncryptorName =
            parameters.getProperty(ParameterNaming.ENCRYPTOR_NAME);
        String paramAlgorithm =
            parameters.getProperty(ParameterNaming.ALGORITHM);
        String paramProviderName =
            parameters.getProperty(ParameterNaming.PROVIDER_NAME);
        String paramPassword =
            parameters.getProperty(ParameterNaming.PASSWORD);
        String paramKeyObtentionIterations =
            parameters.getProperty(ParameterNaming.KEY_OBTENTION_ITERATIONS);
        String paramStringOutputType =
            parameters.getProperty(ParameterNaming.STRING_OUTPUT_TYPE);
        
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
            
            if (paramProviderName != null) {
                this.providerName = paramProviderName;
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
            
            if (paramStringOutputType != null) {
                this.stringOutputType = paramStringOutputType;
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

    
    
    protected synchronized void checkInitialization() {
        
        if (!this.initialized) {
            
            if (this.useEncryptorName) {

                HibernatePBEEncryptorRegistry registry = 
                    HibernatePBEEncryptorRegistry.getInstance();
                PBEStringEncryptor pbeEncryptor = 
                    registry.getPBEStringEncryptor(this.encryptorName);
                if (pbeEncryptor == null) {
                    throw new EncryptionInitializationException(
                            "No string encryptor registered for hibernate " +
                            "with name \"" + this.encryptorName + "\"");
                }
                this.encryptor = pbeEncryptor;
                
            } else {
                
                StandardPBEStringEncryptor newEncryptor = 
                    new StandardPBEStringEncryptor();
                
                newEncryptor.setPassword(this.password);
                
                if (this.algorithm != null) {
                    newEncryptor.setAlgorithm(this.algorithm);
                }
                
                if (this.providerName != null) {
                    newEncryptor.setProviderName(this.providerName);
                }
                
                if (this.keyObtentionIterations != null) {
                    newEncryptor.setKeyObtentionIterations(
                            this.keyObtentionIterations.intValue());
                }
                
                if (this.stringOutputType != null) {
                    newEncryptor.setStringOutputType(this.stringOutputType);
                }
                
                newEncryptor.initialize();
                
                this.encryptor = newEncryptor;
                
            }
            
            this.initialized = true;
        }
        
    }
    
    
}
