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
package org.jasypt.hibernate4.type;

import java.io.Serializable;
import java.sql.PreparedStatement;
import java.sql.ResultSet;
import java.sql.SQLException;
import java.sql.Types;
import java.util.Properties;

import org.hibernate.HibernateException;
import org.hibernate.engine.spi.SessionImplementor;
import org.hibernate.usertype.ParameterizedType;
import org.hibernate.usertype.UserType;
import org.jasypt.encryption.pbe.PBEStringEncryptor;
import org.jasypt.encryption.pbe.StandardPBEStringEncryptor;
import org.jasypt.exceptions.EncryptionInitializationException;
import org.jasypt.hibernate4.encryptor.HibernatePBEEncryptorRegistry;

/**
 *
 * Base class for <b>Hibernate</b> <tt>UserType</tt>s to store 
 * values as encrypted strings.
 * 
 * @since 1.9.0
 * @author Daniel Fern&aacute;ndez
 * @author Iv&aacute;n Garc&iacute;a S&aacute;inz-Aja
 * 
 */
public abstract class AbstractEncryptedAsStringType 
        implements UserType, ParameterizedType {

    static final int sqlType = Types.VARCHAR;
    static final int[] sqlTypes = new int[]{ sqlType };
    
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
    protected abstract Object convertToObject(final String string);
    
    /**
     * Converts given Object to its String form.
     * @param object the object value
     * @return the string form of the passes Object
     */
    protected String convertToString(final Object object) {
        return object == null? null : object.toString();
    }
    
    public final int[] sqlTypes() {
        return (int[]) sqlTypes.clone();
    }

    
    public abstract Class returnedClass();

    
    public final boolean equals(final Object x, final Object y) 
            throws HibernateException {
        return x == y || ( x != null && y != null && x.equals( y ) );
    }
    
    
    public final Object deepCopy(final Object value)
            throws HibernateException {
        return value;
    }
    
    
    public final Object assemble(final Serializable cached, final Object owner)
            throws HibernateException {
        if (cached == null) {
            return null;
        }
        return deepCopy(cached);
    }

    
    public final Serializable disassemble(final Object value) 
            throws HibernateException {
        if (value == null) {
            return null;
        }
        return (Serializable) deepCopy(value);
    }

    
    public final boolean isMutable() {
        return false;
    }


    public final int hashCode(final Object x)
            throws HibernateException {
        return x.hashCode();
    }

    
    public final Object replace(final Object original, final Object target, final Object owner) 
            throws HibernateException {
        return original;
    }

    
    public Object nullSafeGet(final ResultSet rs, final String[] names,
            final SessionImplementor session, final Object owner)
            throws HibernateException, SQLException {
        
        checkInitialization();
        final String message = rs.getString(names[0]);
        return rs.wasNull() ? null : convertToObject(this.encryptor.decrypt(message));
        
    }

    
    public void nullSafeSet(final PreparedStatement st, final Object value, final int index,
            final SessionImplementor session) throws HibernateException, SQLException {

        checkInitialization();
        if (value == null) {
            st.setNull(index, sqlType);
        } else {
            st.setString(index, this.encryptor.encrypt(convertToString(value)));
        }
        
    }

    
    public synchronized void setParameterValues(final Properties parameters) {
        
        final String paramEncryptorName =
            parameters.getProperty(ParameterNaming.ENCRYPTOR_NAME);
        final String paramAlgorithm =
            parameters.getProperty(ParameterNaming.ALGORITHM);
        final String paramProviderName =
            parameters.getProperty(ParameterNaming.PROVIDER_NAME);
        final String paramPassword =
            parameters.getProperty(ParameterNaming.PASSWORD);
        final String paramKeyObtentionIterations =
            parameters.getProperty(ParameterNaming.KEY_OBTENTION_ITERATIONS);
        final String paramStringOutputType =
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

    
    
    protected synchronized final void checkInitialization() {
        
        if (!this.initialized) {
            
            if (this.useEncryptorName) {

                final HibernatePBEEncryptorRegistry registry = 
                    HibernatePBEEncryptorRegistry.getInstance();
                final PBEStringEncryptor pbeEncryptor = 
                    registry.getPBEStringEncryptor(this.encryptorName);
                if (pbeEncryptor == null) {
                    throw new EncryptionInitializationException(
                            "No string encryptor registered for hibernate " +
                            "with name \"" + this.encryptorName + "\"");
                }
                this.encryptor = pbeEncryptor;
                
            } else {
                
                final StandardPBEStringEncryptor newEncryptor = 
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
