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

import java.io.ByteArrayInputStream;
import java.io.ByteArrayOutputStream;
import java.io.IOException;
import java.io.InputStream;
import java.io.Serializable;
import java.sql.PreparedStatement;
import java.sql.ResultSet;
import java.sql.SQLException;
import java.util.Properties;

import org.hibernate.Hibernate;
import org.hibernate.HibernateException;
import org.hibernate.cfg.Environment;
import org.hibernate.type.NullableType;
import org.hibernate.usertype.ParameterizedType;
import org.hibernate.usertype.UserType;
import org.jasypt.encryption.pbe.PBEByteEncryptor;
import org.jasypt.encryption.pbe.StandardPBEByteEncryptor;
import org.jasypt.exceptions.EncryptionInitializationException;
import org.jasypt.hibernate.ParameterNaming;
import org.jasypt.hibernate.encryptor.HibernatePBEByteEncryptor;
import org.jasypt.hibernate.encryptor.HibernatePBEEncryptorRegistry;

/**
 * <p>
 * A <b>Hibernate 3</b> <tt>UserType</tt> implementation which allows transparent 
 * encryption of byte[] values during persistence of entities.
 * </p>
 * <p>
 * <i>This class is intended only for declarative use from a Hibernate mapping
 * file. Do not use it directly from your <tt>.java</tt> files (although
 * of course you can use it when mapping entities using annotations).</i>
 * </p>
 * <p>
 * To use this Hibernate type in one of your Hibernate mappings, you can
 * add it like this:
 * </p>
 * <p>
 * <pre>
 *  &lt;hibernate-mapping package="myapp">
 *    ...
 *    &lt;typedef name="<b>encryptedBinary</b>" class="org.jasypt.hibernate.type.EncryptedBinaryType">
 *      &lt;param name="encryptorRegisteredName"><b><i>myHibernateByteEncryptor</i></b>&lt;/param>
 *    &lt;/typedef>
 *    ...
 *    &lt;class name="UserData" table="USER_DATA">
 *      ...
 *      &lt;property name="resume" column="RESUME" type="<b>encryptedBinary</b>" />
 *      ...
 *    &lt;class>
 *    ...
 *  &lt;hibernate-mapping>
 * </pre>
 * </p>
 * <p>
 * ...where a <tt>HibernatePBEByteEncryptor</tt> object
 * should have been previously registered to be used
 * from Hibernate with name <tt>myHibernateByteEncryptor</tt> (see
 * {@link HibernatePBEByteEncryptor} and {@link HibernatePBEEncryptorRegistry}). 
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
 *    &lt;typedef name="<b>encryptedBinary</b>" class="org.jasypt.hibernate.type.EncryptedBinaryType">
 *      &lt;param name="algorithm"><b><i>PBEWithMD5AndTripleDES</i></b>&lt;/param>
 *      &lt;param name="password"><b><i>XXXXX</i></b>&lt;/param>
 *      &lt;param name="keyObtentionIterations"><b><i>1000</i></b>&lt;/param>
 *    &lt;/typedef>
 *    ...
 *    &lt;class name="UserData" table="USER_DATA">
 *      ...
 *      &lt;property name="resume" column="RESUME" type="<b>encryptedBinary</b>" />
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
 * @since 1.2
 * 
 * @author Daniel Fern&aacute;ndez Garrido
 * 
 */
public final class EncryptedBinaryType implements UserType, ParameterizedType {

    private static final int BLOCK_SIZE = 2048;
    
    private static NullableType nullableType = Hibernate.BINARY;
    private static int sqlType = nullableType.sqlType();
    private static int[] sqlTypes = new int[]{ sqlType };
    
    private boolean initialized = false;
    private boolean useEncryptorName = false;
    
    private String encryptorName = null;
    private String algorithm = null;
    private String password = null;
    private Integer keyObtentionIterations = null;
    
    private PBEByteEncryptor encryptor = null;

    
    public int[] sqlTypes() {
        return sqlTypes;
    }

    
    public Class returnedClass() {
        return byte[].class;
    }

    
    public boolean equals(Object x, Object y) 
            throws HibernateException {
        
        return (x == y) || 
               (x != null && y != null && java.util.Arrays.equals((byte[]) x, (byte[]) y));
        
    }
    
    
    public Object deepCopy(Object value)
            throws HibernateException {
        
        if (value == null) {
            return null;
        }
        byte[] valueBytes = (byte[]) value;
        byte[] copyBytes = new byte[valueBytes.length];
        System.arraycopy(valueBytes, 0, copyBytes, 0, valueBytes.length);
        return copyBytes;
        
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
        return true;
    }


    public int hashCode(Object x)
            throws HibernateException {
        
        byte[] valueBytes = (byte[]) x;
        int result = 1;
        for (int i = 0; i < valueBytes.length; i++ ) {
            result = (result * 17) + valueBytes[i];
        }
        return result;
        
    }

    
    public Object replace(Object original, Object target, Object owner) 
            throws HibernateException {
        return (original == null)? null : deepCopy(original);
    }

    
    public Object nullSafeGet(ResultSet rs, String[] names, Object owner)
            throws HibernateException, SQLException {

        checkInitialization();

        byte[] encryptedValue = null;
        if (Environment.useStreamsForBinary()) {

            InputStream inputStream = rs.getBinaryStream(names[0]);
            if (rs.wasNull()) {
                return null;
            }
            
            ByteArrayOutputStream outputStream = 
                new ByteArrayOutputStream(BLOCK_SIZE);
            byte[] inputBuff = new byte[BLOCK_SIZE];
            try {
                int readBytes = 0;
                while (readBytes != -1) {
                    readBytes = inputStream.read(inputBuff);
                    if (readBytes != -1) {
                        outputStream.write(inputBuff, 0, readBytes);
                    }
                }
            } catch (IOException e) {
                throw new HibernateException(
                        "IOException occurred reading a binary value", e);
            } finally {
                try {
                    inputStream.close();
                } catch (IOException e) {}
                try {
                    outputStream.close();
                } catch (IOException e) {}
            }
            
            encryptedValue = outputStream.toByteArray();
            
        } else {
            
            encryptedValue = rs.getBytes(names[0]);
            if (rs.wasNull()) {
                return null;
            }
            
        }
        
        return this.encryptor.decrypt(encryptedValue);
        
    }

    
    public void nullSafeSet(PreparedStatement st, Object value, int index)
            throws HibernateException, SQLException {

        checkInitialization();
        
        if (value == null) {
            st.setNull(index, sqlType);
        } else {
            byte[] encryptedValue = this.encryptor.encrypt((byte[]) value);
            if (Environment.useStreamsForBinary()) {
                st.setBinaryStream(
                        index, 
                        new ByteArrayInputStream(encryptedValue), 
                        encryptedValue.length);
            } else {
                st.setBytes(index, encryptedValue);
            }
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
                PBEByteEncryptor pbeEncryptor = 
                    registry.getPBEByteEncryptor(encryptorName);
                if (pbeEncryptor == null) {
                    throw new EncryptionInitializationException(
                            "No big integer encryptor registered for hibernate " +
                            "with name \"" + encryptorName + "\"");
                }
                this.encryptor = pbeEncryptor;
                
            } else {
                
                StandardPBEByteEncryptor newEncryptor = 
                    new StandardPBEByteEncryptor();
                
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
