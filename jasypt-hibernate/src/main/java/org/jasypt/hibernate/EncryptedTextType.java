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
import org.hibernate.usertype.EnhancedUserType;
import org.hibernate.usertype.ParameterizedType;
import org.hibernate.util.EqualsHelper;
import org.jasypt.exceptions.EncryptionInitializationException;

public final class EncryptedTextType implements EnhancedUserType, ParameterizedType {

    private static NullableType nullableType = Hibernate.STRING;
    private static int sqlType = nullableType.sqlType();
    private static int[] sqlTypes = new int[]{ sqlType };
    
    private String encryptorName = null;
    private HibernatePBEEncryptor encryptor = null;

    
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

    
    // TODO: Check this... if we don't get the same encryption value always... this is not possible
    //       Maybe not an EnhancedType?
    public String objectToSQLString(Object value) {
        checkInitialization();
        return this.encryptor.encrypt((String) value);
    }

    
    public Object fromXMLString(String xmlValue) {

        checkInitialization();
        return null;
        
    }


    public String toXMLString(Object value) {
        
        checkInitialization();
        return null;
        
    }

    
    public void setParameterValues(Properties parameters) {
        this.encryptorName = 
            parameters.getProperty(ParameterNaming.ENCRYPTOR_NAME);
    }

    
    private void checkInitialization() {
        if (this.encryptorName == null) {
            throw new EncryptionInitializationException(
                    "Encryptor name not configured in hibernate type");
        }
        if (this.encryptor == null) {
            HibernatePBEEncryptorRegistry registry = 
                HibernatePBEEncryptorRegistry.getInstance();
            this.encryptor = registry.getHibernatePBEEncryptor(encryptorName);
            if (this.encryptor == null) {
                throw new EncryptionInitializationException(
                        "No encryptor registered for hibernate with name \"" +
                        encryptorName + "\"");
            }
        }
    }
    
    
}
