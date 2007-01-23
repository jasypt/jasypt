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

import org.hibernate.HibernateException;
import org.hibernate.usertype.EnhancedUserType;
import org.hibernate.usertype.ParameterizedType;

public class EncryptedTextType implements EnhancedUserType, ParameterizedType {

    
    public Object assemble(Serializable cached, Object owner) throws HibernateException {
        // TODO Auto-generated method stub
        return null;
    }

    public Object deepCopy(Object value) throws HibernateException {
        // TODO Auto-generated method stub
        return null;
    }

    public Serializable disassemble(Object value) throws HibernateException {
        // TODO Auto-generated method stub
        return null;
    }

    public boolean equals(Object x, Object y) throws HibernateException {
        // TODO Auto-generated method stub
        return false;
    }

    public Object fromXMLString(String xmlValue) {
        // TODO Auto-generated method stub
        return null;
    }

    public int hashCode(Object x) throws HibernateException {
        // TODO Auto-generated method stub
        return 0;
    }

    public boolean isMutable() {
        // TODO Auto-generated method stub
        return false;
    }

    public Object nullSafeGet(ResultSet rs, String[] names, Object owner) throws HibernateException, SQLException {
        // TODO Auto-generated method stub
        return null;
    }

    public void nullSafeSet(PreparedStatement st, Object value, int index) throws HibernateException, SQLException {
        // TODO Auto-generated method stub
        
    }

    public String objectToSQLString(Object value) {
        // TODO Auto-generated method stub
        return null;
    }

    public Object replace(Object original, Object target, Object owner) throws HibernateException {
        // TODO Auto-generated method stub
        return null;
    }

    public Class returnedClass() {
        return String.class;
    }

    public void setParameterValues(Properties parameters) {
        // TODO Auto-generated method stub
        
    }

    public int[] sqlTypes() {
        // TODO Auto-generated method stub
        return null;
    }

    public String toXMLString(Object value) {
        // TODO Auto-generated method stub
        return null;
    }

}
