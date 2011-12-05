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
package org.jasypt.hibernate3.type;

import java.util.Calendar;
import java.util.Properties;
import java.util.TimeZone;

import org.jasypt.commons.CommonUtils;
import org.jasypt.hibernate3.encryptor.HibernatePBEEncryptorRegistry;
import org.jasypt.hibernate3.encryptor.HibernatePBEStringEncryptor;

/**
 * <p>
 * A <b>Hibernate</b> <tt>UserType</tt> implementation which allows 
 * encryption of Calendar values into String (VARCHAR) database fields
 * during persistence of entities.
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
 *    &lt;typedef name="<b>encryptedCalendarAsString</b>" class="org.jasypt.hibernate.type.EncryptedCalendarAsStringType">
 *      &lt;param name="encryptorRegisteredName"><b><i>myHibernateStringEncryptor</i></b>&lt;/param>
 *      &lt;param name="storeTimeZone"><b><i>true</i></b>&lt;/param>
 *    &lt;/typedef>
 *    ...
 *    &lt;class name="UserData" table="USER_DATA">
 *      ...
 *      &lt;property name="birth" column="BIRTH" type="<b>encryptedCalendarAsString</b>" />
 *      ...
 *    &lt;class>
 *    ...
 *  &lt;hibernate-mapping>
 * </pre>
 * </p>
 * <p>
 * ...where a <tt>HibernatePBEStringEncryptor</tt> object
 * should have been previously registered to be used
 * from Hibernate with name <tt>myHibernateStringEncryptor</tt> (see
 * {@link HibernatePBEStringEncryptor} and {@link HibernatePBEEncryptorRegistry}). 
 * </p>
 * <p>
 * The boolean <tt>storeTimeZone</tt> parameter allows the Calendar to be 
 * re-created with the same TimeZone that it was created. This is an 
 * <b>optional</b> parameter, and its default value is <b>FALSE</b>.
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
 *    &lt;typedef name="<b>encryptedCalendarAsString</b>" class="org.jasypt.hibernate.type.EncryptedCalendarAsStringType">
 *      &lt;param name="algorithm"><b><i>PBEWithMD5AndTripleDES</i></b>&lt;/param>
 *      &lt;param name="password"><b><i>XXXXX</i></b>&lt;/param>
 *      &lt;param name="keyObtentionIterations"><b><i>1000</i></b>&lt;/param>
 *      &lt;param name="storeTimeZone"><b><i>true</i></b>&lt;/param>
 *    &lt;/typedef>
 *    ...
 *    &lt;class name="UserData" table="USER_DATA">
 *      ...
 *      &lt;property name="birth" column="BIRTH" type="<b>encryptedCalendarAsString</b>" />
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
 * @since 1.9.0 (class existed in package
 *            org.jasypt.hibernate.type since 1.2)
 * 
 * @author Daniel Fern&aacute;ndez
 * 
 */
public final class EncryptedCalendarAsStringType extends AbstractEncryptedAsStringType{

    private Boolean storeTimeZone = Boolean.FALSE;

    /**
     * @see org.jasypt.hibernate.type.AbstractEncryptedAsStringType#convertToObject(java.lang.String)
     */
    protected Object convertToObject(final String string) {
        final String[] stringTokens = CommonUtils.split(string);
        TimeZone tz = null;
        final long timeMillis = Long.valueOf(stringTokens[0]).longValue();
        if (this.storeTimeZone.booleanValue()) {
            tz = TimeZone.getTimeZone(stringTokens[1]);
        } else {
            tz = TimeZone.getDefault();
        }
        final Calendar cal = Calendar.getInstance();
        cal.setTimeZone(tz);
        cal.setTimeInMillis(timeMillis);
        return cal;
    }


    /**
     * @see org.jasypt.hibernate.type.AbstractEncryptedAsStringType#convertToString(java.lang.Object)
     */
    protected String convertToString(final Object object) {
        final StringBuffer strBuff = new StringBuffer();
        final long timeMillis = ((Calendar) object).getTimeInMillis();
        strBuff.append((new Long(timeMillis)).toString());
        if (this.storeTimeZone.booleanValue()) {
            strBuff.append(" ");
            strBuff.append(((Calendar) object).getTimeZone().getID());
        }
        return strBuff.toString();
    }
 
    
    public synchronized void setParameterValues(final Properties parameters) {
        
      	super.setParameterValues(parameters);
      	
        final String paramStoreTimeZone = parameters.getProperty(ParameterNaming.STORE_TIME_ZONE);
        if ((paramStoreTimeZone != null) && (!paramStoreTimeZone.trim().equals(""))) {
            this.storeTimeZone = CommonUtils.getStandardBooleanValue(paramStoreTimeZone);
        }
        
    }


    public Class returnedClass() {
        return Calendar.class;
    }

}
