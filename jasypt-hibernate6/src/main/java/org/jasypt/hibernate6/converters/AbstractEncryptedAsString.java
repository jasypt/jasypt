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
package org.jasypt.hibernate6.converters;

import java.util.Properties;

import jakarta.persistence.AttributeConverter;
import jakarta.persistence.Converter;
import org.jasypt.encryption.pbe.PBEStringEncryptor;
import org.jasypt.encryption.pbe.StandardPBEStringEncryptor;
import org.jasypt.exceptions.EncryptionInitializationException;
import org.jasypt.hibernate6.encryptor.HibernatePBEEncryptorRegistry;

/**
 *
 * Base class for <b>Hibernate</b> <ttAttributeConverter</tt>s to store
 * values as encrypted strings.
 * 
 * @since 2.0.0
 * @author Kris Rice
 * 
 */
@Converter
public abstract class AbstractEncryptedAsString implements AttributeConverter<Object, String> {

    private boolean initialized = false;
    private boolean useEncryptorName = false;

    private String encryptorName = null;
    private String algorithm = null;
    private String providerName = null;
    private String password = null;
    private Integer keyObtentionIterations = null;
    private String stringOutputType = null;

    protected PBEStringEncryptor encryptor = null;

    protected abstract Object convertToObject(String string);

    protected abstract String convertToString(Object object);

    protected void checkInitialized() {

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
                    this.keyObtentionIterations = Integer.parseInt(paramKeyObtentionIterations);
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

    @Override
    public String convertToDatabaseColumn(Object value) {
        checkInitialized();
        if (value == null) {
            return null;
        }
        return encryptor.encrypt(convertToString(value));
    }

    @Override
    public Object convertToEntityAttribute(String s) {
        checkInitialized();
        if (s == null) {
            return null;
        }
        return convertToObject(encryptor.decrypt(s));
    }
    
}
