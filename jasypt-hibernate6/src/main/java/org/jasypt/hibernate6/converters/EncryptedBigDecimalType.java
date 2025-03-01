package org.jasypt.hibernate6.converters;

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

import java.io.Serializable;
import java.math.BigDecimal;
import java.math.RoundingMode;
import java.util.Properties;

import jakarta.persistence.AttributeConverter;
import jakarta.persistence.Converter;
import org.hibernate.HibernateException;
import org.jasypt.encryption.pbe.PBEBigDecimalEncryptor;
import org.jasypt.encryption.pbe.StandardPBEBigDecimalEncryptor;
import org.jasypt.exceptions.EncryptionInitializationException;
import org.jasypt.hibernate6.encryptor.HibernatePBEEncryptorRegistry;

/**
 *
 * @since 2.0.0
 *
 * @author Kris Rice
 *
 */
@Converter
public final class EncryptedBigDecimalType implements AttributeConverter<BigDecimal, BigDecimal> {

    private boolean initialized = false;
    private boolean useEncryptorName = false;

    private String encryptorName = null;
    private String algorithm = null;
    private String password = null;
    private Integer keyObtentionIterations = null;
    private Integer decimalScale = null;

    private PBEBigDecimalEncryptor encryptor = null;

    @Override
    public BigDecimal convertToDatabaseColumn(BigDecimal bigDecimal) {
        checkInitialized();
        if (bigDecimal == null) {
            return null;
        } else {
            final BigDecimal scaledValue = bigDecimal.setScale(this.decimalScale, RoundingMode.DOWN);
            return this.encryptor.encrypt(scaledValue);
        }
    }

    @Override
    public BigDecimal convertToEntityAttribute(BigDecimal bigDecimal) {
        checkInitialized();
        if (bigDecimal == null) return null;

        final BigDecimal scaledEncryptedMessage = bigDecimal.setScale(this.decimalScale, RoundingMode.UNNECESSARY);
        return this.encryptor.decrypt(scaledEncryptedMessage);
    }

    public Class<BigDecimal> returnedClass() {
        return BigDecimal.class;
    }

    public boolean equals(final Object x, final Object y) throws HibernateException {
        return x == y || ( x != null && y != null && x.equals( y ) );
    }

    public Object deepCopy(final Object value) throws HibernateException {
        return value;
    }

    public Object assemble(final Serializable cached, final Object owner) throws HibernateException {
        if (cached == null) {
            return null;
        }
        return deepCopy(cached);
    }

    public Serializable disassemble(final Object value) throws HibernateException {
        if (value == null) {
            return null;
        }
        return (Serializable) deepCopy(value);
    }

    public boolean isMutable() {
        return false;
    }

    public int hashCode(final Object x) throws HibernateException {
        return x.hashCode();
    }

    public Object replace(final Object original, final Object target, final Object owner) throws HibernateException {
        return original;
    }

    public synchronized void setParameterValues(final Properties parameters) {

        final String paramEncryptorName =
                parameters.getProperty(ParameterNaming.ENCRYPTOR_NAME);
        final String paramAlgorithm =
                parameters.getProperty(ParameterNaming.ALGORITHM);
        final String paramPassword =
                parameters.getProperty(ParameterNaming.PASSWORD);
        final String paramKeyObtentionIterations =
                parameters.getProperty(ParameterNaming.KEY_OBTENTION_ITERATIONS);
        final String paramDecimalScale =
                parameters.getProperty(ParameterNaming.DECIMAL_SCALE);

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

        if (paramDecimalScale != null) {

            try {
                this.decimalScale =
                        new Integer(Integer.parseInt(paramDecimalScale));
            } catch (NumberFormatException e) {
                throw new EncryptionInitializationException(
                        "Value specified for \"" +
                                ParameterNaming.DECIMAL_SCALE +
                                "\" is not a valid integer");
            }

        } else {

            throw new EncryptionInitializationException(
                    ParameterNaming.DECIMAL_SCALE +
                            " must be specified");

        }

    }

    private synchronized void checkInitialized() {

        if (!this.initialized) {

            if (this.useEncryptorName) {

                final HibernatePBEEncryptorRegistry registry =
                        HibernatePBEEncryptorRegistry.getInstance();
                final PBEBigDecimalEncryptor pbeEncryptor =
                        registry.getPBEBigDecimalEncryptor(this.encryptorName);
                if (pbeEncryptor == null) {
                    throw new EncryptionInitializationException(
                            "No big decimal encryptor registered for hibernate " +
                                    "with name \"" + this.encryptorName + "\"");
                }
                this.encryptor = pbeEncryptor;

            } else {

                final StandardPBEBigDecimalEncryptor newEncryptor =
                        new StandardPBEBigDecimalEncryptor();

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
