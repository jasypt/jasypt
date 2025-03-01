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

import java.math.BigDecimal;
import java.math.RoundingMode;

import jakarta.persistence.Converter;
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
public final class EncryptedBigDecimal extends JasyptConverter<BigDecimal, BigDecimal> {

    private PBEBigDecimalEncryptor encryptor = null;

    public static ConverterConfig converterConfig;

    public static void setConverterConfig(final ConverterConfig converterConfig) {
        EncryptedBigDecimal.converterConfig = converterConfig;
    }

    @Override
    protected synchronized void checkInitialized() {

        if (!this.initialized) {

            if (EncryptedBigDecimal.converterConfig.useEncryptorName) {

                final HibernatePBEEncryptorRegistry registry =
                        HibernatePBEEncryptorRegistry.getInstance();
                final PBEBigDecimalEncryptor pbeEncryptor =
                        registry.getPBEBigDecimalEncryptor(
                                EncryptedBigDecimal.converterConfig.getProperty(EncryptionParameters.ENCRYPTOR_NAME));
                if (pbeEncryptor == null) {
                    throw new EncryptionInitializationException(
                            "No big decimal encryptor registered for hibernate " +
                                    "with name \"" +
                                    EncryptedBigDecimal.converterConfig.getProperty(EncryptionParameters.ENCRYPTOR_NAME)
                                    + "\"");
                }
                this.encryptor = pbeEncryptor;

            } else {

                final StandardPBEBigDecimalEncryptor newEncryptor =
                        new StandardPBEBigDecimalEncryptor();

                newEncryptor.setPassword(EncryptedBigDecimal.converterConfig.getProperty(EncryptionParameters.PASSWORD));

                if (EncryptedBigDecimal.converterConfig.getProperty(EncryptionParameters.ALGORITHM) != null) {
                    newEncryptor.setAlgorithm(EncryptedBigDecimal.converterConfig.getProperty(EncryptionParameters.ALGORITHM));
                }

                if (EncryptedBigDecimal.converterConfig.getProperty(EncryptionParameters.KEY_OBTENTION_ITERATIONS) != null) {
                    newEncryptor.setKeyObtentionIterations(EncryptedBigDecimal.converterConfig.getProperty(EncryptionParameters.KEY_OBTENTION_ITERATIONS));
                }

                newEncryptor.initialize();

                this.encryptor = newEncryptor;

            }

            this.initialized = true;
        }

    }

    @Override
    public BigDecimal convertToDatabaseColumn(BigDecimal bigDecimal) {
        checkInitialized();
        if (bigDecimal == null) {
            return null;
        } else {
            final BigDecimal scaledValue =
                    bigDecimal.setScale(
                            EncryptedBigDecimal.converterConfig.getProperty(
                                    EncryptionParameters.DECIMAL_SCALE
                            ), RoundingMode.DOWN);
            return this.encryptor.encrypt(scaledValue);
        }
    }

    @Override
    public BigDecimal convertToEntityAttribute(BigDecimal bigDecimal) {
        checkInitialized();
        if (bigDecimal == null) return null;

        final BigDecimal scaledEncryptedMessage =
                bigDecimal.setScale(
                        EncryptedBigDecimal.converterConfig.getProperty(
                                EncryptionParameters.DECIMAL_SCALE
                        ), RoundingMode.UNNECESSARY);
        return this.encryptor.decrypt(scaledEncryptedMessage);
    }

}
