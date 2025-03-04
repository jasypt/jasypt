package org.jasypt.hibernate6.converters;

import org.jasypt.encryption.pbe.PBEBigIntegerEncryptor;
import org.jasypt.encryption.pbe.StandardPBEBigIntegerEncryptor;
import org.jasypt.exceptions.EncryptionInitializationException;
import org.jasypt.hibernate6.encryptor.HibernatePBEEncryptorRegistry;

import java.math.BigInteger;

public class EncryptedBigIntegerConverter extends JasyptConverter<BigInteger, BigInteger> {

    private PBEBigIntegerEncryptor encryptor = null;

    public static ConverterConfig converterConfig;

    public static void setConverterConfig(final ConverterConfig converterConfig) {
        EncryptedBigIntegerConverter.converterConfig = converterConfig;
    }

    @Override
    protected synchronized void checkInitialized() {

        if (!this.initialized) {

            if (converterConfig == null) {
                encryptor = new StandardPBEBigIntegerEncryptor();
            } else {

                if (EncryptedBigIntegerConverter.converterConfig.useEncryptorName) {

                    final HibernatePBEEncryptorRegistry registry =
                            HibernatePBEEncryptorRegistry.getInstance();
                    final PBEBigIntegerEncryptor pbeEncryptor =
                            registry.getPBEBigIntegerEncryptor(
                                    EncryptedBigIntegerConverter.converterConfig.getProperty(EncryptionParameters.ENCRYPTOR_NAME));
                    if (pbeEncryptor == null) {
                        throw new EncryptionInitializationException(
                                "No big integer encryptor registered for hibernate " +
                                        "with name \"" + EncryptedBigIntegerConverter.converterConfig.getProperty(EncryptionParameters.ENCRYPTOR_NAME) + "\"");
                    }
                    this.encryptor = pbeEncryptor;

                } else {

                    final StandardPBEBigIntegerEncryptor newEncryptor =
                            new StandardPBEBigIntegerEncryptor();

                    newEncryptor.setPassword(EncryptedBigIntegerConverter.converterConfig.getProperty(EncryptionParameters.PASSWORD));

                    if (EncryptedBigIntegerConverter.converterConfig.getProperty(EncryptionParameters.ALGORITHM) != null) {
                        newEncryptor.setAlgorithm(EncryptedBigIntegerConverter.converterConfig.getProperty(EncryptionParameters.ALGORITHM));
                    }

                    if (EncryptedBigIntegerConverter.converterConfig.getProperty(EncryptionParameters.KEY_OBTENTION_ITERATIONS) != null) {
                        newEncryptor.setKeyObtentionIterations(
                                EncryptedBigIntegerConverter.converterConfig.getProperty(EncryptionParameters.KEY_OBTENTION_ITERATIONS));
                    }

                    newEncryptor.initialize();

                    this.encryptor = newEncryptor;

                }
            }

            this.initialized = true;
        }

    }

    @Override
    public BigInteger convertToDatabaseColumn(BigInteger bigInteger) {
        checkInitialized();
        if (bigInteger == null) return null;

        return this.encryptor.encrypt(bigInteger);
    }

    @Override
    public BigInteger convertToEntityAttribute(BigInteger bigInteger) {
        checkInitialized();
        if (bigInteger == null) return null;

        return new BigInteger(String.valueOf(encryptor.decrypt(bigInteger)));
    }
}
