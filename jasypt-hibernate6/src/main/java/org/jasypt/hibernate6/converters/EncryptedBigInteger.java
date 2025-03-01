package org.jasypt.hibernate6.converters;

import org.jasypt.encryption.pbe.PBEBigIntegerEncryptor;
import org.jasypt.encryption.pbe.StandardPBEBigIntegerEncryptor;
import org.jasypt.exceptions.EncryptionInitializationException;
import org.jasypt.hibernate6.encryptor.HibernatePBEEncryptorRegistry;

import java.math.BigInteger;

public class EncryptedBigInteger extends JasyptConverter<BigInteger, BigInteger> {

    private PBEBigIntegerEncryptor encryptor = null;

    public static ConverterConfig converterConfig;

    public static void setConverterConfig(final ConverterConfig converterConfig) {
        EncryptedBigInteger.converterConfig = converterConfig;
    }

    @Override
    protected synchronized void checkInitialized() {

        if (!this.initialized) {

            if (EncryptedBigInteger.converterConfig.useEncryptorName) {

                final HibernatePBEEncryptorRegistry registry =
                        HibernatePBEEncryptorRegistry.getInstance();
                final PBEBigIntegerEncryptor pbeEncryptor =
                        registry.getPBEBigIntegerEncryptor(
                                EncryptedBigInteger.converterConfig.getProperty(ParameterNaming.ENCRYPTOR_NAME));
                if (pbeEncryptor == null) {
                    throw new EncryptionInitializationException(
                            "No big integer encryptor registered for hibernate " +
                                    "with name \"" + EncryptedBigInteger.converterConfig.getProperty(ParameterNaming.ENCRYPTOR_NAME) + "\"");
                }
                this.encryptor = pbeEncryptor;

            } else {

                final StandardPBEBigIntegerEncryptor newEncryptor =
                        new StandardPBEBigIntegerEncryptor();

                newEncryptor.setPassword(EncryptedBigInteger.converterConfig.getProperty(ParameterNaming.PASSWORD));

                if (EncryptedBigInteger.converterConfig.getProperty(ParameterNaming.ALGORITHM) != null) {
                    newEncryptor.setAlgorithm(EncryptedBigInteger.converterConfig.getProperty(ParameterNaming.ALGORITHM));
                }

                if (EncryptedBigInteger.converterConfig.getProperty(ParameterNaming.KEY_OBTENTION_ITERATIONS) != null) {
                    newEncryptor.setKeyObtentionIterations(
                            EncryptedBigInteger.converterConfig.getProperty(ParameterNaming.KEY_OBTENTION_ITERATIONS));
                }

                newEncryptor.initialize();

                this.encryptor = newEncryptor;

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
