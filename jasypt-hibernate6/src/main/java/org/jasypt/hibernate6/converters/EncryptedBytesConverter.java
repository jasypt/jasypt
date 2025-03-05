package org.jasypt.hibernate6.converters;

import jakarta.persistence.Converter;
import org.jasypt.encryption.pbe.PBEByteEncryptor;
import org.jasypt.encryption.pbe.StandardPBEByteEncryptor;
import org.jasypt.exceptions.EncryptionInitializationException;
import org.jasypt.hibernate6.encryptor.HibernatePBEEncryptorRegistry;

@Converter
public class EncryptedBytesConverter extends JasyptConverter<byte[], byte[]> {

    private PBEByteEncryptor encryptor = null;

    public static ConverterConfig converterConfig;

    public static void setConverterConfig(final ConverterConfig converterConfig) {
        EncryptedBytesConverter.converterConfig = converterConfig;
    }

    @Override
    protected synchronized void checkInitialized() {

        if (!this.initialized) {

            if (converterConfig == null) {
                throw new ConverterInitializationException("Converter config is null for EncryptedBytesConverter");
            } else {

                if (converterConfig.useEncryptorName) {

                    final HibernatePBEEncryptorRegistry registry =
                            HibernatePBEEncryptorRegistry.getInstance();
                    final PBEByteEncryptor pbeEncryptor =
                            registry.getPBEByteEncryptor(
                                    converterConfig.getProperty(EncryptionParameters.ENCRYPTOR_NAME));
                    if (pbeEncryptor == null) {
                        throw new EncryptionInitializationException(
                                "No big integer encryptor registered for hibernate " +
                                        "with name \"" +
                                        converterConfig.getProperty(EncryptionParameters.ENCRYPTOR_NAME)
                                        + "\"");
                    }
                    this.encryptor = pbeEncryptor;

                } else {

                    final StandardPBEByteEncryptor newEncryptor = new StandardPBEByteEncryptor();

                    newEncryptor.setPassword(converterConfig.getProperty(EncryptionParameters.PASSWORD));

                    if (converterConfig.getProperty(EncryptionParameters.ALGORITHM) != null) {
                        newEncryptor.setAlgorithm(converterConfig.getProperty(EncryptionParameters.ALGORITHM));
                    }

                    if (converterConfig.getProperty(EncryptionParameters.KEY_OBTENTION_ITERATIONS) != null) {
                        newEncryptor.setKeyObtentionIterations(
                                converterConfig.getProperty(EncryptionParameters.KEY_OBTENTION_ITERATIONS));
                    }

                    newEncryptor.initialize();

                    this.encryptor = newEncryptor;

                }
            }

            this.initialized = true;
        }

    }

    @Override
    public byte[] convertToDatabaseColumn(byte[] attribute) {
        checkInitialized();

        if (attribute == null) {
            return null;
        }

        return encryptor.encrypt(attribute);
    }

    @Override
    public byte[] convertToEntityAttribute(byte[] value) {
        checkInitialized();

        if (value == null) {
            return null;
        }


        return encryptor.decrypt(value);
    }
}
