package org.jasypt.hibernate6.converters;

import jakarta.persistence.Converter;
import jakarta.persistence.EntityManager;
import jakarta.persistence.PersistenceContext;
import org.jasypt.exceptions.EncryptionInitializationException;
import org.jasypt.exceptions.EncryptionOperationNotPossibleException;
import org.jasypt.hibernate6.encryptor.*;

import java.io.*;
import java.sql.Blob;
import java.sql.SQLException;

@Converter
public class EncryptedInputStreamConverter extends JasyptConverter<InputStream, Blob> {

    private HibernatePBEInputStreamEncryptor encryptor = null;

    public static ConverterConfig converterConfig;

    public static void setConverterConfig(final ConverterConfig converterConfig) {
        EncryptedInputStreamConverter.converterConfig = converterConfig;
    }

    @Override
    protected synchronized void checkInitialized() {

        if (!this.initialized) {

            if (converterConfig == null) {
                throw new ConverterInitializationException("Converter config is null for EncryptedInputStreamConverter");
            } else {

                if (converterConfig.useEncryptorName) {

                    final HibernatePBEEncryptorRegistry registry =
                            HibernatePBEEncryptorRegistry.getInstance();
                    final HibernatePBEInputStreamEncryptor pbeEncryptor =
                            registry.getPBEInputStreamEncryptor(
                                    converterConfig.getProperty(EncryptionParameters.ENCRYPTOR_NAME));
                    if (pbeEncryptor == null) {
                        throw new EncryptionInitializationException(
                                "No input stream encryptor registered for hibernate " +
                                        "with name \"" +
                                        converterConfig.getProperty(EncryptionParameters.ENCRYPTOR_NAME)
                                        + "\"");
                    }
                    this.encryptor = pbeEncryptor;

                } else {

                    final HibernatePBEInputStreamEncryptor newEncryptor = new HibernatePBEInputStreamEncryptor();

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
    public Blob convertToDatabaseColumn(InputStream value) {
        checkInitialized();

        if (value == null) {
            return null;
        }

        return encryptor.encrypt(value);
    }

    @Override
    public InputStream convertToEntityAttribute(Blob value) {
        checkInitialized();

        if (value == null) {
            return null;
        }
        try {
            // Decrypt the Blob back to InputStream
            InputStream encryptedStream = value.getBinaryStream();
            return encryptor.decrypt(encryptedStream);
        } catch (IOException | SQLException e) {
            throw new EncryptionOperationNotPossibleException();
        }
    }
}

