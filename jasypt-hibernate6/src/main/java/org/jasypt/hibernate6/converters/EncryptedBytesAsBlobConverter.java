package org.jasypt.hibernate6.converters;

import jakarta.persistence.Converter;
import org.hibernate.HibernateException;
import org.hibernate.engine.jdbc.BlobProxy;
import org.jasypt.encryption.pbe.PBEByteEncryptor;
import org.jasypt.encryption.pbe.StandardPBEByteEncryptor;
import org.jasypt.exceptions.EncryptionInitializationException;
import org.jasypt.hibernate6.encryptor.HibernatePBEEncryptorRegistry;

import java.io.ByteArrayOutputStream;
import java.io.IOException;
import java.io.InputStream;
import java.sql.Blob;
import java.sql.SQLException;

@Converter
public class EncryptedBytesAsBlobConverter extends JasyptConverter<byte[], Blob> {

    private static final int BLOCK_SIZE = 2048;
    private PBEByteEncryptor encryptor = null;

    public static ConverterConfig converterConfig;

    public static void setConverterConfig(final ConverterConfig converterConfig) {
        EncryptedBytesAsBlobConverter.converterConfig = converterConfig;
    }

    @Override
    protected synchronized void checkInitialized() {

        if (!this.initialized) {

            if (converterConfig == null) {
                throw new ConverterInitializationException("Converter config is null for EncryptedBytesAsBlobConverter");
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
    public Blob convertToDatabaseColumn(byte[] attribute) {
        checkInitialized();

        if (attribute == null) {
            return null;
        }

        byte[] encryptedValue = encryptor.encrypt(attribute);
        return BlobProxy.generateProxy(encryptedValue);
    }

    @Override
    public byte[] convertToEntityAttribute(Blob dbData) {
        checkInitialized();

        if (dbData == null) {
            return null;
        }

        try (InputStream inputStream = dbData.getBinaryStream();
             ByteArrayOutputStream outputStream = new ByteArrayOutputStream(BLOCK_SIZE)) {

            byte[] buffer = new byte[BLOCK_SIZE];
            int bytesRead;
            while ((bytesRead = inputStream.read(buffer)) != -1) {
                outputStream.write(buffer, 0, bytesRead);
            }

            return encryptor.decrypt(outputStream.toByteArray());

        } catch (IOException | SQLException e) {
            throw new HibernateException("Error reading or decrypting Blob data", e);
        }
    }
}
