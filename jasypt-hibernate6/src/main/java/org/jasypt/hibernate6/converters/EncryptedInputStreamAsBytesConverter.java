package org.jasypt.hibernate6.converters;

import jakarta.persistence.Converter;
import org.hibernate.HibernateException;
import org.jasypt.encryption.pbe.PBEByteEncryptor;
import org.jasypt.encryption.pbe.StandardPBEByteEncryptor;
import org.jasypt.exceptions.EncryptionInitializationException;
import org.jasypt.hibernate6.encryptor.HibernatePBEEncryptorRegistry;

import java.io.ByteArrayOutputStream;
import java.io.IOException;
import java.io.InputStream;

@Converter
public class EncryptedInputStreamAsBytesConverter extends JasyptConverter<InputStream, byte[]> {

    private static final int BUFFER_SIZE = 2048;
    private PBEByteEncryptor encryptor = null;

    public static ConverterConfig converterConfig;

    public static void setConverterConfig(final ConverterConfig converterConfig) {
        EncryptedInputStreamAsBytesConverter.converterConfig = converterConfig;
    }

    @Override
    protected synchronized void checkInitialized() {
        if (!this.initialized) {

            if (converterConfig == null) {
                throw new ConverterInitializationException("Converter config is null for EncryptedInputStreamAsBytesConverter");
            } else {
                if (converterConfig.useEncryptorName) {
                    HibernatePBEEncryptorRegistry registry = HibernatePBEEncryptorRegistry.getInstance();
                    PBEByteEncryptor pbeEncryptor = registry.getPBEByteEncryptor(
                            converterConfig.getProperty(EncryptionParameters.ENCRYPTOR_NAME));
                    if (pbeEncryptor == null) {
                        throw new EncryptionInitializationException("No encryptor registered with given name");
                    }
                    this.encryptor = pbeEncryptor;
                } else {
                    StandardPBEByteEncryptor newEncryptor = new StandardPBEByteEncryptor();
                    newEncryptor.setPassword(converterConfig.getProperty(EncryptionParameters.PASSWORD));
                    newEncryptor.initialize();
                    this.encryptor = newEncryptor;
                }
            }
            this.initialized = true;
        }
    }

    @Override
    public byte[] convertToDatabaseColumn(InputStream inputStream) {
        checkInitialized();
        if (inputStream == null) {
            return null;
        }
        try (ByteArrayOutputStream outputStream = new ByteArrayOutputStream()) {
            byte[] buffer = new byte[BUFFER_SIZE];
            int bytesRead;
            while ((bytesRead = inputStream.read(buffer)) != -1) {
                outputStream.write(buffer, 0, bytesRead);
            }
            return encryptor.encrypt(outputStream.toByteArray());
        } catch (IOException e) {
            throw new HibernateException("Error encrypting InputStream", e);
        }
    }

    @Override
    public InputStream convertToEntityAttribute(byte[] dbData) {
        checkInitialized();
        if (dbData == null) {
            return null;
        }
        try {
            byte[] decryptedData = encryptor.decrypt(dbData);
            return new java.io.ByteArrayInputStream(decryptedData);
        } catch (Exception e) {
            throw new HibernateException("Error decrypting Blob data", e);
        }
    }
}
