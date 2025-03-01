package org.jasypt.hibernate6.converters;

import jakarta.persistence.Converter;
import org.hibernate.HibernateException;
import org.hibernate.cfg.Environment;
import org.jasypt.encryption.pbe.PBEByteEncryptor;
import org.jasypt.encryption.pbe.StandardPBEByteEncryptor;
import org.jasypt.exceptions.EncryptionInitializationException;
import org.jasypt.hibernate6.encryptor.HibernatePBEEncryptorRegistry;

import java.io.ByteArrayInputStream;
import java.io.ByteArrayOutputStream;
import java.io.IOException;
import java.io.InputStream;

@Converter
public class EncryptedBinary extends JasyptConverter<byte[], byte[]> {

    private static final int BLOCK_SIZE = 2048;
    private PBEByteEncryptor encryptor = null;

    public static ConverterConfig converterConfig;

    public static void setConverterConfig(final ConverterConfig converterConfig) {
        EncryptedBinary.converterConfig = converterConfig;
    }

    @Override
    protected synchronized void checkInitialized() {

        if (!this.initialized) {

            if (EncryptedBinary.converterConfig.useEncryptorName) {

                final HibernatePBEEncryptorRegistry registry =
                        HibernatePBEEncryptorRegistry.getInstance();
                final PBEByteEncryptor pbeEncryptor =
                        registry.getPBEByteEncryptor(
                                EncryptedBinary.converterConfig.getProperty(ParameterNaming.ENCRYPTOR_NAME));
                if (pbeEncryptor == null) {
                    throw new EncryptionInitializationException(
                            "No big integer encryptor registered for hibernate " +
                                    "with name \"" +
                                    EncryptedBinary.converterConfig.getProperty(ParameterNaming.ENCRYPTOR_NAME)
                                    + "\"");
                }
                this.encryptor = pbeEncryptor;

            } else {

                final StandardPBEByteEncryptor newEncryptor =
                        new StandardPBEByteEncryptor();

                newEncryptor.setPassword(EncryptedBinary.converterConfig.getProperty(ParameterNaming.PASSWORD));

                if (EncryptedBinary.converterConfig.getProperty(ParameterNaming.ALGORITHM) != null) {
                    newEncryptor.setAlgorithm(EncryptedBinary.converterConfig.getProperty(ParameterNaming.ALGORITHM));
                }

                if (EncryptedBinary.converterConfig.getProperty(ParameterNaming.KEY_OBTENTION_ITERATIONS) != null) {
                    newEncryptor.setKeyObtentionIterations(
                            EncryptedBinary.converterConfig.getProperty(ParameterNaming.KEY_OBTENTION_ITERATIONS));
                }

                newEncryptor.initialize();

                this.encryptor = newEncryptor;

            }

            this.initialized = true;
        }

    }

    @Override
    public byte[] convertToDatabaseColumn(byte[] bytes) {
        checkInitialized();

        if (bytes == null) return null;

        return this.encryptor.encrypt(bytes);
    }

    @Override
    public byte[] convertToEntityAttribute(byte[] bytes) {
        checkInitialized();

        byte[] encryptedValue = null;
        if (Environment.getProperties().getProperty("hibernate.jdbc.use_streams_for_binary").equals("true")) {

            if (bytes == null) return null;
            final InputStream inputStream = new ByteArrayInputStream(bytes);

            final ByteArrayOutputStream outputStream = new ByteArrayOutputStream(BLOCK_SIZE);
            final byte[] inputBuff = new byte[BLOCK_SIZE];
            try {
                int readBytes = 0;
                while (readBytes != -1) {
                    readBytes = inputStream.read(inputBuff);
                    if (readBytes != -1) {
                        outputStream.write(inputBuff, 0, readBytes);
                    }
                }
            } catch (IOException e) {
                throw new HibernateException(
                        "IOException occurred reading a binary value", e);
            } finally {
                try {
                    inputStream.close();
                } catch (IOException e) {
                    // exception ignored
                }
                try {
                    outputStream.close();
                } catch (IOException e) {
                    // exception ignored
                }
            }

            encryptedValue = outputStream.toByteArray();

        } else {
            if (bytes == null) return null;
        }

        return this.encryptor.decrypt(encryptedValue);
    }
}
