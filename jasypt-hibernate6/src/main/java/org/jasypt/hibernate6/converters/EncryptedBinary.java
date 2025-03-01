package org.jasypt.hibernate6.converters;

import jakarta.persistence.AttributeConverter;
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
import java.util.Properties;

@Converter
public class EncryptedBinary implements AttributeConverter<byte[], byte[]> {

    private static final int BLOCK_SIZE = 2048;

    private boolean initialized = false;
    private boolean useEncryptorName = false;

    private String encryptorName = null;
    private String algorithm = null;
    private String password = null;
    private Integer keyObtentionIterations = null;

    private PBEByteEncryptor encryptor = null;

    public synchronized void setParameterValues(final Properties parameters) {

        final String paramEncryptorName =
                parameters.getProperty(ParameterNaming.ENCRYPTOR_NAME);
        final String paramAlgorithm =
                parameters.getProperty(ParameterNaming.ALGORITHM);
        final String paramPassword =
                parameters.getProperty(ParameterNaming.PASSWORD);
        final String paramKeyObtentionIterations =
                parameters.getProperty(ParameterNaming.KEY_OBTENTION_ITERATIONS);

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
                            Integer.parseInt(paramKeyObtentionIterations);
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
    }

    private synchronized void checkInitialized() {

        if (!this.initialized) {

            if (this.useEncryptorName) {

                final HibernatePBEEncryptorRegistry registry =
                        HibernatePBEEncryptorRegistry.getInstance();
                final PBEByteEncryptor pbeEncryptor =
                        registry.getPBEByteEncryptor(this.encryptorName);
                if (pbeEncryptor == null) {
                    throw new EncryptionInitializationException(
                            "No big integer encryptor registered for hibernate " +
                                    "with name \"" + this.encryptorName + "\"");
                }
                this.encryptor = pbeEncryptor;

            } else {

                final StandardPBEByteEncryptor newEncryptor =
                        new StandardPBEByteEncryptor();

                newEncryptor.setPassword(this.password);

                if (this.algorithm != null) {
                    newEncryptor.setAlgorithm(this.algorithm);
                }

                if (this.keyObtentionIterations != null) {
                    newEncryptor.setKeyObtentionIterations(
                            this.keyObtentionIterations);
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
