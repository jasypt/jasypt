package org.jasypt.hibernate6.converters;

import jakarta.persistence.AttributeConverter;
import org.jasypt.encryption.pbe.PBEBigIntegerEncryptor;
import org.jasypt.encryption.pbe.StandardPBEBigIntegerEncryptor;
import org.jasypt.exceptions.EncryptionInitializationException;
import org.jasypt.hibernate6.encryptor.HibernatePBEEncryptorRegistry;

import java.math.BigInteger;
import java.util.Properties;

public class EncryptedBigInteger implements AttributeConverter<BigInteger, BigInteger> {

    private boolean initialized = false;
    private boolean useEncryptorName = false;

    private String encryptorName = null;
    private String algorithm = null;
    private String password = null;
    private Integer keyObtentionIterations = null;

    private PBEBigIntegerEncryptor encryptor = null;

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
                final PBEBigIntegerEncryptor pbeEncryptor =
                        registry.getPBEBigIntegerEncryptor(this.encryptorName);
                if (pbeEncryptor == null) {
                    throw new EncryptionInitializationException(
                            "No big integer encryptor registered for hibernate " +
                                    "with name \"" + this.encryptorName + "\"");
                }
                this.encryptor = pbeEncryptor;

            } else {

                final StandardPBEBigIntegerEncryptor newEncryptor =
                        new StandardPBEBigIntegerEncryptor();

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
