package org.jasypt.hibernate6.converters;

import org.jasypt.encryption.pbe.PBEStringEncryptor;
import org.jasypt.encryption.pbe.StandardPBEStringEncryptor;
import org.jasypt.exceptions.EncryptionInitializationException;
import org.jasypt.hibernate6.encryptor.HibernatePBEEncryptorRegistry;

public class EncryptedByteAsString extends JasyptConverter<Byte, String> {

    protected PBEStringEncryptor encryptor = null;

    public static ConverterConfig converterConfig;

    public static void setConverterConfig(final ConverterConfig converterConfig) {
        EncryptedByteAsString.converterConfig = converterConfig;
    }

    @Override
    protected void checkInitialized() {
        if (!this.initialized) {
            if (converterConfig == null) {
                this.encryptor = new StandardPBEStringEncryptor();
            } else {

                if (converterConfig.useEncryptorName) {

                    final HibernatePBEEncryptorRegistry registry =
                            HibernatePBEEncryptorRegistry.getInstance();
                    final PBEStringEncryptor pbeEncryptor =
                            registry.getPBEStringEncryptor(converterConfig.getProperty(ParameterNaming.ENCRYPTOR_NAME));
                    if (pbeEncryptor == null) {
                        throw new EncryptionInitializationException(
                                "No string encryptor registered for hibernate " +
                                        "with name \"" + converterConfig.getProperty(ParameterNaming.ENCRYPTOR_NAME) + "\"");
                    }
                    this.encryptor = pbeEncryptor;

                } else {

                    final StandardPBEStringEncryptor newEncryptor = new StandardPBEStringEncryptor();

                    newEncryptor.setPassword(converterConfig.getProperty(ParameterNaming.PASSWORD));

                    if (converterConfig.getProperty(ParameterNaming.ALGORITHM) != null)
                        newEncryptor.setAlgorithm(converterConfig.getProperty(ParameterNaming.ALGORITHM));

                    if (converterConfig.getProperty(ParameterNaming.PROVIDER_NAME) != null)
                        newEncryptor.setProviderName(converterConfig.getProperty(ParameterNaming.PROVIDER_NAME));

                    if (converterConfig.getProperty(ParameterNaming.KEY_OBTENTION_ITERATIONS) != null)
                        newEncryptor.setKeyObtentionIterations(converterConfig.getProperty(ParameterNaming.KEY_OBTENTION_ITERATIONS));

                    if (converterConfig.getProperty(ParameterNaming.STRING_OUTPUT_TYPE) != null)
                        newEncryptor.setStringOutputType(converterConfig.getProperty(ParameterNaming.STRING_OUTPUT_TYPE));

                    newEncryptor.initialize();

                    this.encryptor = newEncryptor;

                }
            }
            this.initialized = true;
        }
    }

    @Override
    public String convertToDatabaseColumn(Byte value) {
        checkInitialized();
        if (value == null) {
            return null;
        }
        return encryptor.encrypt(value.toString());
    }

    @Override
    public Byte convertToEntityAttribute(String s) {
        checkInitialized();
        if (s == null) {
            return null;
        }
        return Byte.parseByte(encryptor.decrypt(s));
    }
}

