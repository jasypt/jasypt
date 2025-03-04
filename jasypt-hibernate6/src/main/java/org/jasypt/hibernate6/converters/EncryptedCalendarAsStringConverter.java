package org.jasypt.hibernate6.converters;

import org.jasypt.commons.CommonUtils;
import org.jasypt.encryption.pbe.PBEStringEncryptor;
import org.jasypt.encryption.pbe.StandardPBEStringEncryptor;
import org.jasypt.exceptions.EncryptionInitializationException;
import org.jasypt.hibernate6.encryptor.HibernatePBEEncryptorRegistry;

import java.util.Calendar;
import java.util.TimeZone;

public class EncryptedCalendarAsStringConverter extends JasyptConverter<Calendar, String> {

    private Boolean storeTimeZone = Boolean.FALSE;

    protected PBEStringEncryptor encryptor = null;

    public static ConverterConfig converterConfig;

    public static void setConverterConfig(final ConverterConfig converterConfig) {
        EncryptedCalendarAsStringConverter.converterConfig = converterConfig;
    }
    
    @Override
    protected void checkInitialized() {
        if (!this.initialized) {
            if (converterConfig == null) {
                throw new ConverterInitializationException("Converter config is null for EncryptedCalendarAsStringConverter");
            } else {

                if (converterConfig.useEncryptorName) {

                    final HibernatePBEEncryptorRegistry registry =
                            HibernatePBEEncryptorRegistry.getInstance();
                    final PBEStringEncryptor pbeEncryptor =
                            registry.getPBEStringEncryptor(converterConfig.getProperty(EncryptionParameters.ENCRYPTOR_NAME));
                    if (pbeEncryptor == null) {
                        throw new EncryptionInitializationException(
                                "No string encryptor registered for hibernate " +
                                        "with name \"" + converterConfig.getProperty(EncryptionParameters.ENCRYPTOR_NAME) + "\"");
                    }
                    this.encryptor = pbeEncryptor;

                } else {

                    final StandardPBEStringEncryptor newEncryptor = new StandardPBEStringEncryptor();

                    newEncryptor.setPassword(converterConfig.getProperty(EncryptionParameters.PASSWORD));

                    if (converterConfig.getProperty(EncryptionParameters.ALGORITHM) != null)
                        newEncryptor.setAlgorithm(converterConfig.getProperty(EncryptionParameters.ALGORITHM));

                    if (converterConfig.getProperty(EncryptionParameters.PROVIDER_NAME) != null)
                        newEncryptor.setProviderName(converterConfig.getProperty(EncryptionParameters.PROVIDER_NAME));

                    if (converterConfig.getProperty(EncryptionParameters.KEY_OBTENTION_ITERATIONS) != null)
                        newEncryptor.setKeyObtentionIterations(converterConfig.getProperty(EncryptionParameters.KEY_OBTENTION_ITERATIONS));

                    if (converterConfig.getProperty(EncryptionParameters.STRING_OUTPUT_TYPE) != null)
                        newEncryptor.setStringOutputType(converterConfig.getProperty(EncryptionParameters.STRING_OUTPUT_TYPE));

                    newEncryptor.initialize();

                    this.encryptor = newEncryptor;

                }

                if (converterConfig.getProperty(EncryptionParameters.STORE_TIME_ZONE) != null) {
                    this.storeTimeZone = converterConfig.getProperty(EncryptionParameters.STORE_TIME_ZONE);
                }
            }
            this.initialized = true;
        }
    }

    protected Calendar convertToObject(final String string) {
        final String[] stringTokens = CommonUtils.split(string);
        TimeZone tz;
        final long timeMillis = Long.parseLong(stringTokens[0]);
        if (this.storeTimeZone) {
            tz = TimeZone.getTimeZone(stringTokens[1]);
        } else {
            tz = TimeZone.getDefault();
        }
        final Calendar cal = Calendar.getInstance();
        cal.setTimeZone(tz);
        cal.setTimeInMillis(timeMillis);
        return cal;
    }

    protected String convertToString(final Object object) {
        final StringBuilder strBuff = new StringBuilder();
        final long timeMillis = ((Calendar) object).getTimeInMillis();
        strBuff.append(timeMillis);
        if (this.storeTimeZone) {
            strBuff.append(" ");
            strBuff.append(((Calendar) object).getTimeZone().getID());
        }
        return strBuff.toString();
    }

    @Override
    public String convertToDatabaseColumn(Calendar value) {
        checkInitialized();
        if (value == null) {
            return null;
        }
        return encryptor.encrypt(convertToString(value));
    }

    @Override
    public Calendar convertToEntityAttribute(String s) {
        checkInitialized();
        if (s == null) {
            return null;
        }
        return convertToObject(encryptor.decrypt(s));
    }

}
