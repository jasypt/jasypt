package org.jasypt.hibernate6.configuration;

import org.hibernate.cfg.Configuration;
import org.jasypt.encryption.pbe.PBEStringEncryptor;
import org.jasypt.exceptions.EncryptionInitializationException;
import org.jasypt.hibernate6.converters.*;
import org.jasypt.hibernate6.encryptor.HibernatePBEEncryptorRegistry;
import org.jasypt.properties.PropertyValueEncryptionUtils;
import java.util.Properties;

import static org.hibernate.cfg.JdbcSettings.*;
import static org.hibernate.cfg.JdbcSettings.JAKARTA_JDBC_PASSWORD;

public class JasyptConfig extends Configuration {

    public JasyptConfig() {
        // register custom converters
        addAnnotatedClass(EncryptedBigDecimalAsString.class);
        addAnnotatedClass(EncryptedBigDecimal.class);
        addAnnotatedClass(EncryptedBigIntegerAsString.class);
        addAnnotatedClass(EncryptedBigInteger.class);
        addAnnotatedClass(EncryptedBinary.class);
        addAnnotatedClass(EncryptedBooleanAsString.class);
        addAnnotatedClass(EncryptedByteAsString.class);
        addAnnotatedClass(EncryptedCalendarAsString.class);
        addAnnotatedClass(EncryptedDateAsString.class);
        addAnnotatedClass(EncryptedDoubleAsString.class);
        addAnnotatedClass(EncryptedDoubleAsString.class);
        addAnnotatedClass(EncryptedFloatAsString.class);
        addAnnotatedClass(EncryptedIntegerAsString.class);
        addAnnotatedClass(EncryptedLongAsString.class);
        addAnnotatedClass(EncryptedShortAsString.class);
        addAnnotatedClass(EncryptedString.class);
    }

    private void storeDecrypted(String propertyName, Properties props) {
        final String encryptorRegisteredName = props.getProperty(ParameterNaming.ENCRYPTOR_REGISTERED_NAME);
        final HibernatePBEEncryptorRegistry encryptorRegistry =
                HibernatePBEEncryptorRegistry.getInstance();
        final PBEStringEncryptor encryptor = encryptorRegistry.getPBEStringEncryptor(encryptorRegisteredName);

        String value = props.getProperty(propertyName);

        if (PropertyValueEncryptionUtils.isEncryptedValue(value)) {
            if (encryptor == null) {
                throw new EncryptionInitializationException(
                        "No string encryptor registered for hibernate " +
                                "with name \"" + encryptorRegisteredName + "\"");
            } else {
                props.setProperty(propertyName, PropertyValueEncryptionUtils.decrypt(value, encryptor));
            }
        }
    }

    public void configure(final Configuration configuration) {

        // verify if any of the provided properties are encrypted, and decrypt them for hibernate if needed
        final Properties props = configuration.getProperties();

        // attempt to decrypt config values
        storeDecrypted(JAKARTA_JDBC_DRIVER, props);
        storeDecrypted(JAKARTA_JDBC_URL, props);
        storeDecrypted(JAKARTA_JDBC_USER, props);
        storeDecrypted(JAKARTA_JDBC_PASSWORD, props);
    }

}
