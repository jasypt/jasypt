package org.jasypt.hibernate6.converters;

import org.jasypt.exceptions.EncryptionInitializationException;

import java.util.HashMap;
import java.util.Map;
import java.util.Properties;

public class ConverterConfig {

    private static final Map<String, Class<?>> PROPERTIES_MAPPING = new HashMap<>();

    static {
        PROPERTIES_MAPPING.put(ParameterNaming.ENCRYPTOR_NAME, String.class);
        PROPERTIES_MAPPING.put(ParameterNaming.ALGORITHM, String.class);
        PROPERTIES_MAPPING.put(ParameterNaming.PROVIDER_NAME, String.class);
        PROPERTIES_MAPPING.put(ParameterNaming.PASSWORD, String.class);
        PROPERTIES_MAPPING.put(ParameterNaming.KEY_OBTENTION_ITERATIONS, Integer.class);
        PROPERTIES_MAPPING.put(ParameterNaming.STRING_OUTPUT_TYPE, String.class);
        PROPERTIES_MAPPING.put(ParameterNaming.DECIMAL_SCALE, Integer.class);
        PROPERTIES_MAPPING.put(ParameterNaming.STORE_TIME_ZONE, Boolean.class);
    }

    private final Map<String, Object> mappedProperties = new HashMap<>();

    protected boolean useEncryptorName = false;

    public ConverterConfig(Properties properties) {
        for (String propertyName : properties.stringPropertyNames()) {
            Class<?> propertyClass = PROPERTIES_MAPPING.get(propertyName);

            try {
                switch (propertyClass.getName()) {
                    case "java.lang.String":
                    case "java.lang.Character":
                        mappedProperties.put(propertyName, properties.getProperty(propertyName));
                        break;
                    case "java.lang.Integer":
                        mappedProperties.put(propertyName, Integer.valueOf(properties.getProperty(propertyName)));
                        break;
                    case "java.lang.Long":
                        mappedProperties.put(propertyName, Long.valueOf(properties.getProperty(propertyName)));
                        break;
                    case "java.lang.Float":
                        mappedProperties.put(propertyName, Float.valueOf(properties.getProperty(propertyName)));
                        break;
                    case "java.lang.Double":
                        mappedProperties.put(propertyName, Double.valueOf(properties.getProperty(propertyName)));
                        break;
                    case "java.lang.Boolean":
                        mappedProperties.put(propertyName, Boolean.valueOf(properties.getProperty(propertyName)));
                        break;
                    case "java.lang.Byte":
                        mappedProperties.put(propertyName, Byte.valueOf(properties.getProperty(propertyName)));
                        break;
                    case "java.lang.Short":
                        mappedProperties.put(propertyName, Short.valueOf(properties.getProperty(propertyName)));
                        break;

                }
            } catch (Exception e) {
                throw new EncryptionInitializationException("Failed to convert property " + propertyName, e);
            }
        }

        useEncryptorName = false;
        if (mappedProperties.get(ParameterNaming.ENCRYPTOR_NAME) != null) {
            if ((mappedProperties.get(ParameterNaming.ALGORITHM) != null) ||
                    (mappedProperties.get(ParameterNaming.PASSWORD) != null) ||
                    (mappedProperties.get(ParameterNaming.KEY_OBTENTION_ITERATIONS) != null)) {

                throw new EncryptionInitializationException(
                        "If \"" + ParameterNaming.ENCRYPTOR_NAME +
                                "\" is specified, none of \"" +
                                ParameterNaming.ALGORITHM + "\", \"" +
                                ParameterNaming.PASSWORD + "\" or \"" +
                                ParameterNaming.KEY_OBTENTION_ITERATIONS + "\" " +
                                "can be specified");
            }
            this.useEncryptorName = true;
        } else if (mappedProperties.get(ParameterNaming.PASSWORD) == null) {

            throw new EncryptionInitializationException(
                    "If \"" + ParameterNaming.ENCRYPTOR_NAME +
                            "\" is not specified, then \"" +
                            ParameterNaming.PASSWORD + "\" (and optionally \"" +
                            ParameterNaming.ALGORITHM + "\" and \"" +
                            ParameterNaming.KEY_OBTENTION_ITERATIONS + "\") " +
                            "must be specified");
        }
    }

    public <T> T getProperty (String propertyName) {
        return (T)mappedProperties.get(propertyName);
    }

}
