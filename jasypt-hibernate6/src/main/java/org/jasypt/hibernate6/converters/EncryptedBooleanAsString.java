package org.jasypt.hibernate6.converters;

public class EncryptedBooleanAsString extends AbstractEncryptedAsString {

    @Override
    protected Object convertToObject(String string) {
        return Boolean.parseBoolean(string);
    }

    @Override
    protected String convertToString(Object object) {
        return object.toString();
    }

}
