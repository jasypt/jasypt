package org.jasypt.hibernate6.converters;

public class EncryptedString extends AbstractEncryptedAsString {

    @Override
    protected Object convertToObject(String string) {
        return string;
    }

    @Override
    protected String convertToString(Object object) {
        return object.toString();
    }
}
