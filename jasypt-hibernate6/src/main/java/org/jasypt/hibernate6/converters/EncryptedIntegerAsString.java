package org.jasypt.hibernate6.converters;

public class EncryptedIntegerAsString extends AbstractEncryptedAsString {

    @Override
    protected Object convertToObject(String string) {
        return Integer.valueOf(string);
    }

    @Override
    protected String convertToString(Object object) {
        return object.toString();
    }

}
