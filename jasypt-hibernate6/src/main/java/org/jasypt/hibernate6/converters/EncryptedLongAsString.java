package org.jasypt.hibernate6.converters;

public class EncryptedLongAsString extends AbstractEncryptedAsString {

    @Override
    protected Object convertToObject(String string) {
        return Long.valueOf(string);
    }

    @Override
    protected String convertToString(Object object) {
        return object.toString();
    }

}
