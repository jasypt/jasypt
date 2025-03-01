package org.jasypt.hibernate6.converters;

public class EncryptedByteAsString extends AbstractEncryptedAsString {

    @Override
    protected Object convertToObject(String string) {
        return Byte.valueOf(string);
    }

    @Override
    protected String convertToString(Object object) {
        return object.toString();
    }

}
