package org.jasypt.hibernate6.converters;

public class EncryptedFloatAsString extends AbstractEncryptedAsString {

    @Override
    protected Object convertToObject(String string) {
        return Float.parseFloat(string);
    }

    @Override
    protected String convertToString(Object object) {
        return object.toString();
    }

}
