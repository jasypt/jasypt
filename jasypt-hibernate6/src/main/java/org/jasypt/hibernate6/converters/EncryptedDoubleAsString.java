package org.jasypt.hibernate6.converters;

public class EncryptedDoubleAsString extends AbstractEncryptedAsString {

    @Override
    protected Object convertToObject(String string) {
        return Double.parseDouble(string);
    }

    @Override
    protected String convertToString(Object object) {
        return object.toString();
    }

}
