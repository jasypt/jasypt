package org.jasypt.hibernate6.converters;

public class EncryptedShortAsString extends AbstractEncryptedAsString {

    @Override
    protected Object convertToObject(String string) {
        return Short.parseShort(string);
    }

    @Override
    protected String convertToString(Object object) {
        return object.toString();
    }

}
