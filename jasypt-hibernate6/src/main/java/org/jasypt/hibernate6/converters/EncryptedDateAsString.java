package org.jasypt.hibernate6.converters;

import java.util.Date;

public class EncryptedDateAsString extends AbstractEncryptedAsString {

    @Override
    protected Object convertToObject(String string) {
        final long timeMillis = Long.parseLong(string);
        return new Date(timeMillis);
    }

    @Override
    protected String convertToString(Object object) {
        final long timeMillis = ((Date) object).getTime();
        return String.valueOf(timeMillis);
    }
    
}
