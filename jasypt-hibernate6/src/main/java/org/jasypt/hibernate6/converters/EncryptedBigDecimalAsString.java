package org.jasypt.hibernate6.converters;

import java.math.BigDecimal;

public class EncryptedBigDecimalAsString extends AbstractEncryptedAsString {

    @Override
    protected Object convertToObject(String string) {
        return new BigDecimal(string);
    }

    @Override
    protected String convertToString(Object object) {
        return object.toString();
    }
}
