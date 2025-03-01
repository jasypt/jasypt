package org.jasypt.hibernate6.converters;

import java.math.BigInteger;

public class EncryptedBigIntegerAsString extends AbstractEncryptedAsString {

    @Override
    protected Object convertToObject(String string) {
        return new BigInteger(string);
    }

    @Override
    protected String convertToString(Object object) {
        return object.toString();
    }

}
