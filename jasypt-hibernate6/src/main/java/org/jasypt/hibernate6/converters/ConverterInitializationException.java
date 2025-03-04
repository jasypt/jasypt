package org.jasypt.hibernate6.converters;

public class ConverterInitializationException extends RuntimeException {

    public ConverterInitializationException() {
    }

    public ConverterInitializationException(Throwable t) {
        super(t);
    }

    public ConverterInitializationException(String msg, Throwable t) {
        super(msg, t);
    }

    public ConverterInitializationException(String msg) {
        super(msg);
    }

}
