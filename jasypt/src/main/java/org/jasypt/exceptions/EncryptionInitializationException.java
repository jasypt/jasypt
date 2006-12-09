package org.jasypt.exceptions;

import org.apache.commons.lang.exception.NestableRuntimeException;

public class EncryptionInitializationException 
        extends NestableRuntimeException {
    
    private static final long serialVersionUID = 8929638240023639778L;

    public EncryptionInitializationException() {
        super();
    }

    public EncryptionInitializationException(Throwable t) {
        super(t);
    }
    
    public EncryptionInitializationException(String msg, Throwable t) {
        super(msg, t);
    }
    
    public EncryptionInitializationException(String msg) {
        super(msg);
    }

}
