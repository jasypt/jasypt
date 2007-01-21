package org.jasypt.exceptions;

import org.apache.commons.lang.exception.NestableRuntimeException;

public class AlreadyInitializedException extends NestableRuntimeException {
    
    private static final long serialVersionUID = 4592515503937873874L;

    public AlreadyInitializedException() {
        super("Encryption entity already initialized");
    }

}
