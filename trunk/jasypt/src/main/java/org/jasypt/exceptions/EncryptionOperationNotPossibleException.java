package org.jasypt.exceptions;

import org.apache.commons.lang.exception.NestableRuntimeException;

public class EncryptionOperationNotPossibleException 
        extends NestableRuntimeException {

    private static final long serialVersionUID = 6304674109588715145L;

    public EncryptionOperationNotPossibleException() {
        super();
    }

    public EncryptionOperationNotPossibleException(Throwable t) {
        super(t);
    }
    
}
