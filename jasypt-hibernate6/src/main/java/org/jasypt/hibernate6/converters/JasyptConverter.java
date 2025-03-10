package org.jasypt.hibernate6.converters;

import jakarta.persistence.AttributeConverter;

public abstract class JasyptConverter<T, E> implements AttributeConverter<T, E> {
    
    protected boolean initialized = false;
    
    abstract void checkInitialized();
    
}
