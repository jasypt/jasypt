package org.jasypt.digest;

public interface StringDigester {
    
    public String digest(String message);
    
    public boolean matches(String message, String digest);

}
