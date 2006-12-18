package org.jasypt.digest;

public interface ByteDigester {

    public byte[] digest(byte[] message);
    
    public boolean matches(byte[] message, byte[] digest);

}
