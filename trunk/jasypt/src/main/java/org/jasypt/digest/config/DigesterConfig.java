package org.jasypt.digest.config;

public interface DigesterConfig {

    public String getAlgorithm();
    
    public Integer getSaltSizeBytes();
    
    public Integer getIterations();
    
}
