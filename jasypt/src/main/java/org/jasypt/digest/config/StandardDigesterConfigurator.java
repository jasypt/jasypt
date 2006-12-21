package org.jasypt.digest.config;

public interface StandardDigesterConfigurator {

    public String getAlgorithm();
    
    public Integer getSaltSizeBytes();
    
    public Integer getIterations();
    
}
