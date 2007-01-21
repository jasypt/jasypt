package org.jasypt.digest.config;

public interface DigesterConfig {

    /* 
     * FOR DOC: If these are null, the current object values are respected 
     */
    
    public String getAlgorithm();
    
    public Integer getSaltSizeBytes();
    
    public Integer getIterations();
    
}
