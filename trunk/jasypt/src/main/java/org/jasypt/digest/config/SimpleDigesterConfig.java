package org.jasypt.digest.config;

public class SimpleDigesterConfig 
        implements DigesterConfig {

    private String algorithm = null;
    private Integer iterations = null;
    private Integer saltSizeBytes = null; 
    

    
    public SimpleDigesterConfig() {
    }
    
    public SimpleDigesterConfig(
            DigesterConfig source) {
        this.algorithm = source.getAlgorithm();
        this.iterations = source.getIterations();
        this.saltSizeBytes = source.getSaltSizeBytes();
    }
    
        
    public void setAlgorithm(String algorithm) {
        this.algorithm = algorithm;
    }

    public void setIterations(Integer iterations) {
        this.iterations = iterations;
    }

    public void setSaltSizeBytes(Integer saltSizeBytes) {
        this.saltSizeBytes = saltSizeBytes;
    }

    public String getAlgorithm() {
        return algorithm;
    }

    public Integer getIterations() {
        return iterations;
    }

    public Integer getSaltSizeBytes() {
        return saltSizeBytes;
    }

    
}
