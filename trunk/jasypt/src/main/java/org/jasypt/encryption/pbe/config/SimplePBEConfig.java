package org.jasypt.encryption.pbe.config;

public class SimplePBEConfig 
        implements PBEConfig {

    private String password = null;
    private Integer iterations = null;
    

    
    public SimplePBEConfig() {
    }
    
    public SimplePBEConfig(
            PBEConfig source) {
        this.password = source.getPassword();
        this.iterations = source.getIterations();
    }
    
        
    public void setPassword(String password) {
        this.password = password;
    }

    public void setIterations(Integer iterations) {
        this.iterations = iterations;
    }

    public String getPassword() {
        return password;
    }

    public Integer getIterations() {
        return iterations;
    }

    
}
