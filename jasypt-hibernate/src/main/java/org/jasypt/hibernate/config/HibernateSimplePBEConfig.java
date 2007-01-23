package org.jasypt.hibernate.config;

public class HibernateSimplePBEConfig extends HibernatePBEConfig {

    private String algorithm = null;
    private String password = null;
    private Integer keyObtentionIterations = null;
    
    
    public void setAlgorithm(String algorithm) {
        this.algorithm = algorithm;
    }
    
    public void setPassword(String password) {
        this.password = password;
    }

    public void setKeyObtentionIterations(int keyObtentionIterations) {
        this.keyObtentionIterations = new Integer(keyObtentionIterations);
    }
    
    public String getAlgorithm() {
        return algorithm;
    }

    public String getPassword() {
        return password;
    }

    public Integer getKeyObtentionIterations() {
        return keyObtentionIterations;
    }

    
}
