package org.jasypt.hibernate.config;

import java.util.HashMap;

import org.jasypt.encryption.pbe.config.PBEConfig;

public class HibernatePBEConfigRegistry {

    
    private static HibernatePBEConfigRegistry instance = 
        new HibernatePBEConfigRegistry();
    
    
    private HashMap configs = new HashMap();
    
    
    public static HibernatePBEConfigRegistry getInstance() {
        return instance;
    }
    
    private HibernatePBEConfigRegistry() { }
 

    public synchronized void registerHibernatePBEConfig(
            HibernatePBEConfig config) {
        this.configs.put(config.getName(), config);
    }

    public synchronized void registerPBEConfig(String name, PBEConfig config) {
        if (config instanceof HibernatePBEConfig) {
            ((HibernatePBEConfig) config).setName(name);
        } else {
            this.configs.put(name, config);
        }
    }
    
    synchronized void unregisterPBEConfig(String name) {
        this.configs.remove(name);
    }
    
    public synchronized PBEConfig getPBEConfig(String name) {
        return (PBEConfig) configs.get(name);
    }
    
}
