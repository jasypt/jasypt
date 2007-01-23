package org.jasypt.hibernate.config;

import org.jasypt.encryption.pbe.config.PBEConfig;

public abstract class HibernatePBEConfig implements PBEConfig {

    private String name = null;
    
    public final synchronized void setName(String name) {
        if (this.name != null) {
            HibernatePBEConfigRegistry.getInstance().
                    unregisterPBEConfig(this.name);
        }
        this.name = name;
        HibernatePBEConfigRegistry.getInstance().
                registerHibernatePBEConfig(this);
    }
    
    public final String getName() {
        return name;
    }
    
}
