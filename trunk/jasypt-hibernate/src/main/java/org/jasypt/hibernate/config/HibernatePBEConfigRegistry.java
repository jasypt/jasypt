/*
 * =============================================================================
 * 
 *   Copyright (c) 2007, The JASYPT team (http://www.jasypt.org)
 * 
 *   Licensed under the Apache License, Version 2.0 (the "License");
 *   you may not use this file except in compliance with the License.
 *   You may obtain a copy of the License at
 * 
 *       http://www.apache.org/licenses/LICENSE-2.0
 * 
 *   Unless required by applicable law or agreed to in writing, software
 *   distributed under the License is distributed on an "AS IS" BASIS,
 *   WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 *   See the License for the specific language governing permissions and
 *   limitations under the License.
 * 
 * =============================================================================
 */
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
