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

import org.jasypt.encryption.pbe.config.PBEConfig;

public abstract class AbstractHibernatePBEConfig implements PBEConfig {

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
