/*
 * =============================================================================
 * 
 *   Copyright (c) 2007-2008, The JASYPT team (http://www.jasypt.org)
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
package org.jasypt.web.pbeconfig;

import java.util.ArrayList;
import java.util.Collections;
import java.util.HashSet;
import java.util.List;
import java.util.Set;

import org.jasypt.encryption.pbe.config.WebPBEConfig;
import org.jasypt.exceptions.EncryptionInitializationException;

/**
 * <p>
 *   Registry for {@link WebPBEConfig} objects. <b>This class is intended
 *   for internal use only, and should not be accessed from the user's
 *   code.</b>
 * </p> 
 * 
 * @since 1.3
 * 
 * @author Daniel Fern&aacute;ndez
 *
 */
public class WebPBEConfigRegistry {

    private Set names = new HashSet();
    private List configs = new ArrayList();
    private boolean webConfigurationDone = false;
    
    private static final WebPBEConfigRegistry instance = 
        new WebPBEConfigRegistry();
    
    
    public static WebPBEConfigRegistry getInstance() {
        return instance;
    }
    
    private WebPBEConfigRegistry() {
        super();
    }
    
    
    public synchronized void registerConfig(WebPBEConfig config) {
        if (this.webConfigurationDone) {
            throw new EncryptionInitializationException(
                    "Cannot register: Web configuration is already done");
        }
        // Avoid duplication of encryptors because of the initialization
        // class being called more than once.
        if (!this.names.contains(config.getName())) {
            this.configs.add(config);
            this.names.add(config);
        }
    }
    
    public synchronized List getConfigs() {
        return Collections.unmodifiableList(this.configs);
    }

    public boolean isWebConfigurationDone() {
        return (this.webConfigurationDone || (this.configs.size() == 0));
    }

    public void setWebConfigurationDone(boolean configurationDone) {
        this.webConfigurationDone = configurationDone;
    }
    
}
