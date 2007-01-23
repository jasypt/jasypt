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
