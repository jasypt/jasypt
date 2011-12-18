/*
 * =============================================================================
 * 
 *   Copyright (c) 2007-2010, The JASYPT team (http://www.jasypt.org)
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
package org.jasypt.spring3.configuration;

/**
 * 
 * @author Soraya S&aacute;nchez
 *
 */
public class ConfigurationProperties {
    
    private String location;
    
    private String locatinPlainValue;
    
    private String locationEncryptedValue;
    

    public ConfigurationProperties() {
        super();
    }

    public String getLocation() {
        return location;
    }

    public void setLocation(String location) {
        this.location = location;
    }

    public String getLocatinPlainValue() {
        return locatinPlainValue;
    }

    public void setLocationPlainValue(String locatinPlainValue) {
        this.locatinPlainValue = locatinPlainValue;
    }

    public String getLocationEncryptedValue() {
        return locationEncryptedValue;
    }

    public void setLocationEncryptedValue(String locatinEncryptedValue) {
        this.locationEncryptedValue = locatinEncryptedValue;
    }
   
}
