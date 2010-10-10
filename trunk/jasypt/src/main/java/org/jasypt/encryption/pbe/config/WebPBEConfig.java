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
package org.jasypt.encryption.pbe.config;

import org.jasypt.commons.CommonUtils;
import org.jasypt.web.pbeconfig.WebPBEConfigRegistry;

/**
 * <p>
 * Implementation for {@link PBEConfig} which can be used from the
 * Web PBE Config infrastructure (Filter + Servlet) to set the
 * password for an encryptor from the web at initialization time.
 * </p>
 * <p>
 * For an encryptor to be assigned a password from the web, it only has
 * to be assigned a WebPBEConfig object, which must be initialized with
 * <b>both</b> a unique name an a validation word. The name will identify
 * the config object (and thus the encryptor) and the validation word will
 * make sure that only an authorized person (for example, the application
 * deployer) sets the passwords.
 * </p>
 * <p>
 * As this class extends {@link SimplePBEConfig}, parameter values
 * can be also set with the usual <tt>setX</tt> methods.
 * </p>
 * <p>
 * For any of the configuration parameters, if its <tt>setX</tt>
 * method is not called, a <tt>null</tt> value will be returned by the
 * corresponding <tt>getX</tt> method. 
 * </p>
 * 
 * @since 1.3
 * 
 * @author Daniel Fern&aacute;ndez
 * 
 */
public class WebPBEConfig extends SimplePBEConfig {

    private String name = null;
    private String validationWord = null;
    
    
    /**
     * <p>
     * Creates a new <tt>WebPBEConfig</tt> instance.
     * </p>
     */
    public WebPBEConfig() {
        super();
        WebPBEConfigRegistry registry = 
            WebPBEConfigRegistry.getInstance();
        registry.registerConfig(this);
    }

    /**
     * <p>
     * Returns the name by which this WebPBEConfig object will be identified
     * from the web. This name must be unique for each WebPBEConfig object.
     * </p>
     * 
     * @return the config name.
     */
    public String getName() {
        return this.name;
    }


    /**
     * <p>
     * Sets the name by which this WebPBEConfig object will be identified
     * from the web. This name must be unique for each WebPBEConfig object.
     * </p>
     * 
     * @param name the unique name which will identify this config object.
     */
    public void setName(String name) {
        CommonUtils.validateNotEmpty(name, "Name cannot be set empty");
        this.name = name;
    }


    /**
     * <p>
     * Returns the validation word which will be asked from the web to the
     * person setting the password for the encryptor this config object belongs
     * to. This validation word will make sure that only an authorized person
     * (for example, the application deployer) sets the value for the
     * encryption password.
     * </p>
     * 
     * @return the validation word assigned to this config object
     */
    public String getValidationWord() {
        return this.validationWord;
    }


    /**
     * <p>
     * Sets the validation word which will be asked from the web to the
     * person setting the password for the encryptor this config object belongs
     * to. This validation word will make sure that only an authorized person
     * (for example, the application deployer) sets the value for the
     * encryption password.
     * </p>
     * 
     * @param validation the validation word to be assigned to this config object
     */
    public void setValidationWord(String validation) {
        CommonUtils.validateNotEmpty(validation, "Validation word cannot be set empty");
        this.validationWord = validation;
    }
    
    
    /**
     * <p>
     * Returns whether this config object is complete or not (both name and
     * validation word have been set). <b>Intended for internal use only</b>.
     * </p>
     * 
     * @return whether the config object is complete or not.
     */
    public boolean isComplete() {
        return ((CommonUtils.isNotEmpty(this.name)) && 
                (CommonUtils.isNotEmpty(this.validationWord)));
    }

}
