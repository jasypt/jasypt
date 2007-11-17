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
package org.jasypt.cli;

import java.util.Properties;

import org.jasypt.encryption.pbe.StandardPBEStringEncryptor;
import org.jasypt.encryption.pbe.config.SimpleStringPBEConfig;

public class JasyptPBEStringDecryptionCLI {
    
    private static final String[] VALID_REQUIRED_ARGUMENTS =
        new String[] {
            ArgumentNaming.ARG_INPUT,
            ArgumentNaming.ARG_PASSWORD
        };
    
    private static final String[] VALID_OPTIONAL_ARGUMENTS =
        new String[] {
            ArgumentNaming.ARG_ALGORITHM,
            ArgumentNaming.ARG_KEY_OBTENTION_ITERATIONS,
            ArgumentNaming.ARG_SALT_GENERATOR_CLASS_NAME,
            ArgumentNaming.ARG_PROVIDER_NAME,
            ArgumentNaming.ARG_PROVIDER_CLASS_NAME,
            ArgumentNaming.ARG_STRING_OUTPUT_TYPE
        };
    
    
    public static void main(String[] args) {

        Properties argumentValues = 
            ArgumentUtils.getArgumentValues(
                    args, args[0], 
                    VALID_REQUIRED_ARGUMENTS, VALID_OPTIONAL_ARGUMENTS);

        SimpleStringPBEConfig config = new SimpleStringPBEConfig();
        config.setAlgorithm(ArgumentUtils.getAlgorithm(argumentValues));
        config.setKeyObtentionIterations(
                ArgumentUtils.getKeyObtentionIterations(argumentValues));
        config.setSaltGenerator(ArgumentUtils.getSaltGenerator(argumentValues));
        config.setProviderName(ArgumentUtils.getProviderName(argumentValues));
        config.setProvider(ArgumentUtils.getProvider(argumentValues));
        config.setStringOutputType(
                ArgumentUtils.getStringOutputType(argumentValues));
        config.setPassword(ArgumentUtils.getPassword(argumentValues));

        String input = ArgumentUtils.getInput(argumentValues);

        ArgumentUtils.showArgumentDescription(argumentValues);
        
        StandardPBEStringEncryptor encryptor = new StandardPBEStringEncryptor();
        encryptor.setConfig(config);
        
        ArgumentUtils.showOutput(encryptor.decrypt(input));
        
    }
    
    
    
    
    private JasyptPBEStringDecryptionCLI() {
        super();
    }
    
}
