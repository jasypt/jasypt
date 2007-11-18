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
package org.jasypt.intf.cli;

import java.util.Properties;

import org.apache.commons.lang.ArrayUtils;
import org.jasypt.digest.StandardStringDigester;
import org.jasypt.digest.config.SimpleStringDigesterConfig;

public class JasyptStringDigestCLI {
    
    private static final String[] VALID_REQUIRED_ARGUMENTS =
        new String[] {
            ArgumentNaming.ARG_INPUT
        };
    
    private static final String[] VALID_OPTIONAL_ARGUMENTS =
        new String[] {
            ArgumentNaming.ARG_ALGORITHM,
            ArgumentNaming.ARG_ITERATIONS,
            ArgumentNaming.ARG_SALT_SIZE_BYTES,
            ArgumentNaming.ARG_SALT_GENERATOR_CLASS_NAME,
            ArgumentNaming.ARG_PROVIDER_NAME,
            ArgumentNaming.ARG_PROVIDER_CLASS_NAME,
            ArgumentNaming.ARG_UNICODE_NORMALIZATION_IGNORED,
            ArgumentNaming.ARG_STRING_OUTPUT_TYPE
        };
    
    
    public static void main(String[] args) {
        
        String applicationName = null;
        String[] arguments = null;
        if (args[0] == null || args[0].indexOf("=") != -1) {
            applicationName = JasyptStringDigestCLI.class.getName();
            arguments = args;
        } else {
            applicationName = args[0];
            arguments = (String[]) ArrayUtils.subarray(args, 1, args.length);
        }
        
        Properties argumentValues = 
            ArgumentUtils.getArgumentValues(
                    arguments, applicationName, 
                    VALID_REQUIRED_ARGUMENTS, VALID_OPTIONAL_ARGUMENTS);

        SimpleStringDigesterConfig config = new SimpleStringDigesterConfig();
        config.setAlgorithm(ArgumentUtils.getAlgorithm(argumentValues));
        config.setIterations(ArgumentUtils.getIterations(argumentValues));
        config.setSaltSizeBytes(ArgumentUtils.getSaltSizeBytes(argumentValues));
        config.setSaltGenerator(ArgumentUtils.getSaltGenerator(argumentValues));
        config.setProviderName(ArgumentUtils.getProviderName(argumentValues));
        config.setProvider(ArgumentUtils.getProvider(argumentValues));
        config.setUnicodeNormalizationIgnored(
                ArgumentUtils.getUnicodeNormalizationIgnored(argumentValues));
        config.setStringOutputType(
                ArgumentUtils.getStringOutputType(argumentValues));

        String input = ArgumentUtils.getInput(argumentValues);

        ArgumentUtils.showArgumentDescription(argumentValues);
        
        StandardStringDigester digester = new StandardStringDigester();
        digester.setConfig(config);
        
        ArgumentUtils.showOutput(digester.digest(input));
        
    }
    
    
    
    
    private JasyptStringDigestCLI() {
        super();
    }
    
}
