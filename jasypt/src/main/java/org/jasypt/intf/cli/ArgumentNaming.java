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
package org.jasypt.intf.cli;


/*
 * Internal class for holding the names of the CLI parameters. These
 * can be both direct and environment variable names. 
 */
final class ArgumentNaming {

    
    static final String ARG_VERBOSE = "verbose";
    
    static final String ARG_INPUT = "input";
    
    static final String ARG_PASSWORD = "password";
    
    static final String ARG_ALGORITHM = "algorithm";
    
    static final String ARG_ITERATIONS = "iterations";
    
    static final String ARG_KEY_OBTENTION_ITERATIONS = 
        "keyObtentionIterations";
    
    static final String ARG_SALT_SIZE_BYTES = "saltSizeBytes";
    
    static final String ARG_SALT_GENERATOR_CLASS_NAME = 
        "saltGeneratorClassName";
    
    static final String ARG_PROVIDER_CLASS_NAME = "providerClassName";
    
    static final String ARG_PROVIDER_NAME = "providerName";
    
    static final String ARG_INVERT_POSITION_OF_SALT_IN_MESSAGE_BEFORE_DIGESTING =
        "invertPositionOfSaltInMessageBeforeDigesting";
    
    static final String ARG_INVERT_POSITION_OF_PLAIN_SALT_IN_ENCRYPTION_RESULTS =
        "invertPositionOfPlainSaltInEncryptionResults";

    static final String ARG_USE_LENIENT_SALT_SIZE_CHECK =
        "useLenientSaltSizeCheck";
    
    static final String ARG_UNICODE_NORMALIZATION_IGNORED = 
        "unicodeNormalizationIgnored";
    
    static final String ARG_STRING_OUTPUT_TYPE = 
        "stringOutputType";
    
    static final String ARG_PREFIX = "prefix";
    
    static final String ARG_SUFFIX = "suffix";

    
    
    // Instantiation is not allowed
    private ArgumentNaming() {
        super();
    }
    
}
