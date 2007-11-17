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

import java.security.Provider;
import java.util.Arrays;
import java.util.HashSet;
import java.util.Iterator;
import java.util.Map;
import java.util.Properties;
import java.util.Set;

import org.apache.commons.lang.ArrayUtils;
import org.apache.commons.lang.StringUtils;
import org.jasypt.commons.CommonUtils;
import org.jasypt.exceptions.EncryptionInitializationException;
import org.jasypt.salt.SaltGenerator;

class ArgumentUtils {

    
    static String getPassword(Properties argumentValues) {
        return argumentValues.getProperty(ArgumentNaming.ARG_PASSWORD);
    }

    
    static String getAlgorithm(Properties argumentValues) {
        return argumentValues.getProperty(ArgumentNaming.ARG_ALGORITHM);
    }
    
    
    static Integer getIterations(Properties argumentValues) {
        String iterations = 
            argumentValues.getProperty(ArgumentNaming.ARG_ITERATIONS);
        if (iterations != null) {
            return new Integer(iterations);
        }
        return null;
    }
    
    
    static Integer getKeyObtentionIterations(Properties argumentValues) {
        String keyObtentionIterations = 
            argumentValues.getProperty(
                    ArgumentNaming.ARG_KEY_OBTENTION_ITERATIONS);
        if (keyObtentionIterations != null) {
            return new Integer(keyObtentionIterations);
        }
        return null;
    }
    
    
    static Integer getSaltSizeBytes(Properties argumentValues) {
        String saltSizeBytes = 
            argumentValues.getProperty(ArgumentNaming.ARG_SALT_SIZE_BYTES);
        if (saltSizeBytes != null) {
            return new Integer(saltSizeBytes);
        }
        return null;
    }
    
    
    static SaltGenerator getSaltGenerator(Properties argumentValues) {
        String saltGeneratorClassName = 
            argumentValues.getProperty(
                    ArgumentNaming.ARG_SALT_GENERATOR_CLASS_NAME);
        if (saltGeneratorClassName != null) {
            try {
                Class saltGeneratorClass = 
                    Class.forName(saltGeneratorClassName);
                SaltGenerator saltGenerator = 
                    (SaltGenerator) saltGeneratorClass.newInstance();
                return saltGenerator;
            } catch (Exception e) {
                throw new EncryptionInitializationException(e);
            }
        }
        return null;
    }

    
    static String getProviderName(Properties argumentValues) {
        String providerName = 
            argumentValues.getProperty(ArgumentNaming.ARG_PROVIDER_NAME);
        if (providerName != null) {
            return providerName;
        }
        return null;
    }
    

    static Provider getProvider(Properties argumentValues) {
        String providerClassName = 
            argumentValues.getProperty(ArgumentNaming.ARG_PROVIDER_CLASS_NAME);
        if (providerClassName != null) {
            try {
                Class providerClass = Class.forName(providerClassName);
                Provider provider = (Provider) providerClass.newInstance();
                return provider;
            } catch (Exception e) {
                throw new EncryptionInitializationException(e);
            }
        }
        return null;
    }
    
    
    static Boolean getUnicodeNormalizationIgnored(Properties argumentValues) {
        String unicodeNormalizationIgnored = 
            argumentValues.getProperty(
                    ArgumentNaming.ARG_UNICODE_NORMALIZATION_IGNORED);
        if (unicodeNormalizationIgnored != null) {
            return CommonUtils.getStandardBooleanValue(
                    unicodeNormalizationIgnored);
        }
        return null;
    }
    
    
    static String getStringOutputType(Properties argumentValues) {
        String stringOutputType =
            argumentValues.getProperty(ArgumentNaming.ARG_STRING_OUTPUT_TYPE);
        if (stringOutputType != null) {
            return CommonUtils.getStandardStringOutputType(stringOutputType);
        }
        return null;
    }
    
    
    static String getInput(Properties argumentValues) {
        // Cannot be null (checked in getArgumentValues)
        return argumentValues.getProperty(ArgumentNaming.ARG_INPUT);
    }

    
    static void showArgumentDescription(Properties argumentValues) {
        
        System.out.println("ARGUMENTS:");
        Iterator entriesIter = argumentValues.entrySet().iterator();
        while (entriesIter.hasNext()) {
            Map.Entry entry = (Map.Entry) entriesIter.next();
            System.out.println("  " + entry.getKey() + "=" + entry.getValue());
        }
        System.out.println("--------------------------------");
        
    }
    
    
    static void showOutput(String output) {
        
        System.out.println("OUTPUT: " + output);
        System.out.println("--------------------------------");
        
    }

    
    static Properties getArgumentValues(String[] args, String appName, 
            String[] requiredArgNames, String[] optionalArgNames) {
        
        Set argNames = new HashSet(
                    Arrays.asList(ArrayUtils.addAll(
                            requiredArgNames, optionalArgNames)));
        Properties argumentValues = new Properties();
        for (int i = 1; i < args.length; i++) {
            String key = StringUtils.substringBefore(args[i], "=");
            String value = StringUtils.substringAfter(args[i], "=");
            if (StringUtils.isEmpty(key) || StringUtils.isEmpty(value)) {
                throw new IllegalArgumentException("Bad argument: " + args[i]);
            }
            if (argNames.contains(key)) {
                argumentValues.setProperty(key, value);
            }
        }
        
        //Check for all required arguments
        for (int i = 0; i < requiredArgNames.length; i++) {
            if (!argumentValues.containsKey(requiredArgNames[i])) {
                showUsageAndExit(appName, requiredArgNames, optionalArgNames);
            }
        }
        return argumentValues;
        
    }
    
    
    static void showUsageAndExit(String appName,
            String[] requiredArgNames, String[] optionalArgNames) {
        
        System.err.println("USAGE: " + appName + " [ARGUMENTS]");
        System.err.print("  * Arguments must apply to format: ");
        System.err.println("\"arg1=value1 arg2=value2 arg3=value3 ...\"");
        System.err.println("  * Required arguments:");
        for (int i = 0; i < requiredArgNames.length; i++) {
            System.err.println("      " + requiredArgNames[i]);
        }
        System.err.println("  * Optional arguments:");
        for (int i = 0; i < optionalArgNames.length; i++) {
            System.err.println("      " + optionalArgNames[i]);
        }
        System.exit(1);
        
    }
    
    
    
    private ArgumentUtils() {
        super();
    }
    
}
