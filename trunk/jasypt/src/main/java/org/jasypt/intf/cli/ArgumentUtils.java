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

import java.util.Arrays;
import java.util.HashSet;
import java.util.Iterator;
import java.util.Map;
import java.util.Properties;
import java.util.Set;

import org.apache.commons.lang.BooleanUtils;
import org.apache.commons.lang.StringUtils;
import org.jasypt.exceptions.EncryptionOperationNotPossibleException;

class ArgumentUtils {

    
    static void showEnvironment(boolean verbose) {
        
        if (verbose) {
            System.out.println("\n----ENVIRONMENT-----------------\n");
            System.out.println("Runtime: " + 
                    System.getProperty("java.vm.vendor") + " " + 
                    System.getProperty("java.vm.name") + " " +
                    System.getProperty("java.vm.version") + " " +
                    "(Java version: " + 
                    System.getProperty("java.vm.specification.version") + 
                    ")");
            System.out.println("\n");
        }
        
    }
    
    
    static void showArgumentDescription(Properties argumentValues, 
            boolean verbose) {
        
        if (verbose) {
            System.out.println("\n----ARGUMENTS-------------------\n");
            Iterator entriesIter = argumentValues.entrySet().iterator();
            while (entriesIter.hasNext()) {
                Map.Entry entry = (Map.Entry) entriesIter.next();
                System.out.println(
                        entry.getKey() + ": " + entry.getValue());
            }
            System.out.println("\n");
        }
        
    }
    
    
    static void showOutput(String output, boolean verbose) {

        if (verbose) {
            System.out.println("\n----OUTPUT----------------------\n");
            System.out.println(output);
            System.out.println("\n");
        } else {
            System.out.println(output);
        }
        
    }

    
    static void showError(Throwable t, boolean verbose) {

        if (verbose) {

            System.err.println("\n----ERROR-----------------------\n");
            if (t instanceof EncryptionOperationNotPossibleException) {
                System.err.println(
                        "Operation not possible (Bad input or parameters)");
            } else {
                if (t.getMessage() != null) {
                    System.err.println(t.getMessage());
                } else {
                    System.err.println(t.getClass().getName());
                }
            }
            System.err.println("\n");
            
        } else {
            
            System.err.print("ERROR: ");
            if (t instanceof EncryptionOperationNotPossibleException) {
                System.err.println(
                        "Operation not possible (Bad input or parameters)");
            } else {
                if (t.getMessage() != null) {
                    System.err.println(t.getMessage());
                } else {
                    System.err.println(t.getClass().getName());
                }
            }
            
        }
        
    }

    
    static boolean getVerbosity(String[] args) {
        for (int i = 0; i < args.length; i++) {
            String key = StringUtils.substringBefore(args[i], "=");
            String value = StringUtils.substringAfter(args[i], "=");
            if (StringUtils.isEmpty(key) || StringUtils.isEmpty(value)) {
                continue;
            }
            if (ArgumentNaming.ARG_VERBOSE.equals(key)) {
                return BooleanUtils.toBoolean(value);
            }
        }
        return true;
    }
    
    
    static Properties getArgumentValues(String appName, String[] args, 
            String[][] requiredArgNames, String[][] optionalArgNames) {
        
        Set argNames = new HashSet();
        for (int i = 0; i < requiredArgNames.length; i++) {
            argNames.addAll(Arrays.asList(requiredArgNames[i]));
        }
        for (int i = 0; i < optionalArgNames.length; i++) {
            argNames.addAll(Arrays.asList(optionalArgNames[i]));
        }

        Properties argumentValues = new Properties();
        for (int i = 0; i < args.length; i++) {
            String key = StringUtils.substringBefore(args[i], "=");
            String value = StringUtils.substringAfter(args[i], "=");
            if (StringUtils.isEmpty(key) || StringUtils.isEmpty(value)) {
                throw new IllegalArgumentException("Bad argument: " + args[i]);
            }
            if (argNames.contains(key)) {
                if (value.startsWith("\"") && value.endsWith("\"")) {
                    argumentValues.setProperty(
                            key, 
                            value.substring(1, value.length() - 1));
                } else {
                    argumentValues.setProperty(key, value);
                }
            }
        }
        
        //Check for all required arguments
        for (int i = 0; i < requiredArgNames.length; i++) {
            boolean found = false;
            for (int j = 0; j < requiredArgNames[i].length; j++) {
                if (argumentValues.containsKey(requiredArgNames[i][j])) {
                    found = true;
                }
            }
            if (!found) {
                showUsageAndExit(
                        appName, requiredArgNames, optionalArgNames);
            }
        }
        return argumentValues;
        
    }
    
    
    static void showUsageAndExit(String appName,
            String[][] requiredArgNames, String[][] optionalArgNames) {
        
        System.err.println("\nUSAGE: " + appName + " [ARGUMENTS]\n");
        System.err.println("  * Arguments must apply to format:\n");
        System.err.println(
                "      \"arg1=value1 arg2=value2 arg3=value3 ...\"\n");
        System.err.println("  * Required arguments:\n");
        for (int i = 0; i < requiredArgNames.length; i++) {
            System.err.print("      ");
            if (requiredArgNames[i].length == 1) {
                System.err.print(requiredArgNames[i][0]);
            } else {
                System.err.print("(");
                for (int j = 0; j < requiredArgNames[i].length; j++) {
                    if (j > 0) {
                        System.err.print(" | ");
                    }
                    System.err.print(requiredArgNames[i][j]);
                }
                System.err.print(")");
            }
            System.err.println();
            System.err.println();
        }
        System.err.println("  * Optional arguments:\n");
        for (int i = 0; i < optionalArgNames.length; i++) {
            System.err.print("      ");
            if (optionalArgNames[i].length == 1) {
                System.err.print(optionalArgNames[i][0]);
            } else {
                System.err.print("(");
                for (int j = 0; j < optionalArgNames[i].length; j++) {
                    if (j > 0) {
                        System.err.print(" | ");
                    }
                    System.err.print(optionalArgNames[i][j]);
                }
                System.err.print(")");
            }
            System.err.println();
            System.err.println();
        }
        System.exit(1);
        
    }
    
    
    
    private ArgumentUtils() {
        super();
    }
    
}
