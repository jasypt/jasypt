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

import java.util.Arrays;
import java.util.HashSet;
import java.util.Iterator;
import java.util.Map;
import java.util.Properties;
import java.util.Set;

import org.jasypt.commons.CommonUtils;
import org.jasypt.exceptions.EncryptionOperationNotPossibleException;


/*
 * Internal class for managing common CLI operations like argument extraction
 * or rendering command output/errors.
 */
final class CLIUtils {

    
    /*
     * Renders the execution environment.
     */
    static void showEnvironment(final boolean verbose) {
        
        if (verbose) {
            System.out.println("\n----ENVIRONMENT-----------------\n");
            System.out.println("Runtime: " + 
                    System.getProperty("java.vm.vendor") + " " + 
                    System.getProperty("java.vm.name") + " " +
                    System.getProperty("java.vm.version") + " ");
            System.out.println("\n");
        }
        
    }
    

    /*
     * Renders the command arguments as accepted for execution.
     */
    static void showArgumentDescription(final Properties argumentValues, final boolean verbose) {
        
        if (verbose) {
            System.out.println("\n----ARGUMENTS-------------------\n");
            final Iterator entriesIter = argumentValues.entrySet().iterator();
            while (entriesIter.hasNext()) {
                final Map.Entry entry = (Map.Entry) entriesIter.next();
                System.out.println(
                        entry.getKey() + ": " + entry.getValue());
            }
            System.out.println("\n");
        }
        
    }
    
    
    /*
     * Renders the command output.
     */
    static void showOutput(final String output, final boolean verbose) {

        if (verbose) {
            System.out.println("\n----OUTPUT----------------------\n");
            System.out.println(output);
            System.out.println("\n");
        } else {
            System.out.println(output);
        }
        
    }

    
    /*
     * Renders an error occurred during execution.
     */
    static void showError(final Throwable t, final boolean verbose) {

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

    
    /*
     * Defines whether the user has turned verbosity off or not.
     */
    static boolean getVerbosity(final String[] args) {
        for (int i = 0; i < args.length; i++) {
            final String key = CommonUtils.substringBefore(args[i], "=");
            final String value = CommonUtils.substringAfter(args[i], "=");
            if (CommonUtils.isEmpty(key) || CommonUtils.isEmpty(value)) {
                continue;
            }
            if (ArgumentNaming.ARG_VERBOSE.equals(key)) {
                final Boolean verbosity =
                    CommonUtils.getStandardBooleanValue(value);
                return (verbosity != null? verbosity.booleanValue() : false);
            }
        }
        return true;
    }
    
    
    /*
     * Extracts the argument values and checks its wellformedness.
     */
    static Properties getArgumentValues(final String appName, final String[] args, 
            final String[][] requiredArgNames, final String[][] optionalArgNames) {
        
        final Set argNames = new HashSet();
        for (int i = 0; i < requiredArgNames.length; i++) {
            argNames.addAll(Arrays.asList(requiredArgNames[i]));
        }
        for (int i = 0; i < optionalArgNames.length; i++) {
            argNames.addAll(Arrays.asList(optionalArgNames[i]));
        }

        final Properties argumentValues = new Properties();
        for (int i = 0; i < args.length; i++) {
            final String key = CommonUtils.substringBefore(args[i], "=");
            final String value = CommonUtils.substringAfter(args[i], "=");
            if (CommonUtils.isEmpty(key) || CommonUtils.isEmpty(value)) {
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
            } else {
                throw new IllegalArgumentException("Bad argument: " + args[i]);
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
    
    
    /*
     * Renders the usage instructions and exits with error.
     */
    static void showUsageAndExit(final String appName,
            final String[][] requiredArgNames, final String[][] optionalArgNames) {
        
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
    
    
    /*
     * Instantiation is forbidden.
     */
    private CLIUtils() {
        super();
    }
    
}
