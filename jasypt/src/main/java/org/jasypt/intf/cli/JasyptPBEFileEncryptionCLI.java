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

import java.io.IOException;
import java.util.Properties;

import org.jasypt.commons.CommonUtils;
import org.jasypt.encryption.pbe.config.SimpleStringPBEConfig;
import org.jasypt.intf.service.FileEncryptorService;


/**
 * <p>
 * This class supports the CLI "encrypt" operation for files.
 * </p>
 * <p>
 * <b>It should NEVER be used inside your code, only from the supplied
 * command-line tools</b>.
 * </p>
 * 
 * @since 1.10
 * 
 * @author Prakash Tiwari
 *
 */
public final class JasyptPBEFileEncryptionCLI {
    
    /*
     * The required arguments for this CLI operation.
     */
    private static final String[][] VALID_REQUIRED_ARGUMENTS =
        new String[][] {
            new String [] {
                ArgumentNaming.ARG_INPUT_FILE
            },
            new String [] {
                ArgumentNaming.ARG_PASSWORD
            }
        };
    
    /*
     * The optional arguments for this CLI operation.
     */
    private static final String[][] VALID_OPTIONAL_ARGUMENTS =
        new String[][] {
            new String [] {
                ArgumentNaming.ARG_OUTPUT_FILE
            },
            new String [] {
                ArgumentNaming.ARG_ENCRYPTED_PREFIX
            },
            new String [] {
                ArgumentNaming.ARG_ENCRYPTED_SUFFIX
            },
            new String [] {
                ArgumentNaming.ARG_DECRYPTED_PREFIX
            },
            new String [] {
                ArgumentNaming.ARG_DECRYPTED_SUFFIX
            },
            new String [] {
                ArgumentNaming.ARG_VERBOSE
            },
            new String [] {
                ArgumentNaming.ARG_ALGORITHM
            },
            new String [] {
                ArgumentNaming.ARG_KEY_OBTENTION_ITERATIONS
            },
            new String [] {
                ArgumentNaming.ARG_SALT_GENERATOR_CLASS_NAME
            },
            new String [] {
                ArgumentNaming.ARG_PROVIDER_NAME
            },
            new String [] {
                ArgumentNaming.ARG_PROVIDER_CLASS_NAME
            },
            new String [] {
                ArgumentNaming.ARG_STRING_OUTPUT_TYPE
            },
            new String[] {
                ArgumentNaming.ARG_IV_GENERATOR_CLASS_NAME
            }
        };
    
    
    /**
     * <p>
     * CLI execution method.
     * </p>
     * 
     * @param args the command execution arguments. Not providing the "outputFile" argument implies that
     * encryption is to be done in-place.
     */
    public static void main(final String[] args) {

        final boolean verbose = CLIUtils.getVerbosity(args);

        try {
            
            String applicationName = null;
            String[] arguments = null;
            if (args[0] == null || args[0].indexOf("=") != -1) {
                applicationName = JasyptPBEFileEncryptionCLI.class.getName();
                arguments = args;
            } else {
                applicationName = args[0];
                arguments = new String[args.length - 1];
                System.arraycopy(args, 1, arguments, 0, args.length - 1);
            }
            
            final Properties argumentValues = 
                CLIUtils.getArgumentValues(
                        applicationName, arguments, 
                        VALID_REQUIRED_ARGUMENTS, VALID_OPTIONAL_ARGUMENTS);

            CLIUtils.showEnvironment(verbose);
            
            final String location = System.getProperty("user.dir") + "/";
            
            CLIUtils.showArgumentDescription(argumentValues, verbose);
                        
            final String outputFilePath = encryptFile(location, argumentValues, verbose);
            
            final String result = "Encryption complete and is written at: " + outputFilePath;
            
            CLIUtils.showOutput(result, verbose);

        } catch (Throwable t) {
            CLIUtils.showError(t, verbose);
        }

    }
    
    /**
     * <p>
     * Performs encryption operation on a file by identifying parameters from CLI Arguments
     * </p>
     * 
     * @param location The base location to perform I/O operations
     * @param argumentValues
     * @param verbose
     * @return The output file path where encrypted file is saved
     * @throws IOException if there's some exception while reading/writing the files.
     * @throws EncryptionOperationNotPossibleException if the encryption operation could
     *         not be performed on any of the values (either because of wrong input or wrong
     *         parameterization).
     */
    private static String encryptFile(
            final String location,
            final Properties argumentValues,
            final boolean verbose) throws IOException {
        
        String encryptedPrefix = argumentValues.getProperty(ArgumentNaming.ARG_ENCRYPTED_PREFIX);
        String encryptedSuffix = argumentValues.getProperty(ArgumentNaming.ARG_ENCRYPTED_SUFFIX);
        String decryptedPrefix = argumentValues.getProperty(ArgumentNaming.ARG_DECRYPTED_PREFIX);
        String decryptedSuffix = argumentValues.getProperty(ArgumentNaming.ARG_DECRYPTED_SUFFIX);
        
        final String inputFileName = argumentValues.getProperty(ArgumentNaming.ARG_INPUT_FILE);
        final String password = argumentValues.getProperty(ArgumentNaming.ARG_PASSWORD);
        CommonUtils.validateNotEmpty(inputFileName, "Input file name cannot be null/empty");
        CommonUtils.validateNotEmpty(password, "Password cannot be null/empty");
        
        final String inputFilePath = location + inputFileName;
        final String inputFileAsString = CommonUtils.getFileAsString(inputFilePath);
        
        SimpleStringPBEConfig config = new SimpleStringPBEConfig();
        config.setPassword(password);
        config.setAlgorithm(argumentValues.getProperty(ArgumentNaming.ARG_ALGORITHM));
        config.setKeyObtentionIterations(argumentValues.getProperty(ArgumentNaming.ARG_KEY_OBTENTION_ITERATIONS));
        config.setSaltGeneratorClassName(argumentValues.getProperty(ArgumentNaming.ARG_SALT_GENERATOR_CLASS_NAME));
        config.setProviderName(argumentValues.getProperty(ArgumentNaming.ARG_PROVIDER_NAME));
        config.setProviderClassName(argumentValues.getProperty(ArgumentNaming.ARG_PROVIDER_CLASS_NAME));
        config.setStringOutputType(argumentValues.getProperty(ArgumentNaming.ARG_STRING_OUTPUT_TYPE));
        config.setIvGeneratorClassName(argumentValues.getProperty(ArgumentNaming.ARG_IV_GENERATOR_CLASS_NAME));
        
        final FileEncryptorService fileEncryptorService = new FileEncryptorService();
        
        String outputFileAsString = fileEncryptorService.encrypt(
        		inputFileAsString, config, encryptedPrefix, encryptedSuffix, decryptedPrefix, decryptedSuffix, verbose
        		);
        
        final String outputFileName = argumentValues.getProperty(ArgumentNaming.ARG_OUTPUT_FILE);
        String outputFilePath = null;
        
        if(CommonUtils.isEmpty(outputFileName)) {
            outputFilePath = inputFilePath;
        } else {
            outputFilePath = location + outputFileName;
        }
        
        CommonUtils.writeStringToFile(outputFilePath, outputFileAsString);
        
        return outputFilePath;
    }
    
    
    /*
     * Instantiation is forbidden.
     */
    private JasyptPBEFileEncryptionCLI() {
        super();
    }
    
}
