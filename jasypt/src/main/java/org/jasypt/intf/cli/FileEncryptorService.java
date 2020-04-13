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

import java.util.Properties;
import java.util.regex.Matcher;
import java.util.regex.Pattern;

import org.jasypt.commons.CommonUtils;
import org.jasypt.intf.service.JasyptStatelessService;

import static java.util.regex.Pattern.DOTALL;

import java.io.IOException;

/**
 * <p>
 * This class acts as a service class to support file encryption/decryption operations.
 * Values to be encrypted/decrypted are identified by prefixes and suffixes provided as input.
 * This class also defines the default values of perfixes and suffixes as:
 * <li> DEFAULT_ENCRYPTED_PREFIX = "ENC("
 * <li> DEFAULT_ENCRYPTED_SUFFIX = ")"
 * <li> DEFAULT_DECRYPTED_PREFIX = "DEC("
 * <li> DEFAULT_DECRYPTED_SUFFIX = ")"
 * </p>
 * <br>
 * <p>
 * It is specifically meant to service the File encryption/decryption CLI interfaces
 * </p>
 * 
 * @since 1.10
 * 
 * @author Prakash Tiwari
 *
 */
public class FileEncryptorService {
    
    private final static String DEFAULT_ENCRYPTED_PREFIX = "ENC(";
    private final static String DEFAULT_ENCRYPTED_SUFFIX = ")";
    private final static String DEFAULT_DECRYPTED_PREFIX = "DEC(";
    private final static String DEFAULT_DECRYPTED_SUFFIX = ")";
    
    /**
     * Creates a new instance of <tt>FileEncryptorService</tt>.
     */
    public FileEncryptorService() {
        super();
    }
    
    /**
     * <p>
     * Performs decryption operation on a file by identifying parameters from CLI Arguments
     * </p>
     * 
     * 
     * @param location The base location to perform I/O operations
     * @param argumentValues
     * @param verbose
     * @return The output file path where decrypted file is saved
     * @throws IOException if there's some exception while reading/writing the files.
     * @throws EncryptionOperationNotPossibleException if the decryption operation could
     *         not be performed on any of the values (either because of wrong input or wrong
     *         parametrization).
     */
    public String decryptFile(
            final String location,
            final Properties argumentValues,
            final boolean verbose) throws IOException {
        
        String encryptedPrefix = argumentValues.getProperty(ArgumentNaming.ARG_ENCRYPTED_PREFIX);
        String encryptedSuffix = argumentValues.getProperty(ArgumentNaming.ARG_ENCRYPTED_SUFFIX);
        String decryptedPrefix = argumentValues.getProperty(ArgumentNaming.ARG_DECRYPTED_PREFIX);
        String decryptedSuffix = argumentValues.getProperty(ArgumentNaming.ARG_DECRYPTED_SUFFIX);
        
        if(CommonUtils.isEmpty(encryptedPrefix)) encryptedPrefix = DEFAULT_ENCRYPTED_PREFIX;
        if(CommonUtils.isEmpty(encryptedSuffix)) encryptedSuffix = DEFAULT_ENCRYPTED_SUFFIX;
        if(CommonUtils.isEmpty(decryptedPrefix)) decryptedPrefix = DEFAULT_DECRYPTED_PREFIX;
        if(CommonUtils.isEmpty(decryptedSuffix)) decryptedSuffix = DEFAULT_DECRYPTED_SUFFIX;
        
        final JasyptStatelessService service = new JasyptStatelessService();
        
        final String regex = CommonUtils.quoteRegExSpecialChars(encryptedPrefix) + "(.*?)"
                + CommonUtils.quoteRegExSpecialChars(encryptedSuffix);
        final Pattern pattern = Pattern.compile(regex, DOTALL);
        
        final String inputFileName = argumentValues.getProperty(ArgumentNaming.ARG_INPUT_FILE);
        final String password = argumentValues.getProperty(ArgumentNaming.ARG_PASSWORD);
        CommonUtils.validateNotEmpty(inputFileName, "Input file name cannot be null/empty");
        CommonUtils.validateNotEmpty(password, "Password cannot be null/empty");
        
        final String inputFilePath = location + inputFileName;
        final String inputFileAsString = CommonUtils.getFileAsString(inputFilePath);
        
        final Matcher matcher = pattern.matcher(inputFileAsString);
        StringBuffer result = new StringBuffer();
        String replacement;
        
        while (matcher.find()) {
            String matched = matcher.group(1);
            
            if(verbose) {
                System.out.println("Attempting to decrypt: \"" + matched + "\"");
            }
            
            String decrypted = service.decrypt(
                    matched, 
                    password,
                    null,
                    null,
                    argumentValues.getProperty(ArgumentNaming.ARG_ALGORITHM),
                    null,
                    null,
                    argumentValues.getProperty(ArgumentNaming.ARG_KEY_OBTENTION_ITERATIONS),
                    null,
                    null,
                    argumentValues.getProperty(ArgumentNaming.ARG_SALT_GENERATOR_CLASS_NAME),
                    null,
                    null,
                    argumentValues.getProperty(ArgumentNaming.ARG_PROVIDER_NAME),
                    null,
                    null,
                    argumentValues.getProperty(ArgumentNaming.ARG_PROVIDER_CLASS_NAME),
                    null,
                    null,
                    argumentValues.getProperty(ArgumentNaming.ARG_STRING_OUTPUT_TYPE),
                    null,
                    null,
                    argumentValues.getProperty(ArgumentNaming.ARG_IV_GENERATOR_CLASS_NAME),
                    null,
                    null);
            
            replacement = decryptedPrefix + decrypted + decryptedSuffix;
            matcher.appendReplacement(result, "");
            result.append(replacement);
        }
        
        final String outputFileName = argumentValues.getProperty(ArgumentNaming.ARG_OUTPUT_FILE);
        String outputFilePath = null;
        
        if(CommonUtils.isEmpty(outputFileName)) {
            outputFilePath = inputFilePath;
        } else {
            outputFilePath = location + outputFileName;
        }
        
        CommonUtils.writeStringToFile(outputFilePath, result.toString());
        
        return outputFilePath;
    }
    
    
    /**
     * <p>
     * Performs encryption operation on a file by identifying parameters from CLI Arguments
     * </p>
     * 
     * 
     * @param location The base location to perform I/O operations
     * @param argumentValues
     * @param verbose
     * @return The output file path where encrypted file is saved
     * @throws IOException if there's some exception while reading/writing the files.
     * @throws EncryptionOperationNotPossibleException if the encryption operation could
     *         not be performed on any of the values (either because of wrong input or wrong
     *         parametrization).
     */
    public String encryptFile(
            final String location,
            final Properties argumentValues,
            final boolean verbose) throws IOException {
        
        String encryptedPrefix = argumentValues.getProperty(ArgumentNaming.ARG_ENCRYPTED_PREFIX);
        String encryptedSuffix = argumentValues.getProperty(ArgumentNaming.ARG_ENCRYPTED_SUFFIX);
        String decryptedPrefix = argumentValues.getProperty(ArgumentNaming.ARG_DECRYPTED_PREFIX);
        String decryptedSuffix = argumentValues.getProperty(ArgumentNaming.ARG_DECRYPTED_SUFFIX);
        
        if(CommonUtils.isEmpty(encryptedPrefix)) encryptedPrefix = DEFAULT_ENCRYPTED_PREFIX;
        if(CommonUtils.isEmpty(encryptedSuffix)) encryptedSuffix = DEFAULT_ENCRYPTED_SUFFIX;
        if(CommonUtils.isEmpty(decryptedPrefix)) decryptedPrefix = DEFAULT_DECRYPTED_PREFIX;
        if(CommonUtils.isEmpty(decryptedSuffix)) decryptedSuffix = DEFAULT_DECRYPTED_SUFFIX;
        
        final JasyptStatelessService service = new JasyptStatelessService();
        
        final String regex = CommonUtils.quoteRegExSpecialChars(decryptedPrefix) + "(.*?)"
                + CommonUtils.quoteRegExSpecialChars(decryptedSuffix);
        final Pattern pattern = Pattern.compile(regex, DOTALL);
        
        final String inputFileName = argumentValues.getProperty(ArgumentNaming.ARG_INPUT_FILE);
        final String password = argumentValues.getProperty(ArgumentNaming.ARG_PASSWORD);
        CommonUtils.validateNotEmpty(inputFileName, "Input file name cannot be null/empty");
        CommonUtils.validateNotEmpty(password, "Password cannot be null/empty");
        
        final String inputFilePath = location + inputFileName;
        final String inputFileAsString = CommonUtils.getFileAsString(inputFilePath);
        
        final Matcher matcher = pattern.matcher(inputFileAsString);
        StringBuffer result = new StringBuffer();
        String replacement;
        
        while (matcher.find()) {
            String matched = matcher.group(1);
            
            if(verbose) {
                System.out.println("Attempting to encrypt: \"" + matched + "\"");
            }
            
            String encrypted = service.encrypt(
                    matched, 
                    password,
                    null,
                    null,
                    argumentValues.getProperty(ArgumentNaming.ARG_ALGORITHM),
                    null,
                    null,
                    argumentValues.getProperty(ArgumentNaming.ARG_KEY_OBTENTION_ITERATIONS),
                    null,
                    null,
                    argumentValues.getProperty(ArgumentNaming.ARG_SALT_GENERATOR_CLASS_NAME),
                    null,
                    null,
                    argumentValues.getProperty(ArgumentNaming.ARG_PROVIDER_NAME),
                    null,
                    null,
                    argumentValues.getProperty(ArgumentNaming.ARG_PROVIDER_CLASS_NAME),
                    null,
                    null,
                    argumentValues.getProperty(ArgumentNaming.ARG_STRING_OUTPUT_TYPE),
                    null,
                    null,
                    argumentValues.getProperty(ArgumentNaming.ARG_IV_GENERATOR_CLASS_NAME),
                    null,
                    null);
            
            replacement = encryptedPrefix + encrypted + encryptedSuffix;
            matcher.appendReplacement(result, "");
            result.append(replacement);
        }
        
        final String outputFileName = argumentValues.getProperty(ArgumentNaming.ARG_OUTPUT_FILE);
        String outputFilePath = null;
        
        if(CommonUtils.isEmpty(outputFileName)) {
            outputFilePath = inputFilePath;
        } else {
            outputFilePath = location + outputFileName;
        }
        
        CommonUtils.writeStringToFile(outputFilePath, result.toString());
        
        return outputFilePath;
    }
    
}
