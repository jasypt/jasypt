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
package org.jasypt.intf.service;

import java.util.regex.Matcher;
import java.util.regex.Pattern;

import org.jasypt.commons.CommonUtils;
import org.jasypt.encryption.pbe.StandardPBEStringEncryptor;
import org.jasypt.encryption.pbe.config.SimpleStringPBEConfig;

import static java.util.regex.Pattern.DOTALL;

/**
 * <p>
 * This class acts as a service class to support file encryption/decryption operations.
 * Values to be encrypted/decrypted are identified by prefixes and suffixes provided as input.
 * This class also defines the default values of prefixes and suffixes as:
 * <li> DEFAULT_ENCRYPTED_PREFIX = "ENC("
 * <li> DEFAULT_ENCRYPTED_SUFFIX = ")"
 * <li> DEFAULT_DECRYPTED_PREFIX = "DEC("
 * <li> DEFAULT_DECRYPTED_SUFFIX = ")"
 * </p>
 * 
 * @since 1.10
 * 
 * @author Prakash Tiwari
 *
 */
public final class FileEncryptorService {
    
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
     * <p> Performs decryption operation on a file </p>
     * 
     * @param input The input file content as string
     * @param config The configuration necessary for doing the encryptions
     * @param encryptedPrefix The prefix that should be present before encrypted values
     * @param encryptedSuffix The suffix that should be present after encrypted values
     * @param decryptedPrefix The prefix that should be present before decrypted values
     * @param decryptedSuffix The prefix that should be present before decrypted values
     * @param verbose
     * @return
     */
    public String decrypt(
            final String input,
            final SimpleStringPBEConfig config,
            String encryptedPrefix,
            String encryptedSuffix,
            String decryptedPrefix,
            String decryptedSuffix,
            final boolean verbose) {
    	
    	if(CommonUtils.isEmpty(encryptedPrefix)) encryptedPrefix = DEFAULT_ENCRYPTED_PREFIX;
        if(CommonUtils.isEmpty(encryptedSuffix)) encryptedSuffix = DEFAULT_ENCRYPTED_SUFFIX;
        if(CommonUtils.isEmpty(decryptedPrefix)) decryptedPrefix = DEFAULT_DECRYPTED_PREFIX;
        if(CommonUtils.isEmpty(decryptedSuffix)) decryptedSuffix = DEFAULT_DECRYPTED_SUFFIX;
    	
    	final StandardPBEStringEncryptor encryptor = new StandardPBEStringEncryptor();
    	encryptor.setConfig(config);
    	
    	final String regex = CommonUtils.quoteRegExSpecialChars(encryptedPrefix) + "(.*?)"
                + CommonUtils.quoteRegExSpecialChars(encryptedSuffix);
        final Pattern pattern = Pattern.compile(regex, DOTALL);
        
        final Matcher matcher = pattern.matcher(input);
        StringBuffer result = new StringBuffer();
        String replacement;
        
        while (matcher.find()) {
            String matched = matcher.group(1);
            
            if(verbose) {
                System.out.println("Attempting to decrypt: \"" + matched + "\"");
            }
            
            String decrypted = encryptor.decrypt(matched);
            
            replacement = decryptedPrefix + decrypted + decryptedSuffix;
            matcher.appendReplacement(result, "");
            result.append(replacement);
        }
        
        matcher.appendTail(result);
        
        return result.toString();
    }
    
    
    /**
     * <p> Performs encryption operation on a file </p>
     * 
     * @param input The input file content as string
     * @param config The configuration necessary for doing the encryption.
     * @param encryptedPrefix The prefix that should be present before encrypted values
     * @param encryptedSuffix The suffix that should be present after encrypted values
     * @param decryptedPrefix The prefix that should be present before decrypted values
     * @param decryptedSuffix The prefix that should be present before decrypted values
     * @param verbose
     * @return
     */
    public String encrypt(
            final String input,
            final SimpleStringPBEConfig config,
            String encryptedPrefix,
            String encryptedSuffix,
            String decryptedPrefix,
            String decryptedSuffix,
            final boolean verbose) {
    	
    	if(CommonUtils.isEmpty(encryptedPrefix)) encryptedPrefix = DEFAULT_ENCRYPTED_PREFIX;
        if(CommonUtils.isEmpty(encryptedSuffix)) encryptedSuffix = DEFAULT_ENCRYPTED_SUFFIX;
        if(CommonUtils.isEmpty(decryptedPrefix)) decryptedPrefix = DEFAULT_DECRYPTED_PREFIX;
        if(CommonUtils.isEmpty(decryptedSuffix)) decryptedSuffix = DEFAULT_DECRYPTED_SUFFIX;
    	
    	final StandardPBEStringEncryptor encryptor = new StandardPBEStringEncryptor();
    	encryptor.setConfig(config);
    	
    	final String regex = CommonUtils.quoteRegExSpecialChars(decryptedPrefix) + "(.*?)"
                + CommonUtils.quoteRegExSpecialChars(decryptedSuffix);
        final Pattern pattern = Pattern.compile(regex, DOTALL);
        
        final Matcher matcher = pattern.matcher(input);
        StringBuffer result = new StringBuffer();
        String replacement;
        
        while (matcher.find()) {
            String matched = matcher.group(1);
            
            if(verbose) {
                System.out.println("Attempting to encrypt: \"" + matched + "\"");
            }
            
            String encrypted = encryptor.encrypt(matched);
            
            replacement = encryptedPrefix + encrypted + encryptedSuffix;
            matcher.appendReplacement(result, "");
            result.append(replacement);
        }
        
        matcher.appendTail(result);
        
        return result.toString();
    }
    
}
