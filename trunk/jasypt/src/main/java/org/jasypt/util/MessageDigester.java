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
package org.jasypt.util;

import org.jasypt.digest.StandardByteDigester;
import org.jasypt.exceptions.AlreadyInitializedException;

/**
 * <p>
 * Utility class for creating digests without using a salt or iterating
 * the hash function. This means that digests created by this class will
 * be compatible (and equivalent) to the ones which could be created by 
 * the user by directly using a {@link java.security.MessageDigest} object.
 * </p>
 * <p>
 * This class can be thought of as convenience wrapper for 
 * {@link java.security.MessageDigest}, adding thread-safety and
 * a more javabean-like interface to it. These two features enable a more
 * adequate use from an IoC container like Spring. 
 * </p>
 * <p>
 * This class internally holds a {@link StandardByteDigester} 
 * configured this way:
 * <ul>
 *   <li>Algorithm: <tt>MD5</tt> by default, but configurable.</li>
 *   <li>Salt size: <tt>0 bytes</tt>, no salt used.</li>
 *   <li>Iterations: <tt>1</tt>, hash function will not be iterated.</li>
 * </ul>
 * </p>
 * <p>
 * This class is <i>thread-safe</i>
 * </p>
 * 
 * @since 1.1
 * 
 * @author Daniel Fern&aacute;ndez Garrido
 * 
 */
public final class MessageDigester {

    
    /**
     * MD5 will be the default algorithm to be used if none is specified.
     */
    public static final String DEFAULT_ALGORITHM = "MD5";

    // The hash function will be applied only once
    private static final int ITERATIONS = 1;
    
    // No salt will be used
    private static final int SALT_SIZE_BYTES = 0;
    
    // The internal digester used
    private StandardByteDigester digester = null;
    
    
    /**
     * Creates a new instance of <tt>MessageDigester</tt>. It will use
     * the default algorithm unless one is specified with 
     * {@link #setAlgorithm(String)}. 
     *
     */
    public MessageDigester() {
        super();
        this.digester = new StandardByteDigester();
        this.digester.setIterations(ITERATIONS);
        this.digester.setSaltSizeBytes(SALT_SIZE_BYTES);
    }
    
    /**
     * <p>
     * Creates a new instance of <tt>MessageDigester</tt>, specifying
     * the algorithm to be used.
     * </p>
     * <p>
     * See Appendix A in the <a target="_blank" 
     * href="http://java.sun.com/j2se/1.5.0/docs/guide/security/CryptoSpec.html#AppA">Java 
     * Cryptography Architecture API Specification & Reference</a>
     * for information about standard algorithm names.
     * </p>
     *
     */
    public MessageDigester(String algorithm) {
        super();
        this.digester = new StandardByteDigester();
        this.digester.setIterations(ITERATIONS);
        this.digester.setSaltSizeBytes(SALT_SIZE_BYTES);
        this.digester.setAlgorithm(algorithm);
    }


    /**
     * <p>
     * Sets the algorithm to be used for creating digests.
     * </p>
     * <p>
     * See Appendix A in the <a target="_blank" 
     * href="http://java.sun.com/j2se/1.5.0/docs/guide/security/CryptoSpec.html#AppA">Java 
     * Cryptography Architecture API Specification & Reference</a>
     * for information about standard algorithm names.
     * </p>
     * 
     * @param algorithm the algorithm to be used.
     * @throws AlreadyInitializedException if it has already been initialized,
     *         this is, if {@link #digest(byte[])} has been called at least
     *         once.
     */
    public void setAlgorithm(String algorithm) {
        this.digester.setAlgorithm(algorithm);
    }
    
    
    /**
     * Creates a digest.
     * 
     * @param message the message to be digested.
     * @return the resulting digest.
     * @see StandardByteDigester#digest(byte[])
     */
    public byte[] digest(byte[] message) {
        return digester.digest(message);
    }

    
}
