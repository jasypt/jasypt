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
package org.jasypt.digest;

import org.apache.commons.codec.binary.Base64;
import org.jasypt.digest.config.DigesterConfig;
import org.jasypt.exceptions.EncryptionInitializationException;
import org.jasypt.exceptions.EncryptionOperationNotPossibleException;
import org.jasypt.salt.SaltGeneration;


/**
 * <p>
 * Standard implementation of the {@link StringDigester} interface.
 * This class lets the user specify the algorithm to be used for 
 * creating digests, the size of the random salt to be applied, and
 * the number of times the hash function will be applied (iterations).
 * </p>
 * <p>
 * This class avoids byte-conversion problems related to the fact of 
 * different platforms having different default charsets, and returns 
 * digests in the form of BASE64-encoded ASCII Strings.
 * </p>
 * <p>
 * This class is <i>thread-safe</i>.
 * </p>
 * <p>
 * <br/><b><u>Configuration</u></b>
 * </p>
 * <p>
 * The algorithm, salt size and iterations can take values in any of these
 * ways:
 * <ul>
 *   <li>Using its default values.</li>
 *   <li>Setting a <tt>{@link org.jasypt.digest.config.DigesterConfig}</tt> 
 *       object which provides new 
 *       configuration values.</li>
 *   <li>Calling the corresponding <tt>setAlgorithm</tt>, 
 *       <tt>setSaltSizeBytes</tt> or <tt>setIterations</tt> methods.</li>
 * </ul>
 * And the actual values to be used for initialization will be established
 * by applying the following priorities:
 * <ol>
 *   <li>First, the default values are considered.</li>
 *   <li>Then, if a <tt>{@link org.jasypt.digest.config.DigesterConfig}</tt> 
 *       object has been set with
 *       <tt>setConfig</tt>, the non-null values returned by its
 *       <tt>getX</tt> methods override the default values.</li>
 *   <li>Finally, if the corresponding <tt>setX</tt> method has been called
 *       on the digester itself for any of the configuration parameters, the 
 *       values set by these calls override all of the above.</li>
 * </ol>
 * </p>
 * 
 * <p>
 * <br/><b><u>Initialization</u></b>
 * </p>
 * <p>
 * Before it is ready to create digests, an object of this class has to be
 * <i>initialized</i>. Initialization happens:
 * <ul>
 *   <li>When <tt>initialize</tt> is called.</li>
 *   <li>When <tt>digest</tt> or <tt>matches</tt> are called for the
 *       first time, if <tt>initialize</tt> has not been called before.</li>
 * </ul>
 * Once a digester has been initialized, trying to
 * change its configuration (algorithm, salt size or iterations) will
 * result in an <tt>AlreadyInitializedException</tt> being thrown.
 * </p>
 * 
 * <p>
 * <br/><b><u>Usage</u></b>
 * </p>
 * <p>
 * A digester may be used in two different ways:
 * <ul>
 *   <li>For <i>creating digests</i>, by calling the <tt>digest</tt> method.
 *   <li>For <i>matching digests</i>, this is, checking whether a digest
 *       corresponds adequately to a digest (as in password checking) or not, by
 *       calling the <tt>matches</tt> method.</li> 
 * </ul>
 * The steps taken for creating digests are:
 * <ol>
 *   <li>The String message is converted to a byte array.</li>
 *   <li>A random salt of the specified size is generated (see 
 *       {@link SaltGeneration}).</li>
 *   <li>The salt bytes are added to the message.</li>
 *   <li>The hash function is applied to the salt and message altogether, 
 *       and then to the
 *       results of the function itself, as many times as specified
 *       (iterations).</li>
 *   <li>The <i>undigested</i> salt and the final result of the hash
 *       function are concatenated.</li>
 *   <li>The result of the concatenation is encoded in BASE64
 *       and returned as an ASCII String.</li>
 * </ol>
 * Put schematically:
 * <ul>
 *   <li>
 *     DIGEST = <tt>|<b>S</b>|..(ssb)..|<b>S</b>|<b>X</b>|<b>X</b>|<b>X</b>|...|<b>X</b>|</tt>
 *       <ul>
 *         <li><tt><b>S</b></tt>: salt bytes (plain, not digested).</li>
 *         <li><tt>ssb</tt>: salt size in bytes.</li>
 *         <li><tt><b>X</b></tt>: bytes resulting from hashing (see below).</li>
 *       </ul>
 *   </li>
 *   <li>
 *     <tt>|<b>X</b>|<b>X</b>|<b>X</b>|...|<b>X</b>|</tt> = 
 *     <tt><i>H</i>(<i>H</i>(<i>H</i>(..(it)..<i>H</i>(<b>Z</b>|<b>Z</b>|<b>Z</b>|...|<b>Z</b>|))))</tt>
 *     <ul>
 *       <li><tt><i>H</i></tt>: Hash function (algorithm).</li>
 *       <li><tt>it</tt>: Number of iterations.</li>
 *       <li><tt><b>Z</b></tt>: Input for hashing (see below).</li> 
 *     </ul>
 *   </li>
 *   <li>
 *     <tt>|<b>Z</b>|<b>Z</b>|<b>Z</b>|...|<b>Z</b>|</tt> =
 *     <tt>|<b>S</b>|..(ssb)..|<b>S</b>|<b>M</b>|<b>M</b>|<b>M</b>...|<b>M</b>|</tt>
 *     <ul>
 *         <li><tt><b>S</b></tt>: salt bytes (plain, not digested).</li>
 *         <li><tt>ssb</tt>: salt size in bytes.</li>
 *         <li><tt><b>X</b></tt>: message bytes.</li>
 *     </ul>
 *   </li>
 * </ul>
 * <b>Two digests created for the same message will always be different
 * (except in the case of random salt coincidence).</b>
 * Because of this, the result of the <tt>digest</tt> method contains 
 * both the <i>undigested</i> salt and the digest of the (salt + message), 
 * so that another digest operation can be performed with the same salt 
 * on a different message to check if both messages match (all of which will 
 * be managed automatically by the <tt>matches</tt> method).
 * </p>
 * <p>     
 * To learn more about the mechanisms involved in digest creation, read
 * <a href="http://www.rsasecurity.com/rsalabs/node.asp?id=2127" 
 * target="_blank">PKCS &#035;5: Password-Based Cryptography Standard</a>.
 * </p>
 * 
 * @since 1.0
 * 
 * @author Daniel Fern&aacute;ndez Garrido
 * 
 */
public final class StandardStringDigester implements StringDigester {

    /**
     * <p>
     * Charset to be used to obtain "digestable" byte arrays from input Strings.
     * Set to <b>UTF-8</b>.
     * </p>
     * <p> 
     * This charset has to be fixed to some value so that we avoid problems 
     * with different platforms having different "default" charsets. 
     * </p>
     * <p>
     * It is set to <b>UTF-8</b> because it covers the whole spectrum of characters
     * representable in Java (which internally uses UTF-16), and avoids the
     * size penalty of UTF-16 (which will always use two bytes for representing
     * each character, even if it is an ASCII one).
     * </p>
     * <p>
     * Setting this value to UTF-8 does not mean that Strings that originally
     * come for, for example, an ISO-8859-1 input, will not be correcly 
     * digested. It simply provides a way of "fixing" the way a String will
     * be converted into bytes for digesting.
     * </p>
     */
    public static final String MESSAGE_CHARSET = "UTF-8";
    
    /**
     * <p>
     * Charset to be used for encoding the resulting digests. 
     * Set to <b>US-ASCII</b>.
     * </p>
     * <p>
     * The result of digesting some bytes can be any other bytes, and so
     * the result of digesting, for example, some LATIN-1 valid String bytes, 
     * can be bytes that may not conform a "valid" LATIN-1 String.
     * </p>
     * <p>
     * Because of this, digests are always encoded in <i>BASE64</i> after 
     * being created, and this ensures that the 
     * digests will make perfectly representable, safe ASCII Strings. Because
     * of this, the charset used to convert the digest bytes to the returned 
     * String is set to <b>US-ASCII</b>.
     * </p>
     */
    public static final String DIGEST_CHARSET = "US-ASCII";

    // The StandardByteDigester that will be internally used.
    private StandardByteDigester byteDigester = null;
    
    // BASE64 encoder which will make sure the returned digests are
    // valid US-ASCII strings.
    private Base64 base64 = null;


    
    /**
     * Creates a new instance of <tt>StandardStringDigester</tt>.
     */
    public StandardStringDigester() {
        super();
        this.byteDigester = new StandardByteDigester();
        this.base64 = new Base64();
    }

    
    /**
     * <p>
     * Sets a <tt>{@link org.jasypt.digest.config.DigesterConfig}</tt> 
     * object for the digester. If this config
     * object is set, it will be asked values for:
     * </p>
     * 
     * <ul>
     *   <li>Algorithm</li>
     *   <li>Salt size</li>
     *   <li>Hash iterations</li>
     * </ul>
     * 
     * <p>
     * The non-null values it returns will override the default ones
     * (see {@link StandardByteDigester}), 
     * <i>and will be overriden by any values specified with a <tt>setX</tt>
     * method</i>.
     * </p>
     * 
     * @param config the <tt>DigesterConfig</tt> object to be used as the 
     *               source for configuration parameters.
     */
    public void setConfig(DigesterConfig config) {
        byteDigester.setConfig(config);
    }

    
    /**
     * <p>
     * Sets the algorithm to be used for hashing, like "MD5" or "SHA-1".
     * </p>
     * 
     * <p>
     * This algorithm has to be supported by your Java Virtual Machine, and
     * it should be allowed as an algorithm for creating
     * java.security.MessageDigest instances.
     * </p>
     * 
     * @param algorithm the name of the algorithm to be used. See Appendix A 
     *                  in the <a target="_blank" 
     *                  href="http://java.sun.com/j2se/1.5.0/docs/guide/security/CryptoSpec.html#AppA">Java 
     *                  Cryptography Architecture API Specification & 
     *                  Reference</a>
     *                  for information about standard algorithm names.
     */
    public void setAlgorithm(String algorithm) {
        byteDigester.setAlgorithm(algorithm);
    }

    
    /**
     * <p>
     * Sets the size of the random salt to be used to compute the digest.
     * This mechanism is explained in 
     * <a href="http://www.rsasecurity.com/rsalabs/node.asp?id=2127" 
     * target="_blank">PKCS &#035;5: Password-Based Cryptography Standard</a>.
     * </p>
     * 
     * <p>
     * If salt size is set to zero, then no salt will be used.
     * </p>
     * 
     * @param saltSizeBytes the size of the random salt to be used, in bytes.
     */
    public void setSaltSizeBytes(int saltSizeBytes) {
        byteDigester.setSaltSizeBytes(saltSizeBytes);
    }

    
    /**
     * <p>
     * Set the number of times the hash function will be applied recursively.
     * <br/>
     * The hash function will be applied to its own results as many times as 
     * specified: <i>h(h(...h(x)...))</i>
     * </p>
     * <p>
     * This mechanism is explained in 
     * <a href="http://www.rsasecurity.com/rsalabs/node.asp?id=2127" 
     * target="_blank">PKCS &#035;5: Password-Based Cryptography Standard</a>.
     * </p>
     * 
     * @param iterations the number of iterations.
     */
    public void setIterations(int iterations) {
        byteDigester.setIterations(iterations);
    }

    
    /**
     * <p>
     *   Returns true if the digester has already been initialized, false if
     *   not.<br/> 
     *   Initialization happens:
     * </p>
     * <ul>
     *   <li>When <tt>initialize</tt> is called.</li>
     *   <li>When <tt>digest</tt> or <tt>matches</tt> are called for the
     *       first time, if <tt>initialize</tt> has not been called before.</li>
     * </ul>
     * <p>
     *   Once a digester has been initialized, trying to
     *   change its configuration (algorithm, salt size or iterations) will
     *   result in an <tt>AlreadyInitializedException</tt> being thrown.
     * </p>
     * 
     * @return true if the digester has already been initialized, false if
     *   not.
     */
    public boolean isInitialized() {
        return byteDigester.isInitialized();
    }

    
    /**
     * <p>
     * Initialize the digester.
     * </p>
     * <p>
     * This operation will consist in determining the actual configuration 
     * values to be used, and then initializing the digester using them.
     * <br/>
     * These values are decided by applying the following priorities:
     * </p>
     * <ol>
     *   <li>First, the default values are considered.</li>
     *   <li>Then, if a 
     *       <tt>{@link org.jasypt.digest.config.DigesterConfig}</tt> object 
     *       has been set with
     *       <tt>setConfig</tt>, the non-null values returned by its
     *       <tt>getX</tt> methods override the default values.</li>
     *   <li>Finally, if the corresponding <tt>setX</tt> method has been called
     *       on the digester itself for any of the configuration parameters, the 
     *       values set by these calls override all of the above.</li>
     * </ol>
     * <p>
     *   Once a digester has been initialized, trying to
     *   change its configuration (algorithm, salt size or iterations) will
     *   result in an <tt>AlreadyInitializedException</tt> being thrown.
     * </p>
     *
     */
    public void initialize() {
        byteDigester.initialize();
    }
    

    /**
     * <p>
     * Performs a digest operation on a String message.
     * </p>
     * <p>
     * The steps taken for creating the digest are:
     * <ol>
     *   <li>The String message is converted to a byte array.</li>
     *   <li>A random salt of the specified size is generated (see 
     *       {@link SaltGeneration}).</li>
     *   <li>The salt bytes are added to the message.</li>
     *   <li>The hash function is applied to the salt and message altogether, 
     *       and then to the
     *       results of the function itself, as many times as specified
     *       (iterations).</li>
     *   <li>The <i>undigested</i> salt and the final result of the hash
     *       function are concatenated.</li>
     *   <li>The result of the concatenation is encoded in BASE64
     *       and returned as an ASCII String.</li>
     * </ol>
     * Put schematically:
     * <ul>
     *   <li>
     *     DIGEST = <tt>|<b>S</b>|..(ssb)..|<b>S</b>|<b>X</b>|<b>X</b>|<b>X</b>|...|<b>X</b>|</tt>
     *       <ul>
     *         <li><tt><b>S</b></tt>: salt bytes (plain, not digested).</li>
     *         <li><tt>ssb</tt>: salt size in bytes.</li>
     *         <li><tt><b>X</b></tt>: bytes resulting from hashing (see below).</li>
     *       </ul>
     *   </li>
     *   <li>
     *     <tt>|<b>X</b>|<b>X</b>|<b>X</b>|...|<b>X</b>|</tt> = 
     *     <tt><i>H</i>(<i>H</i>(<i>H</i>(..(it)..<i>H</i>(<b>Z</b>|<b>Z</b>|<b>Z</b>|...|<b>Z</b>|))))</tt>
     *     <ul>
     *       <li><tt><i>H</i></tt>: Hash function (algorithm).</li>
     *       <li><tt>it</tt>: Number of iterations.</li>
     *       <li><tt><b>Z</b></tt>: Input for hashing (see below).</li> 
     *     </ul>
     *   </li>
     *   <li>
     *     <tt>|<b>Z</b>|<b>Z</b>|<b>Z</b>|...|<b>Z</b>|</tt> =
     *     <tt>|<b>S</b>|..(ssb)..|<b>S</b>|<b>M</b>|<b>M</b>|<b>M</b>...|<b>M</b>|</tt>
     *     <ul>
     *         <li><tt><b>S</b></tt>: salt bytes (plain, not digested).</li>
     *         <li><tt>ssb</tt>: salt size in bytes.</li>
     *         <li><tt><b>X</b></tt>: message bytes.</li>
     *     </ul>
     *   </li>
     * </ul>
     * </p>
     * <p>
     * <b>Two digests created for the same message will always be different
     * (except in the case of random salt coincidence).</b>
     * Because of this, the result of the <tt>digest</tt> method contains 
     * both the <i>undigested</i> salt and the digest of the (salt + message), 
     * so that another digest operation can be performed with the same salt 
     * on a different message to check if both messages match (all of which will 
     * be managed automatically by the <tt>matches</tt> method).     
     * </p>
     * 
     * @param message the String to be digested 
     * @return the digest result
     * @throws EncryptionOperationNotPossibleException if the digest operation
     *         fails, ommitting any further information about the cause for
     *         security reasons.
     */
    public String digest(String message) {
        
        if (message == null) {
            return null;
        }
        
        try {

            // The input String is converted into bytes using MESSAGE_CHARSET
            // as a fixed charset to avoid problems with different platforms
            // having different default charsets (see MESSAGE_CHARSET doc).
            byte[] messageBytes = message.getBytes(MESSAGE_CHARSET);

            // The StandardByteDigester does its job.
            byte[] digest = byteDigester.digest(messageBytes);
            
            // We encode the result in BASE64 so that we obtain the safest
            // result String possible.
            synchronized (base64) {
                digest = base64.encode(digest);
            }
            
            // Finally, the result String is encoded in US-ASCII
            return new String(digest, DIGEST_CHARSET);

        } catch (EncryptionInitializationException e) {
            throw e;
        } catch (EncryptionOperationNotPossibleException e) {
            throw e;
        } catch (Exception e) {
            // If digest fails, it is more secure not to return any information
            // about the cause in nested exceptions. Simply fail.
            throw new EncryptionOperationNotPossibleException();
        }
        
    }

    
    
    /**
     * <p>
     * Checks a message against a given digest.
     * </p>
     * <p>
     * This method tells whether a message corresponds to a specific digest
     * or not by getting the salt with which the digest was created and
     * applying it to a digest operation performed on the message. If 
     * new and existing digest match, the message is said to match the digest.
     * </p>
     * <p>
     * This method will be used, for instance, for password checking in
     * authentication processes.
     * </p>
     * <p>
     * A null message will only match a null digest.
     * </p>
     * 
     * @param message the message to be compared to the digest.
     * @param digest the digest. 
     * @return true if the specified message matches the digest, false
     *         if not.
     * @throws EncryptionOperationNotPossibleException if the digest matching
     *         operation fails, ommitting any further information about the 
     *         cause for security reasons.
     */
    public boolean matches(String message, String digest) {

        if (message == null) {
            return (digest == null);
        } else if (digest == null) {
            return false;
        }
        
        try {
            
            // We get a valid byte array from the message, in the 
            // fixed MESSAGE_CHARSET that the digest operations use.
            byte[] messageBytes = message.getBytes(MESSAGE_CHARSET);
            
            // The digest, which must be a US-ASCII String with BASE64-encoded
            // bytes, is converted into a byte array.
            byte[] digestBytes = digest.getBytes(DIGEST_CHARSET);

            // The BASE64 encoding is reversed.
            synchronized (base64) {
                digestBytes = base64.decode(digestBytes);
            }
            
            // The StandardByteDigester is asked to match message to digest.
            return byteDigester.matches(messageBytes, digestBytes); 
        
        } catch (EncryptionInitializationException e) {
            throw e;
        } catch (EncryptionOperationNotPossibleException e) {
            throw e;
        } catch (Exception e) {
            // If digest fails, it is more secure not to return any information
            // about the cause in nested exceptions. Simply fail.
            throw new EncryptionOperationNotPossibleException();
        }

    }
    
    
}
