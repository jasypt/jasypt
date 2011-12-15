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
package org.jasypt.spring31.xml.encryption;

import org.springframework.beans.factory.xml.NamespaceHandlerSupport;

/**
 * <p>
 *   Namespace handler for jasypt&apos;s <tt>encryption</tt> namespace.
 * </p>
 * <p>
 *   In order to use this namespace, add its XML schema declaration to your Spring
 *   beans file like:
 * </p>
 * <code>
 *  &lt;beans xmlns="http://www.springframework.org/schema/beans"<br />
 *  &nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;...<br />
 *  &nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;<b>xmlns:encryption="http://www.jasypt.org/schema/encryption"</b><br />
 *  &nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;...<br />
 *  &nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;xsi:schemaLocation="http://www.springframework.org/schema/beans<br />
 *  &nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;http://www.springframework.org/schema/beans/spring-beans-3.1.xsd<br />
 *  &nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;...<br />
 *  &nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;<b>http://www.jasypt.org/schema/encryption</b><br />
 *  &nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;<b>http://www.jasypt.org/schema/encryption/jasypt-spring31-encryption-1.xsd</b><br />
 *  &nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;..."&gt;
 * </code>
 * <p>
 *   This namespace offers the following elements for creating instances of specific jasypt artifacts
 *   and add them to the Spring application context:
 * </p>
 * <ul>
 *   <li>Digesters
 *     <ul>
 *       <li>{@link org.jasypt.digest.config.DigesterConfig} (simple, string, environment): <tt>&lt;encryption:digester-config/&gt;</tt></li>
 *       <li>{@link org.jasypt.digest.ByteDigester} (pooled or standard, depending on selected pool size): <tt>&lt;encryption:byte-digester/&gt;</tt></li>
 *       <li>{@link org.jasypt.digest.StringDigester} (pooled or standard, depending on selected pool size): <tt>&lt;encryption:string-digester/&gt;</tt></li>
 *       <li>Util digester classes:
 *         <ul>
 *           <li>{@link org.jasypt.util.password.BasicPasswordEncryptor}: <tt>&lt;encryption:basic-password-encryptor/&gt;</tt></li>
 *           <li>{@link org.jasypt.util.password.StrongPasswordEncryptor}: <tt>&lt;encryption:strong-password-encryptor/&gt;</tt></li>
 *           <li>{@link org.jasypt.util.password.ConfigurablePasswordEncryptor}: <tt>&lt;encryption:configurable-password-encryptor/&gt;</tt></li>
 *         </ul>
 *       </li> 
 *     </ul>
 *   </li>
 *   <li>PBE Encryption
 *     <ul>
 *       <li>{@link org.jasypt.encryption.pbe.config.PBEConfig} (simple, string, environment): <tt>&lt;encryption:encryptor-config/&gt;</tt></li>
 *       <li>{@link org.jasypt.encryption.ByteEncryptor} (pooled or standard, depending on selected pool size): <tt>&lt;encryption:byte-encryptor/&gt;</tt></li>
 *       <li>{@link org.jasypt.encryption.StringEncryptor} (pooled or standard, depending on selected pool size): <tt>&lt;encryption:string-encryptor/&gt;</tt></li>
 *       <li>{@link org.jasypt.encryption.BigIntegerEncryptor} (pooled or standard, depending on selected pool size): <tt>&lt;encryption:big-integer-encryptor/&gt;</tt></li>
 *       <li>{@link org.jasypt.encryption.BigDecimalEncryptor} (pooled or standard, depending on selected pool size): <tt>&lt;encryption:big-decimal-encryptor/&gt;</tt></li>
 *       <li>Util encryptor classes:
 *         <ul>
 *           <li>{@link org.jasypt.util.text.BasicTextEncryptor}: <tt>&lt;encryption:basic-text-encryptor/&gt;</tt></li>
 *           <li>{@link org.jasypt.util.text.StrongTextEncryptor}: <tt>&lt;encryption:strong-text-encryptor/&gt;</tt></li>
 *         </ul>
 *       </li> 
 *     </ul>
 *   </li>
 *   <li>Properties management
 *     <ul>
 *       <li>{@link org.jasypt.properties.EncryptableProperties} (equivalent to &lt;util:properties/&gt; adding property decryption): <tt>&lt;encryption:encryptable-properties/&gt;</tt></li>
 *       <li>{@link org.jasypt.spring3.properties.EncryptablePropertyPlaceholderConfigurer} (equivalent to &lt;context:property-placeholder/&gt; adding property decryption): <tt>&lt;encryption:encryptable-property-placeholder/&gt;</tt></li>
 *       <li>{@link org.jasypt.spring3.properties.EncryptablePropertyOverrideConfigurer} (equivalent to &lt;context:property-override/&gt; adding property decryption): <tt>&lt;encryption:encryptable-property-override/&gt;</tt></li>
 *     </ul>
 *   </li>
 * </ul>
 * 
 * @since 1.9.0
 * 
 * @author Daniel Fern&aacute;ndez
 * 
 */
public final class EncryptionNamespaceHandler extends NamespaceHandlerSupport {

    
    public EncryptionNamespaceHandler() {
        super();
    }
    

    public void init() {
        
        registerBeanDefinitionParser("encryptor-config", new EncryptorConfigBeanDefinitionParser());       
        registerBeanDefinitionParser("byte-encryptor", 
                new EncryptorBeanDefinitionParser(EncryptorFactoryBean.ENCRYPTOR_TYPE_BYTE));       
        registerBeanDefinitionParser("string-encryptor", 
                new EncryptorBeanDefinitionParser(EncryptorFactoryBean.ENCRYPTOR_TYPE_STRING));       
        registerBeanDefinitionParser("big-decimal-encryptor", 
                new EncryptorBeanDefinitionParser(EncryptorFactoryBean.ENCRYPTOR_TYPE_BIG_DECIMAL));       
        registerBeanDefinitionParser("big-integer-encryptor", 
                new EncryptorBeanDefinitionParser(EncryptorFactoryBean.ENCRYPTOR_TYPE_BIG_INTEGER));       
        registerBeanDefinitionParser("basic-text-encryptor", 
                new UtilEncryptorBeanDefinitionParser(UtilEncryptorBeanDefinitionParser.UTIL_TYPE_BASIC));       
        registerBeanDefinitionParser("strong-text-encryptor", 
                new UtilEncryptorBeanDefinitionParser(UtilEncryptorBeanDefinitionParser.UTIL_TYPE_STRONG));
        
        registerBeanDefinitionParser("digester-config", new DigesterConfigBeanDefinitionParser());
        registerBeanDefinitionParser("byte-digester", 
                new DigesterBeanDefinitionParser(DigesterFactoryBean.DIGESTER_TYPE_BYTE));       
        registerBeanDefinitionParser("string-digester", 
                new DigesterBeanDefinitionParser(DigesterFactoryBean.DIGESTER_TYPE_STRING));       
        registerBeanDefinitionParser("basic-password-encryptor", 
                new UtilDigesterBeanDefinitionParser(UtilDigesterBeanDefinitionParser.UTIL_TYPE_BASIC));       
        registerBeanDefinitionParser("strong-password-encryptor", 
                new UtilDigesterBeanDefinitionParser(UtilDigesterBeanDefinitionParser.UTIL_TYPE_STRONG));       
        registerBeanDefinitionParser("configurable-password-encryptor", 
                new UtilDigesterBeanDefinitionParser(UtilDigesterBeanDefinitionParser.UTIL_TYPE_CONFIGURABLE));       

        registerBeanDefinitionParser("encryptable-properties", new EncryptablePropertiesBeanDefinitionParser());       

        registerBeanDefinitionParser("encryptable-property-placeholder", new EncryptablePropertyPlaceholderBeanDefinitionParser());
        registerBeanDefinitionParser("encryptable-property-override", new EncryptablePropertyOverrideBeanDefinitionParser());
        
    }


}
