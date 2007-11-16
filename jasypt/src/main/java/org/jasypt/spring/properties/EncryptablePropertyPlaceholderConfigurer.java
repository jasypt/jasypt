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
package org.jasypt.spring.properties;

import java.util.Properties;
import java.util.Set;

import org.jasypt.util.text.BasicTextEncryptor;
import org.springframework.beans.factory.BeanDefinitionStoreException;
import org.springframework.beans.factory.config.PropertyPlaceholderConfigurer;

public class EncryptablePropertyPlaceholderConfigurer 
        extends PropertyPlaceholderConfigurer {

	public static String DEFAUL_PLACEHOLDER_ENCRYPTED_SUFFIX = "*";

	private String placeholderPrefix = DEFAULT_PLACEHOLDER_PREFIX;

	private String placeholderSuffix = DEFAULT_PLACEHOLDER_SUFFIX;

	private int systemPropertiesMode = SYSTEM_PROPERTIES_MODE_FALLBACK;

	private boolean ignoreUnresolvablePlaceholders = false;

	private String placeholderEncryptedSuffix = DEFAUL_PLACEHOLDER_ENCRYPTED_SUFFIX;

	private BasicTextEncryptor encryptor;

	public void setPlaceholderEncryptedSuffix(String placeholderEncryptedSuffix) {
		this.placeholderEncryptedSuffix = placeholderEncryptedSuffix;
	}

	public void setEncryptor(BasicTextEncryptor encryptor) {
		this.encryptor = encryptor;

		// TODO
		encryptor.setPassword("jasypt");
	}

	public void setIgnoreUnresolvablePlaceholders(
			boolean ignoreUnresolvablePlaceholders) {
		this.ignoreUnresolvablePlaceholders = ignoreUnresolvablePlaceholders;
		super.setIgnoreResourceNotFound(ignoreUnresolvablePlaceholders);
	}

	public void setPlaceholderPrefix(String placeholderPrefix) {
		this.placeholderPrefix = placeholderPrefix;
		super.setPlaceholderPrefix(placeholderPrefix);
	}

	public void setPlaceholderSuffix(String placeholderSuffix) {
		this.placeholderSuffix = placeholderSuffix;
		super.setPlaceholderSuffix(placeholderSuffix);
	}

	public void setSystemPropertiesMode(int systemPropertiesMode) {
		this.systemPropertiesMode = systemPropertiesMode;
		super.setSystemPropertiesMode(systemPropertiesMode);
	}

	protected String parseStringValue(String strVal, Properties props,
			Set visitedPlaceholders) throws BeanDefinitionStoreException {

		StringBuffer buf = new StringBuffer(strVal);

		int startIndex = strVal.indexOf(this.placeholderPrefix);
		while (startIndex != -1) {
			int endIndex = buf.toString().indexOf(this.placeholderSuffix,
					startIndex + this.placeholderPrefix.length());
			if (endIndex != -1) {
				String placeholder = buf.substring(startIndex
						+ this.placeholderPrefix.length(), endIndex);
				if (!visitedPlaceholders.add(placeholder)) {
					throw new BeanDefinitionStoreException(
							"Circular placeholder reference '" + placeholder
									+ "' in property definitions");
				}

				String propVal = resolvePlaceholder(placeholder, props,
						this.systemPropertiesMode);

				if (propVal == null) {
					// Placeholder can be an encrypted placeholder
					String encryptedPropVal = resolvePlaceholder(placeholder
							+ placeholderEncryptedSuffix, props,
							this.systemPropertiesMode);

					if (encryptedPropVal != null) {
						propVal = encryptor.decrypt(encryptedPropVal);
					}
				}

				if (propVal != null) {
					// Recursive invocation, parsing placeholders contained
					// in the previously resolved placeholder value.

					propVal = parseStringValue(propVal, props,
							visitedPlaceholders);
					buf.replace(startIndex, endIndex
							+ this.placeholderSuffix.length(), propVal);
					if (logger.isTraceEnabled()) {
						logger.trace("Resolved placeholder '" + placeholder
								+ "'");
					}
					startIndex = buf.toString().indexOf(this.placeholderPrefix,
							startIndex + propVal.length());
				} else if (this.ignoreUnresolvablePlaceholders) {
					// Proceed with unprocessed value.
					startIndex = buf.toString().indexOf(this.placeholderPrefix,
							endIndex + this.placeholderSuffix.length());
				} else {
					throw new BeanDefinitionStoreException(
							"Could not resolve placeholder '" + placeholder
									+ "'");
				}
				visitedPlaceholders.remove(placeholder);
			} else {
				startIndex = -1;
			}
		}

		return buf.toString();

	}
}
