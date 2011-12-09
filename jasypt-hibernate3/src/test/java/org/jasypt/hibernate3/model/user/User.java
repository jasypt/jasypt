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
package org.jasypt.hibernate3.model.user;

import java.util.Calendar;

import org.apache.commons.lang.builder.ToStringBuilder;

/**
 * 
 * @author Soraya S&aacute;nchez
 *
 */
public class User {

	private String name;
	private String login;
	private String password;
	private Calendar birthdate;
	private byte[] document;
	
	
	public User(String name, String login, String password, Calendar birthdate,
			byte[] document) {
		super();
		this.name = name;
		this.login = login;
		this.password = password;
		this.birthdate = birthdate;
		this.document = document;
	}
	public User() {
		super();
	}
	
	public String toString() {
		return new ToStringBuilder(this).append("name", this.name)
				.append("login", this.login).append("password", this.password)
				.append("birthdate", this.birthdate)
				.append("document", this.document).toString();
	}
	public String getName() {
		return this.name;
	}
	public void setName(String name) {
		this.name = name;
	}
	public String getLogin() {
		return this.login;
	}
	public void setLogin(String login) {
		this.login = login;
	}
	public String getPassword() {
		return this.password;
	}
	public void setPassword(String password) {
		this.password = password;
	}
	public Calendar getBirthdate() {
		return this.birthdate;
	}
	public void setBirthdate(Calendar birthdate) {
		this.birthdate = birthdate;
	}
	public byte[] getDocument() {
		return this.document;
	}
	public void setDocument(byte[] document) {
		this.document = document;
	}
	
	
}
