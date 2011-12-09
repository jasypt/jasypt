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
package org.jasypt.hibernate4.test;


import java.io.UnsupportedEncodingException;
import java.sql.Connection;
import java.sql.SQLException;
import java.util.Calendar;

import junit.framework.TestCase;

import org.apache.commons.lang.RandomStringUtils;
import org.hibernate.Session;
import org.hibernate.SessionFactory;
import org.hibernate.Transaction;
import org.hibernate.cfg.Configuration;
import org.hibernate.jdbc.Work;
import org.hibernate.service.ServiceRegistry;
import org.hibernate.service.ServiceRegistryBuilder;
import org.jasypt.encryption.pbe.StandardPBEByteEncryptor;
import org.jasypt.encryption.pbe.StandardPBEStringEncryptor;
import org.jasypt.hibernate4.encryptor.HibernatePBEEncryptorRegistry;
import org.jasypt.hibernate4.model.user.User;

/**
 * 
 * @author Soraya S&aacute;nchez
 *
 */
public class TestHibernateTypes extends TestCase {

	private static Configuration hbConf;
	private static SessionFactory sessionFactory;
	
	private static String userLogin;
	private static String userName;
	private static String userPassword;
	private static Calendar userBirthdate;
	private static byte[] userDocument;

	static Session session;
	
	public TestHibernateTypes() {
        super();
    }

    public TestHibernateTypes(String name) {
        super(name);
    }

    public void testCreateAndReadUser() throws Exception {
        initialize();
        
        createUser();
        readUser();
        
        finish();
    }
    
    private void initialize() {
	    registerEncryptors();
	    
	    // Configure Hibernate and open session
		ServiceRegistryBuilder serviceRegistryBuilder = new ServiceRegistryBuilder()
		    .applySetting("hibernate.dialect", "org.hibernate.dialect.HSQLDialect")
            .applySetting("hibernate.connection.url", 
                "jdbc:hsqldb:mem:jasypttestdb")
            .applySetting("hibernate.connection.driver_class", "org.hsqldb.jdbcDriver")
            .applySetting("hibernate.connection.username", "sa")
            .applySetting("hibernate.connection.password", "")
            .applySetting("hibernate.connection.pool_size", "10");
		ServiceRegistry serviceRegistry = serviceRegistryBuilder.buildServiceRegistry();
		
		hbConf = new Configuration();
		sessionFactory = hbConf
            .addClass(User.class)
            .setProperty("hibernate.dialect", "org.hibernate.dialect.HSQLDialect")
            .setProperty("hibernate.connection.url", 
                    "jdbc:hsqldb:mem:jasypttestdb")
            .setProperty("hibernate.connection.driver_class", "org.hsqldb.jdbcDriver")
            .setProperty("hibernate.connection.username", "sa")
            .setProperty("hibernate.connection.password", "")
            .setProperty("hibernate.connection.pool_size", "10")
            .buildSessionFactory(serviceRegistry);
		session = sessionFactory.openSession();
	    
		initDB();		
		
		generateData();
	}
	
	private void registerEncryptors() {
	    StandardPBEStringEncryptor stringEncryptor = new StandardPBEStringEncryptor();
        stringEncryptor.setAlgorithm("PBEWithMD5AndDES");
        stringEncryptor.setPassword("jasypt-hibernate3-test");
                
        StandardPBEByteEncryptor byteEncryptor = new StandardPBEByteEncryptor();
        byteEncryptor.setAlgorithm("PBEWithMD5AndDES");
        byteEncryptor.setPassword("jasypt-hibernate3-test");
        
        HibernatePBEEncryptorRegistry registry =
            HibernatePBEEncryptorRegistry.getInstance();
        registry.registerPBEStringEncryptor("hibernateStringEncryptor", stringEncryptor);
        registry.registerPBEByteEncryptor("hibernateByteEncryptor", byteEncryptor);
	}
	
	/**
	 * Create db structure
	 */
	private void initDB() {		
		Transaction transaction = session.beginTransaction();
		
		session.doWork(new Work() {
			public void execute(Connection connection) throws SQLException {
				connection.createStatement().execute(
						"CREATE MEMORY TABLE PUBLIC.USER(" +
						"NAME VARCHAR(100)," +
						"LOGIN VARCHAR(100) PRIMARY KEY," +
						"PASSWORD VARCHAR(100)," +
						"BIRTHDATE VARCHAR(100)," +
						"DOCUMENT BLOB);");
			}
		});
		
		transaction.commit();
	}
	
	/**
	 * Generate data to test with
	 */
	private void generateData() {
	    userLogin = RandomStringUtils.randomAlphabetic(5);
	    userName = RandomStringUtils.randomAlphabetic(10);
	    userPassword = RandomStringUtils.randomAlphanumeric(15);
	    userBirthdate = Calendar.getInstance();
	    try {
            userDocument = RandomStringUtils.randomAlphabetic(100).getBytes(
                "ISO-8859-1");
        } catch (UnsupportedEncodingException e) {
            assertTrue(false);
        }
	}
	
	private void finish() {
		session.close();
	}
	
	
	private void createUser() throws Exception {
		User user = new User(userName, userLogin, userPassword,
				userBirthdate, userDocument);
		
		Transaction transaction = session.beginTransaction();
		
		session.saveOrUpdate(user);
		
		System.out.println("User stored: " + user);
		
		transaction.commit();
		
		assertTrue(true);
	}
	
	private void readUser() throws Exception {
		
		Transaction transaction = session.beginTransaction();
		
		User user = (User) session.load(User.class, userLogin);
		
		System.out.println("User read: " + user);
		
		transaction.commit();
		
		assertEquals(user.getLogin(), userLogin);
		assertEquals(user.getName(), userName);
		assertEquals(user.getPassword(), userPassword);
		assertEquals(user.getBirthdate(), userBirthdate);
		assertEquals(user.getDocument(), userDocument);
	}
}
