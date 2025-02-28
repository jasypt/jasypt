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
package org.jasypt.hibernate5.test;


import java.io.UnsupportedEncodingException;
import java.math.BigDecimal;
import java.math.BigInteger;
import java.sql.Connection;
import java.sql.SQLException;
import java.util.Calendar;
import java.util.Random;

import org.apache.commons.lang.RandomStringUtils;
import org.hibernate.Session;
import org.hibernate.SessionFactory;
import org.hibernate.Transaction;
import org.hibernate.boot.registry.StandardServiceRegistry;
import org.hibernate.cfg.Configuration;
import org.hibernate.cfg.Environment;
import org.hibernate.jdbc.Work;
import org.hibernate.testing.ServiceRegistryBuilder;
import org.jasypt.encryption.pbe.StandardPBEBigDecimalEncryptor;
import org.jasypt.encryption.pbe.StandardPBEBigIntegerEncryptor;
import org.jasypt.encryption.pbe.StandardPBEByteEncryptor;
import org.jasypt.encryption.pbe.StandardPBEStringEncryptor;
import org.jasypt.hibernate5.encryptor.HibernatePBEEncryptorRegistry;
import org.jasypt.hibernate5.model.user.User;

import junit.framework.TestCase;

/**
 * 
 * @author Chus Picos
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
	private static BigInteger userCode;
	private static BigDecimal userCode2;

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
	    Configuration cfg = new Configuration();
	    cfg.setProperty(Environment.DIALECT, "org.hibernate.dialect.HSQLDialect");
	    cfg.setProperty(Environment.URL, "jdbc:hsqldb:mem:jasypttestdb");
	    cfg.setProperty(Environment.DRIVER, "org.hsqldb.jdbcDriver");
	    cfg.setProperty(Environment.USER, "sa");
	    cfg.setProperty(Environment.PASS, "");
	    cfg.setProperty(Environment.POOL_SIZE, "10");
	    StandardServiceRegistry serviceRegistry = ServiceRegistryBuilder.buildServiceRegistry(cfg.getProperties());
		
		hbConf = new Configuration();
		sessionFactory = hbConf
            .addClass(User.class)
            .setProperty(Environment.DIALECT, "org.hibernate.dialect.HSQLDialect")
            .setProperty(Environment.URL, "jdbc:hsqldb:mem:jasypttestdb")
            .setProperty(Environment.DRIVER, "org.hsqldb.jdbcDriver")
            .setProperty(Environment.USER, "sa")
            .setProperty(Environment.PASS, "")
            .setProperty(Environment.POOL_SIZE, "10")
            .buildSessionFactory(serviceRegistry);
		session = sessionFactory.openSession();
	    
		initDB();		
		
		generateData();
	}
	
	private void registerEncryptors() {
	    StandardPBEStringEncryptor stringEncryptor = new StandardPBEStringEncryptor();
        stringEncryptor.setAlgorithm("PBEWithMD5AndDES");
        stringEncryptor.setPassword("jasypt-hibernate5-test");
                
        StandardPBEByteEncryptor byteEncryptor = new StandardPBEByteEncryptor();
        byteEncryptor.setAlgorithm("PBEWithMD5AndDES");
        byteEncryptor.setPassword("jasypt-hibernate5-test");
        
        StandardPBEBigIntegerEncryptor bigIntegerEncryptor = new StandardPBEBigIntegerEncryptor();
        bigIntegerEncryptor.setAlgorithm("PBEWithMD5AndDES");
        bigIntegerEncryptor.setPassword("jasypt-hibernate5-test");
        
        StandardPBEBigDecimalEncryptor bigDecimalEncryptor = new StandardPBEBigDecimalEncryptor();
        bigDecimalEncryptor.setAlgorithm("PBEWithMD5AndDES");
        bigDecimalEncryptor.setPassword("jasypt-hibernate5-test");
        
        HibernatePBEEncryptorRegistry registry =
            HibernatePBEEncryptorRegistry.getInstance();
        registry.registerPBEStringEncryptor("hibernateStringEncryptor", stringEncryptor);
        registry.registerPBEByteEncryptor("hibernateByteEncryptor", byteEncryptor);
        registry.registerPBEBigIntegerEncryptor("hibernateBigIntegerEncryptor", bigIntegerEncryptor);
        registry.registerPBEBigDecimalEncryptor("hibernateBigDecimalEncryptor", bigDecimalEncryptor);
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
						"DOCUMENT BLOB," + 
						"CODE NUMERIC, " +
						"CODE2 NUMERIC);");
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
	    userCode = new BigInteger(256, new Random());
	    userCode2 = new BigDecimal(Math.random());
	}
	
	
	private void finish() {
		session.close();
	}
	
	
	private void createUser() throws Exception {
		User user = new User(userName, userLogin, userPassword,
				userBirthdate, userDocument, userCode, userCode2);
		
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
		assertEquals(user.getCode(), userCode);
		assertEquals(user.getCode2(), userCode2);
	}
}
