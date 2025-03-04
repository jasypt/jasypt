package org.jasypt.hibernate6;

import java.math.BigDecimal;
import java.math.BigInteger;
import java.util.Calendar;
import java.util.Date;
import java.util.Properties;
import java.util.Random;

import org.hibernate.Session;
import org.hibernate.SessionFactory;
import org.hibernate.Transaction;
import org.jasypt.encryption.pbe.StandardPBEBigDecimalEncryptor;
import org.jasypt.encryption.pbe.StandardPBEBigIntegerEncryptor;
import org.jasypt.encryption.pbe.StandardPBEByteEncryptor;
import org.jasypt.encryption.pbe.StandardPBEStringEncryptor;
import org.jasypt.hibernate6.configuration.JasyptConfig;
import org.jasypt.hibernate6.converters.*;
import org.jasypt.hibernate6.encryptor.HibernatePBEEncryptorRegistry;

import org.junit.Before;
import org.junit.After;
import org.junit.Test;

import static org.hibernate.cfg.JdbcSettings.*;
import static org.junit.Assert.*;

public class HibernateConvertersTest {

	private static SessionFactory sessionFactory;
	private Session session;
	private User createdUser;

	@Before
	public void setUp() {
		registerEncryptors();
		JasyptConfig config = new JasyptConfig()
				.addAnnotatedClass(User.class)
				.setProperty(JAKARTA_JDBC_URL, "jdbc:hsqldb:mem:jasypttestdb")
				.setProperty(JAKARTA_JDBC_USER, "root")
				.setProperty(JAKARTA_JDBC_PASSWORD, "")
				.setProperty("hibernate.hbm2ddl.auto", "create")
				.setProperty("hibernate.agroal.maxSize", "20");

		sessionFactory = config.buildSessionFactory();
		session = sessionFactory.openSession();
	}

	@After
	public void tearDown() {
		if (session != null) {
			session.close();
		}
		if (sessionFactory != null) {
			sessionFactory.close();
		}
	}

	@Test
	public void testCreateAndReadUser() {
		createUser();
		readUser();
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

		HibernatePBEEncryptorRegistry registry = HibernatePBEEncryptorRegistry.getInstance();
		registry.registerPBEStringEncryptor("hibernateStringEncryptor", stringEncryptor);
		registry.registerPBEByteEncryptor("hibernateByteEncryptor", byteEncryptor);
		registry.registerPBEBigIntegerEncryptor("hibernateBigIntegerEncryptor", bigIntegerEncryptor);
		registry.registerPBEBigDecimalEncryptor("hibernateBigDecimalEncryptor", bigDecimalEncryptor);

		Properties stringProperties = new Properties();
		stringProperties.setProperty(EncryptionParameters.ENCRYPTOR_NAME, "hibernateStringEncryptor");
		ConverterConfig stringConverterConfig = new ConverterConfig(stringProperties);

		EncryptedBigDecimalAsStringConverter.setConverterConfig(stringConverterConfig);
		EncryptedBigIntegerAsStringConverter.setConverterConfig(stringConverterConfig);
		EncryptedByteAsStringConverter.setConverterConfig(stringConverterConfig);
		EncryptedCalendarAsStringConverter.setConverterConfig(stringConverterConfig);
		EncryptedDateAsStringConverter.setConverterConfig(stringConverterConfig);
		EncryptedDoubleAsStringConverter.setConverterConfig(stringConverterConfig);
		EncryptedFloatAsStringConverter.setConverterConfig(stringConverterConfig);
		EncryptedIntegerAsStringConverter.setConverterConfig(stringConverterConfig);
		EncryptedLongAsStringConverter.setConverterConfig(stringConverterConfig);
		EncryptedShortAsStringConverter.setConverterConfig(stringConverterConfig);
		EncryptedStringConverter.setConverterConfig(stringConverterConfig);

		Properties bigDecimalProperties = new Properties();
		bigDecimalProperties.setProperty(EncryptionParameters.ENCRYPTOR_NAME, "hibernateBigDecimalEncryptor");
		bigDecimalProperties.setProperty(EncryptionParameters.DECIMAL_SCALE, "1");
		ConverterConfig bigDecimalConverterConfig = new ConverterConfig(bigDecimalProperties);
		EncryptedBigDecimalConverter.setConverterConfig(bigDecimalConverterConfig);

		Properties bigIntegerProperties = new Properties();
		bigIntegerProperties.setProperty(EncryptionParameters.ENCRYPTOR_NAME, "hibernateBigIntegerEncryptor");
		ConverterConfig bigIntegerConverterConfig = new ConverterConfig(bigIntegerProperties);
		EncryptedBigIntegerConverter.setConverterConfig(bigIntegerConverterConfig);

		Properties byteProperties = new Properties();
		byteProperties.setProperty(EncryptionParameters.ENCRYPTOR_NAME, "hibernateByteEncryptor");
		ConverterConfig byteConverterConfig = new ConverterConfig(byteProperties);
		EncryptedBinaryConverter.setConverterConfig(byteConverterConfig);
	}

	private void createUser() {
		Random random = new Random();
		byte[] randomBytes = new byte[16];
		random.nextBytes(randomBytes);

		createdUser = new User("test_name", BigDecimal.valueOf(random.nextDouble()), BigDecimal.valueOf(random.nextDouble()),
				new BigInteger(256, random), new BigInteger(256, random), randomBytes,
				(byte) random.nextInt(256), Calendar.getInstance(), new Date(), random.nextDouble(), random.nextFloat(),
				random.nextInt(), random.nextLong(), (short) random.nextInt(Short.MAX_VALUE + 1));

		Transaction transaction = session.beginTransaction();
		session.persist(createdUser);
		transaction.commit();

		assertNotNull(createdUser);
	}

	private void readUser() {
		Transaction transaction = session.beginTransaction();
		User user = session.byId(User.class).load("test_name");
		transaction.commit();

		assertNotNull(user);
		assertEquals("test_name", user.getName());
		assertEquals(createdUser.getDecimal(), user.getDecimal());
		assertEquals(createdUser.getDecimalAsString(), user.getDecimalAsString());
		assertEquals(createdUser.getBigInteger(), user.getBigInteger());
		assertEquals(createdUser.getBigIntegerAsString(), user.getBigIntegerAsString());
		assertArrayEquals(createdUser.getBinary(), user.getBinary());
		assertEquals(createdUser.getByteAsString(), user.getByteAsString());
		assertEquals(createdUser.getCalendar().getTimeInMillis(), user.getCalendar().getTimeInMillis());
		assertEquals(createdUser.getDate(), user.getDate());
		assertEquals(createdUser.getDoubleAsString(), user.getDoubleAsString(), 0.0001);
		assertEquals(createdUser.getFloatAsString(), user.getFloatAsString(), 0.0001);
		assertEquals(createdUser.getIntegerAsString(), user.getIntegerAsString());
		assertEquals(createdUser.getLongAsString(), user.getLongAsString());
		assertEquals(createdUser.getShortAsString(), user.getShortAsString());
	}
}
