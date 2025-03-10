package org.jasypt.hibernate6;

import java.io.File;
import java.io.IOException;
import java.io.InputStream;
import java.math.BigDecimal;
import java.math.BigInteger;
import java.util.Calendar;
import java.util.Date;
import java.util.List;
import java.util.Random;

import jakarta.persistence.criteria.CriteriaBuilder;
import jakarta.persistence.criteria.CriteriaQuery;
import jakarta.persistence.criteria.Root;
import org.hibernate.Session;
import org.hibernate.SessionFactory;
import org.hibernate.Transaction;
import org.jasypt.hibernate6.configuration.JasyptConfig;
import org.jasypt.hibernate6.converters.*;
import org.jasypt.hibernate6.encryptor.*;

import org.junit.Before;
import org.junit.After;
import org.junit.Test;

import static org.hibernate.cfg.JdbcSettings.*;
import static org.junit.Assert.*;

public class HibernateConvertersTest {

	private static SessionFactory sessionFactory;
	private Session session;
	private User createdUser;

	private final int BUFFER_SIZE = 4096; // Size of the chunks to read

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
	public void testCreateAndReadUser() throws IOException {
		createUser();
		readUser();
	}

	private void registerEncryptors() {
		HibernatePBEStringEncryptor stringEncryptor = new HibernatePBEStringEncryptor();
		stringEncryptor.setAlgorithm("PBEWithMD5AndDES");
		stringEncryptor.setPassword("jasypt-hibernate6-test");
		stringEncryptor.setRegisteredName("hibernateStringEncryptor");

		HibernatePBEByteEncryptor byteEncryptor = new HibernatePBEByteEncryptor();
		byteEncryptor.setAlgorithm("PBEWithMD5AndDES");
		byteEncryptor.setPassword("jasypt-hibernate6-test");
		byteEncryptor.setRegisteredName("hibernateByteEncryptor");

		HibernatePBEBigIntegerEncryptor bigIntegerEncryptor = new HibernatePBEBigIntegerEncryptor();
		bigIntegerEncryptor.setAlgorithm("PBEWithMD5AndDES");
		bigIntegerEncryptor.setPassword("jasypt-hibernate6-test");
		bigIntegerEncryptor.setRegisteredName("hibernateBigIntegerEncryptor");

		HibernatePBEBigDecimalEncryptor bigDecimalEncryptor = new HibernatePBEBigDecimalEncryptor();
		bigDecimalEncryptor.setAlgorithm("PBEWithMD5AndDES");
		bigDecimalEncryptor.setPassword("jasypt-hibernate6-test");
		bigDecimalEncryptor.setRegisteredName("hibernateBigDecimalEncryptor");
		bigDecimalEncryptor.setDecimalScale(1);

		HibernatePBEInputStreamEncryptor inputStreamEncryptor = new HibernatePBEInputStreamEncryptor();
		inputStreamEncryptor.setAlgorithm("PBEWithMD5AndDES");
		inputStreamEncryptor.setPassword("jasypt-hibernate6-test");
		inputStreamEncryptor.setRegisteredName("hibernateInputStreamEncryptor");
		inputStreamEncryptor.setBlockSize(128 * 1024 * 1024); // 128MB Buffer

		ConverterConfig stringConverterConfig = stringEncryptor.generateConverterConfig();

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

		ConverterConfig bigDecimalConverterConfig = bigDecimalEncryptor.generateConverterConfig();
		EncryptedBigDecimalConverter.setConverterConfig(bigDecimalConverterConfig);

		ConverterConfig bigIntegerConverterConfig = bigIntegerEncryptor.generateConverterConfig();
		EncryptedBigIntegerConverter.setConverterConfig(bigIntegerConverterConfig);

		ConverterConfig byteConverterConfig = byteEncryptor.generateConverterConfig();
		EncryptedBytesAsBlobConverter.setConverterConfig(byteConverterConfig);
		EncryptedBytesConverter.setConverterConfig(byteConverterConfig);

		ConverterConfig inputStreamConverterconfig = inputStreamEncryptor.generateConverterConfig();
		EncryptedInputStreamConverter.setConverterConfig(inputStreamConverterconfig);
	}

	private byte[] generateRandomBytes(Random random) {
		byte[] randomBytes = new byte[16];
		random.nextBytes(randomBytes);
		return randomBytes;
	}

	private void createUser() {
		Random random = new Random();

		InputStream inputStream = ClassLoader.getSystemResourceAsStream("test_file.txt");

		createdUser = new User("test_name", BigDecimal.valueOf(random.nextDouble()), BigDecimal.valueOf(random.nextDouble()),
				new BigInteger(256, random), new BigInteger(256, random), generateRandomBytes(random),
				(byte) random.nextInt(256), generateRandomBytes(random), generateRandomBytes(random),
				Calendar.getInstance(), new Date(), random.nextDouble(), random.nextFloat(), inputStream,
				"test_file.txt", random.nextInt(), random.nextLong(),
				(short) random.nextInt(Short.MAX_VALUE + 1));

		Transaction transaction = session.beginTransaction();
		session.persist(createdUser);
		transaction.commit();

		assertNotNull(createdUser);
	}

	private void readUser() throws IOException {
		Transaction transaction = session.beginTransaction();
		CriteriaBuilder criteriaBuilder = session.getCriteriaBuilder();
		CriteriaQuery<User> criteriaQuery = criteriaBuilder.createQuery(User.class);
		Root<User> root = criteriaQuery.from(User.class);
		criteriaQuery.select(root);
		List<User> users = session.createQuery(criteriaQuery).getResultList();
		transaction.commit();

		User user = users.get(0);

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
		assertEquals(createdUser.getBytes(), user.getBytes());
		assertEquals(createdUser.getByteBlob(), user.getByteBlob());
		assertTrue(areStreamsEqual(createdUser.getInputStream(), user.getInputStream()));
	}

	public boolean areStreamsEqual(InputStream stream1, InputStream stream2) throws IOException {
		byte[] buffer1 = new byte[BUFFER_SIZE];
		byte[] buffer2 = new byte[BUFFER_SIZE];

		int bytesRead1, bytesRead2;

		// Read and compare chunks from both streams
		while ((bytesRead1 = stream1.read(buffer1)) != -1) {
			bytesRead2 = stream2.read(buffer2);

			// If one stream ends before the other, the streams are different
			if (bytesRead2 == -1) {
				return false;
			}

			// Compare the bytes read from both streams
			if (bytesRead1 != bytesRead2 || !equals(buffer1, buffer2, bytesRead1)) {
				return false; // Mismatch found
			}
		}

		// If stream1 ended, stream2 must also end at the same time
		return stream2.read() == -1;
	}

	// Helper method to compare two byte arrays up to a given length
	private boolean equals(byte[] array1, byte[] array2, int length) {
		for (int i = 0; i < length; i++) {
			if (array1[i] != array2[i]) {
				return false; // Mismatch found
			}
		}
		return true;
	}

	public static void main(String[] args) throws IOException {
		HibernateConvertersTest hibernateConvertersTest = new HibernateConvertersTest();
		hibernateConvertersTest.setUp();
		hibernateConvertersTest.testCreateAndReadUser();
		hibernateConvertersTest.tearDown();
	}

}
