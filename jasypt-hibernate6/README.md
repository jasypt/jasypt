
 JASYPT: Java Simplified Encryption
 ----------------------------------
 
 Jasypt (Java Simplified Encryption) is a java library which allows the
 developer to add basic encryption capabilities to his/her projects with
 minimum effort, and without the need of having deep knowledge on how 
 cryptography works.
 

This is a custom fork for adding Hibernate 6 support.

Because of the way hibernate has removed Type in place for Converter, using this library has now changed.

To use you must:

- Use the `JasyptConfig` for your Hibernate config, and add properties to this specific to your database
- Register encryption modules with the registry
- Provide a ConverterConfig to the Converter class you are using, providing encryption parameters

Example:

```java

 // register encryption modules
 StandardPBEStringEncryptor stringEnryptor = new StandardPBEStringEncryptor();
 stringEncryptor.setAlgorithm("PBEWithMD5AndDES");
 stringEncryptor.setPassword("changeme");
 
 HibernatePBEEncryptorRegistry registry = HibernatePBEEncryptorRegistry.getInstance();
 registry.registerPBEStringEncryptor("hibernateStringEncryptor", stringEncryptor);
 
 // tell the EncryptedStringConverter converter which encryptor to use
 Properties props = new Properties();
 props.setProperty(EncryptionParameters.ENCRYPTOR_NAME, "hibernateStringEncryptor");
 EncryptedString.setConverterConfig(new ConverterConfig(props));
 
 JasyptConfig jConfig = new JasyptConfig()
     .addAnnotatedClass(Example.class)
     .setProperty(JAKARTA_JDBC_URL, "jdbc:mysql://localhost:3306/example")
     .setProperty(JAKARTA_JDBC_USER, "root")
     .setProperty(JAKARTA_JDBC_PASSWORD, "changeme")
     .setProperty("hibernate.hbm2ddl.auto", "create");
 
 sessionFactory.jasyptConfig.buildSessionFactory();
 
 ...
 
 @Entity
 class Example {
 
     @Convert(converter = EncryptedString.class)
     String exampleString = "";
 
 }

```
     
_____________

**Key Notes/Breaking Changes**

- Because of Hibernate 6 stricter type checking on Boolean columns, the boolean converter is now removed. If you wish to encrypt Booleans, you will need to store it as an integer, and use the ``EncryptedIntegerAsStringConverter``, parsing it into a Boolean in your code.
- It is recommended if you run into sizing issues (especially with BigDecimal) to use: ``@Column(precision = 64)`` or some larger value
- To avoid issues with long strings (encryption can make some very long strings), use: ``@Column(columnDefinition = "VARCHAR(255)")`` or ``@Column(length=LONG32)``
- If you are unsure how to use this library, please see the ``HibernateConverterTest`` class in ``src/test/java``. There is a fully working example with all possible converters.
