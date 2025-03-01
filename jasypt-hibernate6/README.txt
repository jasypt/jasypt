
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

// tell the EncryptedString converter which encryptor to use
Properties props = new Properties();
props.setProperty(ParameterNaming.ENCRYPTOR_NAME, "hibernateStringEncryptor");
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
     