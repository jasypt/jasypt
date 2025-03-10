package org.jasypt.hibernate6.configuration;

import jakarta.persistence.AttributeConverter;
import jakarta.persistence.SharedCacheMode;
import org.hibernate.*;
import org.hibernate.boot.jaxb.spi.Binding;
import org.hibernate.boot.model.FunctionContributor;
import org.hibernate.boot.model.TypeContributor;
import org.hibernate.boot.model.convert.spi.ConverterDescriptor;
import org.hibernate.boot.model.naming.ImplicitNamingStrategy;
import org.hibernate.boot.model.naming.PhysicalNamingStrategy;
import org.hibernate.boot.model.relational.AuxiliaryDatabaseObject;
import org.hibernate.boot.model.relational.ColumnOrderingStrategy;
import org.hibernate.cfg.Configuration;
import org.hibernate.context.spi.CurrentTenantIdentifierResolver;
import org.hibernate.proxy.EntityNotFoundDelegate;
import org.hibernate.query.sqm.function.SqmFunctionDescriptor;
import org.hibernate.resource.jdbc.spi.StatementInspector;
import org.hibernate.type.BasicType;
import org.hibernate.type.SerializationException;
import org.hibernate.usertype.UserType;
import org.jasypt.encryption.pbe.PBEStringEncryptor;
import org.jasypt.exceptions.EncryptionInitializationException;
import org.jasypt.hibernate6.converters.*;
import org.jasypt.hibernate6.encryptor.HibernatePBEEncryptorRegistry;
import org.jasypt.properties.PropertyValueEncryptionUtils;

import java.io.File;
import java.io.InputStream;
import java.util.Properties;

import static org.hibernate.cfg.JdbcSettings.*;
import static org.hibernate.cfg.JdbcSettings.JAKARTA_JDBC_PASSWORD;

public class JasyptConfig extends Configuration {

    public JasyptConfig() {
        // register custom converters
        addAnnotatedClass(EncryptedBigDecimalAsStringConverter.class);
        addAnnotatedClass(EncryptedBigDecimalConverter.class);
        addAnnotatedClass(EncryptedBigIntegerAsStringConverter.class);
        addAnnotatedClass(EncryptedBigIntegerConverter.class);
        addAnnotatedClass(EncryptedBytesAsBlobConverter.class);
        addAnnotatedClass(EncryptedByteAsStringConverter.class);
        addAnnotatedClass(EncryptedCalendarAsStringConverter.class);
        addAnnotatedClass(EncryptedDateAsStringConverter.class);
        addAnnotatedClass(EncryptedDoubleAsStringConverter.class);
        addAnnotatedClass(EncryptedDoubleAsStringConverter.class);
        addAnnotatedClass(EncryptedFloatAsStringConverter.class);
        addAnnotatedClass(EncryptedIntegerAsStringConverter.class);
        addAnnotatedClass(EncryptedLongAsStringConverter.class);
        addAnnotatedClass(EncryptedShortAsStringConverter.class);
        addAnnotatedClass(EncryptedStringConverter.class);
        addAnnotatedClass(EncryptedInputStreamConverter.class);
    }

    @Override
    public JasyptConfig setProperties(Properties properties) {
        super.setProperties(properties);
        return this;
    }

    @Override
    public JasyptConfig setProperty(String propertyName, String value) {
        super.setProperty(propertyName, value);
        return this;
    }

    @Override
    public JasyptConfig setProperty(String propertyName, boolean value) {
        super.setProperty(propertyName, value);
        return this;
    }

    @Override
    public JasyptConfig setProperty(String propertyName, Class<?> value) {
        super.setProperty(propertyName, value);
        return this;
    }

    @Override
    public JasyptConfig setProperty(String propertyName, Enum<?> value) {
        super.setProperty(propertyName, value);
        return this;
    }

    @Override
    public JasyptConfig setProperty(String propertyName, int value) {
        super.setProperty(propertyName, value);
        return this;
    }

    @Override
    public JasyptConfig addProperties(Properties properties) {
        super.addProperties(properties);
        return this;
    }

    @Override
    public JasyptConfig setImplicitNamingStrategy(ImplicitNamingStrategy implicitNamingStrategy) {
        super.setImplicitNamingStrategy(implicitNamingStrategy);
        return this;
    }

    @Override
    public JasyptConfig setPhysicalNamingStrategy(PhysicalNamingStrategy physicalNamingStrategy) {
        super.setPhysicalNamingStrategy(physicalNamingStrategy);
        return this;
    }

    @Override
    public JasyptConfig configure() throws HibernateException {
        super.configure();
        return this;
    }

    @Override
    public JasyptConfig configure(String resource) throws HibernateException {
        super.configure(resource);
        return this;
    }

    @Override
    public JasyptConfig configure(java.net.URL url) throws HibernateException {
        super.configure(url);
        return this;
    }

    @Override
    public JasyptConfig configure(File configFile) throws HibernateException {
        super.configure(configFile);
        return this;
    }

    @Override
    public JasyptConfig registerTypeContributor(TypeContributor typeContributor) {
        super.registerTypeContributor(typeContributor);
        return this;
    }

    @Override
    public JasyptConfig registerFunctionContributor(FunctionContributor functionContributor) {
        super.registerFunctionContributor(functionContributor);
        return this;
    }

    @Override
    public JasyptConfig registerTypeOverride(BasicType<?> type) {
        super.registerTypeOverride(type);
        return this;
    }

    @Override
    public JasyptConfig registerTypeOverride(UserType<?> type, String[] keys) {
        super.registerTypeOverride(type, keys);
        return this;
    }

    @Override
    public JasyptConfig addFile(String xmlFile) throws MappingException {
        super.addFile(xmlFile);
        return this;
    }

    @Override
    public JasyptConfig addFile(File xmlFile) throws MappingException {
        super.addFile(xmlFile);
        return this;
    }

    @Override
    public JasyptConfig addXmlMapping(Binding<?> binding) {
        super.addXmlMapping(binding);
        return this;
    }

    @Override
    public JasyptConfig addCacheableFile(File xmlFile) throws MappingException {
        super.addCacheableFile(xmlFile);
        return this;
    }

    @Override
    public JasyptConfig addCacheableFileStrictly(File xmlFile) throws SerializationException {
        super.addCacheableFileStrictly(xmlFile);
        return this;
    }

    @Override
    public JasyptConfig addCacheableFile(String xmlFile) throws MappingException {
        super.addCacheableFile(xmlFile);
        return this;
    }

    @Override
    public JasyptConfig addURL(java.net.URL url) throws MappingException {
        super.addURL(url);
        return this;
    }

    @Override
    public JasyptConfig addInputStream(InputStream xmlInputStream) throws MappingException {
        super.addInputStream(xmlInputStream);
        return this;
    }

    @Override
    public JasyptConfig addResource(String resourceName) throws MappingException {
        super.addResource(resourceName);
        return this;
    }

    @Override
    public JasyptConfig addClass(Class entityClass) throws MappingException {
        super.addClass(entityClass);
        return this;
    }

    @Override
    public JasyptConfig addAnnotatedClass(Class annotatedClass) {
        super.addAnnotatedClass(annotatedClass);
        return this;
    }

    @Override
    public JasyptConfig addPackage(String packageName) throws MappingException {
        super.addPackage(packageName);
        return this;
    }

    @Override
    public JasyptConfig addJar(File jar) throws MappingException {
        super.addJar(jar);
        return this;
    }

    @Override
    public JasyptConfig addDirectory(File dir) throws MappingException {
        super.addDirectory(dir);
        return this;
    }

    @Override
    public JasyptConfig setInterceptor(Interceptor interceptor) {
        super.setInterceptor(interceptor);
        return this;
    }

    @Override
    public JasyptConfig setEntityNotFoundDelegate(EntityNotFoundDelegate entityNotFoundDelegate) {
        super.setEntityNotFoundDelegate(entityNotFoundDelegate);
        return this;
    }

    @Override
    public JasyptConfig setSessionFactoryObserver(SessionFactoryObserver sessionFactoryObserver) {
        super.setSessionFactoryObserver(sessionFactoryObserver);
        return this;
    }

    @Override
    public JasyptConfig setStatementInspector(StatementInspector statementInspector) {
        super.setStatementInspector(statementInspector);
        return this;
    }

    @Override
    public JasyptConfig setCurrentTenantIdentifierResolver(CurrentTenantIdentifierResolver<Object> currentTenantIdentifierResolver) {
        super.setCurrentTenantIdentifierResolver(currentTenantIdentifierResolver);
        return this;
    }

    @Override
    public JasyptConfig setCustomEntityDirtinessStrategy(CustomEntityDirtinessStrategy customEntityDirtinessStrategy) {
        super.setCustomEntityDirtinessStrategy(customEntityDirtinessStrategy);
        return this;
    }

    @Override
    public JasyptConfig setColumnOrderingStrategy(ColumnOrderingStrategy columnOrderingStrategy) {
        super.setColumnOrderingStrategy(columnOrderingStrategy);
        return this;
    }

    @Override
    public JasyptConfig addSqlFunction(String functionName, SqmFunctionDescriptor function) {
        super.addSqlFunction(functionName, function);
        return this;
    }

    @Override
    public JasyptConfig addAuxiliaryDatabaseObject(AuxiliaryDatabaseObject object) {
        super.addAuxiliaryDatabaseObject(object);
        return this;
    }

    @Override
    public JasyptConfig addAttributeConverter(Class<? extends AttributeConverter<?, ?>> attributeConverterClass, boolean autoApply) {
        super.addAttributeConverter(attributeConverterClass, autoApply);
        return this;
    }

    @Override
    public JasyptConfig addAttributeConverter(Class<? extends AttributeConverter<?, ?>> attributeConverterClass) {
        super.addAttributeConverter(attributeConverterClass);
        return this;
    }

    @Override
    public JasyptConfig addAttributeConverter(AttributeConverter<?, ?> attributeConverter) {
        super.addAttributeConverter(attributeConverter);
        return this;
    }

    @Override
    public JasyptConfig addAttributeConverter(AttributeConverter<?, ?> attributeConverter, boolean autoApply) {
        super.addAttributeConverter(attributeConverter, autoApply);
        return this;
    }

    @Override
    public JasyptConfig addAttributeConverter(ConverterDescriptor converterDescriptor) {
        super.addAttributeConverter(converterDescriptor);
        return this;
    }

    @Override
    public JasyptConfig addEntityNameResolver(EntityNameResolver entityNameResolver) {
        super.addEntityNameResolver(entityNameResolver);
        return this;
    }

    @Override
    public JasyptConfig setSharedCacheMode(SharedCacheMode sharedCacheMode) {
        super.setSharedCacheMode(sharedCacheMode);
        return this;
    }

    @Override
    public JasyptConfig mergeProperties(Properties properties) {
        super.mergeProperties(properties);
        return this;
    }

    private void storeDecrypted(String propertyName, Properties props) {
        final String encryptorRegisteredName = props.getProperty(ConfigurationParameters.ENCRYPTOR_REGISTERED_NAME);
        final HibernatePBEEncryptorRegistry encryptorRegistry =
                HibernatePBEEncryptorRegistry.getInstance();
        final PBEStringEncryptor encryptor = encryptorRegistry.getPBEStringEncryptor(encryptorRegisteredName);

        String value = props.getProperty(propertyName);

        if (PropertyValueEncryptionUtils.isEncryptedValue(value)) {
            if (encryptor == null) {
                throw new EncryptionInitializationException(
                        "No string encryptor registered for hibernate " +
                                "with name \"" + encryptorRegisteredName + "\"");
            } else {
                props.setProperty(propertyName, PropertyValueEncryptionUtils.decrypt(value, encryptor));
            }
        }
    }

    public void configure(final Configuration configuration) {

        // verify if any of the provided properties are encrypted, and decrypt them for hibernate if needed
        final Properties props = configuration.getProperties();

        // attempt to decrypt config values
        storeDecrypted(JAKARTA_JDBC_DRIVER, props);
        storeDecrypted(JAKARTA_JDBC_URL, props);
        storeDecrypted(JAKARTA_JDBC_USER, props);
        storeDecrypted(JAKARTA_JDBC_PASSWORD, props);
    }

}
