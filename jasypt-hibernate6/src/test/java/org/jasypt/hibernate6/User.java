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
package org.jasypt.hibernate6;

import java.io.InputStream;
import java.math.BigDecimal;
import java.math.BigInteger;
import java.util.Calendar;
import java.util.Date;

import jakarta.persistence.*;
import org.apache.commons.lang.builder.ToStringBuilder;
import org.jasypt.hibernate6.converters.*;

/**
 * 
 * @author Kris Rice
 *
 */
@Entity
@Table(name = "users")
public class User {

	@Id
	@Column(columnDefinition = "VARCHAR(255)")
	@Convert(converter = EncryptedStringConverter.class)
	private String name;

	@Column(precision = 256)
	@Convert(converter = EncryptedBigDecimalConverter.class)
	private BigDecimal decimal;

	@Column(precision = 256)
	@Convert(converter = EncryptedBigDecimalAsStringConverter.class)
	private BigDecimal decimalAsString;

	@Column(precision = 256)
	@Convert(converter = EncryptedBigIntegerConverter.class)
	private BigInteger bigInteger;


	@Column(columnDefinition = "VARCHAR(255)")
	@Convert(converter = EncryptedBigIntegerAsStringConverter.class)
	private BigInteger bigIntegerAsString;

	@Column
	@Convert(converter = EncryptedBytesAsBlobConverter.class)
	private byte[] binary;


	@Column(columnDefinition = "VARCHAR(255)")
	@Convert(converter = EncryptedByteAsStringConverter.class)
	private byte byteAsString;


	@Column
	@Convert(converter = EncryptedBytesAsBlobConverter.class)
	private byte[] byteBlob;

	@Column
	@Convert(converter = EncryptedBytesConverter.class)
	private byte[] bytes;

	@Column(columnDefinition = "VARCHAR(255)")
	@Convert(converter = EncryptedCalendarAsStringConverter.class)
	private Calendar calendar;


	@Column(columnDefinition = "VARCHAR(255)")
	@Convert(converter = EncryptedDateAsStringConverter.class)
	private Date date;


	@Column(columnDefinition = "VARCHAR(255)")
	@Convert(converter = EncryptedDoubleAsStringConverter.class)
	private double doubleAsString;


	@Column(columnDefinition = "VARCHAR(255)")
	@Convert(converter = EncryptedFloatAsStringConverter.class)
	private float floatAsString;


	@Lob
	@Column(length = 10485760) // 10 MB (adjust as needed)
	@Convert(converter = EncryptedInputStreamAsBytesConverter.class)
	private InputStream inputStream;


	@Column(columnDefinition = "VARCHAR(255)")
	@Convert(converter = EncryptedIntegerAsStringConverter.class)
	private int integerAsString;


	@Column(columnDefinition = "VARCHAR(255)")
	@Convert(converter = EncryptedLongAsStringConverter.class)
	private long longAsString;


	@Column(columnDefinition = "VARCHAR(255)")
	@Convert(converter = EncryptedShortAsStringConverter.class)
	private short shortAsString;


	public User(String name, BigDecimal decimal, BigDecimal decimalAsString, BigInteger bigInteger,
				BigInteger bigIntegerAsString, byte[] binary, byte byteAsString, byte[] byteBlob, byte[] bytes,
				Calendar calendar, Date date, double doubleAsString, float floatAsString, InputStream inputStream,
				int integerAsString, long longAsString, short shortAsString) {
		this.name = name;
		this.decimal = decimal;
		this.decimalAsString = decimalAsString;
		this.bigInteger = bigInteger;
		this.bigIntegerAsString = bigIntegerAsString;
		this.binary = binary;
		this.byteAsString = byteAsString;
		this.byteBlob = byteBlob;
		this.bytes = bytes;
		this.calendar = calendar;
		this.date = date;
		this.doubleAsString = doubleAsString;
		this.floatAsString = floatAsString;
		this.inputStream = inputStream;
		this.integerAsString = integerAsString;
		this.longAsString = longAsString;
		this.shortAsString = shortAsString;
	}


	public User() {
		super();
	}


	public String toString() {
		return new ToStringBuilder(this)
				.append("name", this.name)
				.append("decimal", this.decimal)
				.append("decimalAsString", this.decimalAsString)
				.append("bigInteger", this.bigInteger)
				.append("bigIntegerAsString", this.bigIntegerAsString)
				.append("binary", this.binary)
				.append("byteAsString", this.byteAsString)
				.append("calendar", this.calendar)
				.append("date", this.date)
				.append("doubleAsString", this.doubleAsString)
				.append("floatAsString", this.floatAsString)
				.append("integerAsString", this.integerAsString)
				.append("longAsString", this.longAsString)
				.append("shortAsString", this.shortAsString)
				.toString();
	}

	public String getName() {
		return this.name;
	}
	public void setName(String name) {
		this.name = name;
	}

	public BigDecimal getDecimal() {
		return decimal;
	}

	public void setDecimal(BigDecimal decimal) {
		this.decimal = decimal;
	}

	public BigDecimal getDecimalAsString() {
		return decimalAsString;
	}

	public void setDecimalAsString(BigDecimal decimalAsString) {
		this.decimalAsString = decimalAsString;
	}

	public BigInteger getBigInteger() {
		return bigInteger;
	}

	public void setBigInteger(BigInteger bigInteger) {
		this.bigInteger = bigInteger;
	}

	public BigInteger getBigIntegerAsString() {
		return bigIntegerAsString;
	}

	public void setBigIntegerAsString(BigInteger bigIntegerAsString) {
		this.bigIntegerAsString = bigIntegerAsString;
	}

	public byte[] getBinary() {
		return binary;
	}

	public void setBinary(byte[] binary) {
		this.binary = binary;
	}

	public byte getByteAsString() {
		return byteAsString;
	}

	public void setByteAsString(byte byteAsString) {
		this.byteAsString = byteAsString;
	}

	public Calendar getCalendar() {
		return calendar;
	}

	public void setCalendar(Calendar calendar) {
		this.calendar = calendar;
	}

	public Date getDate() {
		return date;
	}

	public void setDate(Date date) {
		this.date = date;
	}

	public double getDoubleAsString() {
		return doubleAsString;
	}

	public void setDoubleAsString(double doubleAsString) {
		this.doubleAsString = doubleAsString;
	}

	public float getFloatAsString() {
		return floatAsString;
	}

	public void setFloatAsString(float floatAsString) {
		this.floatAsString = floatAsString;
	}

	public int getIntegerAsString() {
		return integerAsString;
	}

	public void setIntegerAsString(int integerAsString) {
		this.integerAsString = integerAsString;
	}

	public long getLongAsString() {
		return longAsString;
	}

	public void setLongAsString(long longAsString) {
		this.longAsString = longAsString;
	}

	public short getShortAsString() {
		return shortAsString;
	}

	public void setShortAsString(short shortAsString) {
		this.shortAsString = shortAsString;
	}

	public byte[] getByteBlob() {
		return byteBlob;
	}

	public void setByteBlob(byte[] byteBlob) {
		this.byteBlob = byteBlob;
	}

	public byte[] getBytes() {
		return bytes;
	}

	public void setBytes(byte[] bytes) {
		this.bytes = bytes;
	}

	public InputStream getInputStream() {
		return inputStream;
	}

	public void setInputStream(InputStream inputStream) {
		this.inputStream = inputStream;
	}
}
