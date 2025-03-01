package org.jasypt.hibernate6.converters;

import org.jasypt.commons.CommonUtils;

import java.util.Calendar;
import java.util.Properties;
import java.util.TimeZone;

public class EncryptedCalendarAsString extends AbstractEncryptedAsString {

    private Boolean storeTimeZone = Boolean.FALSE;

    @Override
    public synchronized void setParameterValues(final Properties parameters) {
        super.setParameterValues(parameters);

        final String paramStoreTimeZone = parameters.getProperty(ParameterNaming.STORE_TIME_ZONE);
        if ((paramStoreTimeZone != null) && (!paramStoreTimeZone.trim().equals(""))) {
            this.storeTimeZone = CommonUtils.getStandardBooleanValue(paramStoreTimeZone);
        }
    }

    @Override
    protected Calendar convertToObject(final String string) {
        final String[] stringTokens = CommonUtils.split(string);
        TimeZone tz;
        final long timeMillis = Long.parseLong(stringTokens[0]);
        if (this.storeTimeZone) {
            tz = TimeZone.getTimeZone(stringTokens[1]);
        } else {
            tz = TimeZone.getDefault();
        }
        final Calendar cal = Calendar.getInstance();
        cal.setTimeZone(tz);
        cal.setTimeInMillis(timeMillis);
        return cal;
    }

    @Override
    protected String convertToString(final Object object) {
        final StringBuilder strBuff = new StringBuilder();
        final long timeMillis = ((Calendar) object).getTimeInMillis();
        strBuff.append(timeMillis);
        if (this.storeTimeZone) {
            strBuff.append(" ");
            strBuff.append(((Calendar) object).getTimeZone().getID());
        }
        return strBuff.toString();
    }

}
