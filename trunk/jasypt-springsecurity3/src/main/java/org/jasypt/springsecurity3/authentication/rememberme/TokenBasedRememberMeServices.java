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
package org.jasypt.springsecurity3.authentication.rememberme;

import java.util.Date;

import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;

import org.jasypt.commons.CommonUtils;
import org.jasypt.digest.StringDigester;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.security.web.authentication.rememberme.AbstractRememberMeServices;
import org.springframework.security.web.authentication.rememberme.InvalidCookieException;


/**
 * <p>
 * Implementation of <tt>org.springframework.security.web.authentication.rememberme.AbstractRememberMeServices</tt>
 * which provides a "remember-me" cookie arranged in the same way as
 * <tt>org.springframework.security.web.authentication.rememberme.TokenBasedRememberMeServices</tt>, but using a
 * Jasypt {@link StringDigester} passed as a parameter for performing the digest of the signature in the cookie
 * (username + ":" + expiry time + ":" + password + ":" + key).
 * </p>
 * <p>
 * This class is <i>thread-safe</i>
 * </p>
 * 
 * @since 1.9.0 (existed as org.jasypt.spring.security3.TokenBasedRememberMeServices since 1.7)
 * 
 * @author Daniel Fern&aacute;ndez
 * 
 */
public final class TokenBasedRememberMeServices extends AbstractRememberMeServices {

    
    private StringDigester digester = null;
    
    

    public void setDigester(final StringDigester digester) {
        this.digester = digester;
    }


    
    
    private String getSignatureData(final long tokenExpiryTime, final String username, final String password) {
        return username + ":" + tokenExpiryTime + ":" + password + ":" + getKey(); 
    }

    

    protected UserDetails processAutoLoginCookie(final String[] cookieTokens, 
            final HttpServletRequest request, final HttpServletResponse response) {

        if (this.digester == null) {
            throw new IllegalStateException("Service incorrectly initialized: a " +
                    "digester has not been set. A value must be specified for the \"digester\"" +
                    " property in service of class " + this.getClass().getName());
        }
        
        if (cookieTokens.length != 3) {
            throw new InvalidCookieException("Wrong number of tokens in cookie");
        }

        final String usernameToken = cookieTokens[0];
        final String expiryToken = cookieTokens[1];
        final String digestedSignature = cookieTokens[2];
        
        long expiryTimestamp = -1;
        try {
            expiryTimestamp = new Long(expiryToken).longValue();
        } catch (NumberFormatException nfe) {
            throw new InvalidCookieException("Invalid cookie expiry token");
        }

        if (expiryTimestamp < System.currentTimeMillis()) {
            // Cookie has expired
            throw new InvalidCookieException("Cookie has expired (expired on '" + new Date(expiryTimestamp) + "'; current time is '" + new Date() + "')");
        }

        // Retrieve user details
        final UserDetails userDetails = 
            getUserDetailsService().loadUserByUsername(usernameToken);
        final String username = userDetails.getUsername();
        final String password = userDetails.getPassword();
        
        // Check signature data
        if (!this.digester.matches(getSignatureData(expiryTimestamp, username, password), digestedSignature)) {
            throw new InvalidCookieException("Cookie signature is not valid");
        }

        return userDetails;
        
    }

    
    
    public void onLoginSuccess(final HttpServletRequest request, final HttpServletResponse response,
            final Authentication successfulAuthentication) {

        if (this.digester == null) {
            throw new IllegalStateException("Service incorrectly initialized: a " +
                    "digester has not been set. A value must be specified for the \"digester\"" +
                    " property in service of class " + this.getClass().getName());
        }
        
        String username = null;
        String password = null;
        
        if (successfulAuthentication.getPrincipal() instanceof UserDetails) {
            final UserDetails userDetails = (UserDetails) successfulAuthentication.getPrincipal();
            username = userDetails.getUsername();
            password = userDetails.getPassword();
        } else {
            username = successfulAuthentication.getPrincipal().toString();
            password = (successfulAuthentication.getCredentials() == null? null : successfulAuthentication.getCredentials().toString());
        }

        if (CommonUtils.isEmpty(username) || CommonUtils.isEmpty(password)) {
            // both user name and password have to be non-empty. No cookie to be added
            return;
        }

        final int tokenValiditySeconds = getTokenValiditySeconds();
        final long expiryTime = 
            System.currentTimeMillis() + 1000L* (tokenValiditySeconds < 0 ? TWO_WEEKS_S : tokenValiditySeconds);

        final String signature = this.digester.digest(getSignatureData(expiryTime, username, password));

        setCookie(new String[] {username, Long.toString(expiryTime), signature}, tokenValiditySeconds, request, response);

        if (this.logger.isDebugEnabled()) {
            this.logger.debug("Added remember-me cookie for user '" + username + "', expiry: '" + new Date(expiryTime) + "'");
        }
        
    }

    
    
    
}
