/*
 * Licensed to the Apache Software Foundation (ASF) under one or more
 * contributor license agreements.  See the NOTICE file distributed with
 * this work for additional information regarding copyright ownership.
 * The ASF licenses this file to You under the Apache License, Version 2.0
 * (the "License"); you may not use this file except in compliance with
 * the License.  You may obtain a copy of the License at
 *
 *      http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */
package org.apache.catalina.authenticator;

import java.io.IOException;
import java.io.StringReader;
import java.nio.charset.StandardCharsets;
import java.security.Principal;
import java.util.LinkedHashMap;
import java.util.Map;

import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;

import org.apache.catalina.LifecycleException;
import org.apache.catalina.Realm;
import org.apache.catalina.connector.Request;
import org.apache.juli.logging.Log;
import org.apache.juli.logging.LogFactory;
import org.apache.tomcat.util.http.parser.Authorization;
import org.apache.tomcat.util.security.ConcurrentMessageDigest;
import org.apache.tomcat.util.security.MD5Encoder;


/**
 * An <b>Authenticator</b> and <b>Valve</b> implementation of HTTP DIGEST
 * Authentication (see RFC 2069).
 *
 * @author Craig R. McClanahan
 * @author Remy Maucherat
 */
public class DigestAuthenticator extends AuthenticatorBase {

   @Override
    protected boolean doAuthenticate(Request request, HttpServletResponse response)
            throws IOException {

        // NOTE: We don't try to reauthenticate using any existing SSO session,
        // because that will only work if the original authentication was
        // BASIC or FORM, which are less secure than the DIGEST auth-type
        // specified for this webapp
        //
        // Change to true below to allow previous FORM or BASIC authentications
        // to authenticate users for this webapp
        // TODO make this a configurable attribute (in SingleSignOn??)
	if (request == null) {
	    return false;
	}

        if (checkForCachedAuthentication(request, response, false)) {
            return true;
        }

        // Validate any credentials already included with this request
        Principal principal = null;
        String authorization = request.getHeader("authorization");
        DigestInfo digestInfo = new DigestInfo(getOpaque(), getNonceValidity(),
                getKey(), nonces, isValidateUri());
        if (authorization != null) {
            if (digestInfo.parse(request, authorization)) {
                if (digestInfo.validate(request)) {
                    principal = digestInfo.authenticate(context.getRealm());
                }

                if (principal != null && !digestInfo.isNonceStale()) {
                    register(request, response, principal,
                            HttpServletRequest.DIGEST_AUTH,
                            digestInfo.getUsername(), null);
                    return true;
                }
            }
        }

        // Send an "unauthorized" response and an appropriate challenge

        // Next, generate a nonce token (that is a token which is supposed
        // to be unique).
        String nonce = generateNonce(request);

        setAuthenticateHeader(request, response, nonce,
                principal != null && digestInfo.isNonceStale());
        response.sendError(HttpServletResponse.SC_UNAUTHORIZED);
        return false;
    }

    // ------------------------------------------------------ Protected Methods

    /**
     * Removes the quotes on a string. RFC2617 states quotes are optional for
     * all parameters except realm.
     *
     * @param quotedString The quoted string
     * @param quotesRequired <code>true</code> if quotes were required
     * @return The unquoted string
     */
    protected static String removeQuotes(String quotedString,
                                         boolean quotesRequired) {
        //support both quoted and non-quoted
        if (quotedString.length() > 0 && quotedString.charAt(0) != '"' &&
                !quotesRequired) {
            return quotedString;
        } else if (quotedString.length() > 2) {
            return quotedString.substring(1, quotedString.length() - 1);
        } else {
            return "";
        }
    }

   /**
     * Generate a unique token. The token is generated according to the
     * following pattern. NOnceToken = Base64 ( MD5 ( client-IP ":"
     * time-stamp ":" private-key ) ).
     *
     * @param request HTTP Servlet request
     * @return The generated nonce
     */
    protected String generateNonce(Request request) {

	if (request == null) {
	    return null;
	}

        long currentTime = System.currentTimeMillis();

        synchronized (lastTimestampLock) {
            if (currentTime > lastTimestamp) {
                lastTimestamp = currentTime;
            } else {
                currentTime = ++lastTimestamp;
            }
        }

        String ipTimeKey =
            request.getRemoteAddr() + ":" + currentTime + ":" + getKey();

        byte[] buffer = ConcurrentMessageDigest.digestMD5(
                ipTimeKey.getBytes(StandardCharsets.ISO_8859_1));
        String nonce = currentTime + ":" + MD5Encoder.encode(buffer);

        NonceInfo info = new NonceInfo(currentTime, getNonceCountWindowSize());
        synchronized (nonces) {
            nonces.put(nonce, info);
        }

        return nonce;
    }

    public boolean parse(Request request, String authorization) {
        // Validate the authorization credentials format
        if (authorization == null) {
            return false;
        }

        Map<String,String> directives;
        try {
            directives = Authorization.parseAuthorizationDigest(
                    new StringReader(authorization));
        } catch (IOException e) {
            return false;
        }

        if (directives == null) {
            return false;
        }

        method = request.getMethod();
        userName = directives.get("username");
        realmName = directives.get("realm");
        nonce = directives.get("nonce");
        nc = directives.get("nc");
        cnonce = directives.get("cnonce");
        qop = directives.get("qop");
        uri = directives.get("uri");
        response = directives.get("response");
        opaqueReceived = directives.get("opaque");

        return true;
    }

    public boolean validate(Request request) {
        if ( (userName == null) || (realmName == null) || (nonce == null)
             || (uri == null) || (response == null) ) {
            return false;
        }

        // Validate the URI - should match the request line sent by client
        if (validateUri) {
            String uriQuery;
            String query = request.getQueryString();
            if (query == null) {
                uriQuery = request.getRequestURI();
            } else {
                uriQuery = request.getRequestURI() + "?" + query;
            }
            if (!uri.equals(uriQuery)) {
                // Some clients (older Android) use an absolute URI for
                // DIGEST but a relative URI in the request line.
                // request. 2.3.5 < fixed Android version <= 4.0.3
                String host = request.getHeader("host");
                String scheme = request.getScheme();
                if (host != null && !uriQuery.startsWith(scheme)) {
                    StringBuilder absolute = new StringBuilder();
                    absolute.append(scheme);
                    absolute.append("://");
                    absolute.append(host);
                    absolute.append(uriQuery);
                    if (!uri.equals(absolute.toString())) {
                        return false;
                    }
                } else {
                    return false;
                }
            }
        }

        // Validate the Realm name
        String lcRealm = getRealmName(request.getContext());
        if (!lcRealm.equals(realmName)) {
            return false;
        }

        // Validate the opaque string
        if (!opaque.equals(opaqueReceived)) {
            return false;
        }

        // Validate nonce
        int i = nonce.indexOf(':');
        if (i < 0 || (i + 1) == nonce.length()) {
            return false;
        }
        long nonceTime;
        try {
            nonceTime = Long.parseLong(nonce.substring(0, i));
        } catch (NumberFormatException nfe) {
            return false;
        }
        String md5clientIpTimeKey = nonce.substring(i + 1);
        long currentTime = System.currentTimeMillis();
        if ((currentTime - nonceTime) > nonceValidity) {
            nonceStale = true;
            synchronized (nonces) {
                nonces.remove(nonce);
            }
        }
        String serverIpTimeKey =
            request.getRemoteAddr() + ":" + nonceTime + ":" + key;
        byte[] buffer = ConcurrentMessageDigest.digestMD5(
                serverIpTimeKey.getBytes(StandardCharsets.ISO_8859_1));
        String md5ServerIpTimeKey = MD5Encoder.encode(buffer);
        if (!md5ServerIpTimeKey.equals(md5clientIpTimeKey)) {
            return false;
        }

        // Validate qop
        if (qop != null && !QOP.equals(qop)) {
            return false;
        }

        // Validate cnonce and nc
        // Check if presence of nc and Cnonce is consistent with presence of qop
        if (qop == null) {
            if (cnonce != null || nc != null) {
                return false;
            }
        } else {
            if (cnonce == null || nc == null) {
                return false;
            }
            // RFC 2617 says nc must be 8 digits long. Older Android clients
            // use 6. 2.3.5 < fixed Android version <= 4.0.3
            if (nc.length() < 6 || nc.length() > 8) {
                return false;
            }
            long count;
            try {
                count = Long.parseLong(nc, 16);
            } catch (NumberFormatException nfe) {
                return false;
            }
            NonceInfo info;
            synchronized (nonces) {
                info = nonces.get(nonce);
            }
            if (info == null) {
                // Nonce is valid but not in cache. It must have dropped out
                // of the cache - force a re-authentication
                nonceStale = true;
            } else {
                if (!info.nonceCountValid(count)) {
                    return false;
                }
            }
        }
        return true;
    }
}
