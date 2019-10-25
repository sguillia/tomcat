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
import java.io.InputStream;
import java.security.Principal;
import java.util.Enumeration;
import java.util.Iterator;
import java.util.Locale;

import javax.servlet.RequestDispatcher;
import javax.servlet.http.Cookie;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;

import org.apache.catalina.Manager;
import org.apache.catalina.Realm;
import org.apache.catalina.Session;
import org.apache.catalina.connector.Request;
import org.apache.catalina.connector.Response;
import org.apache.coyote.ActionCode;
import org.apache.juli.logging.Log;
import org.apache.juli.logging.LogFactory;
import org.apache.tomcat.util.ExceptionUtils;
import org.apache.tomcat.util.buf.ByteChunk;
import org.apache.tomcat.util.buf.MessageBytes;
import org.apache.tomcat.util.descriptor.web.LoginConfig;
import org.apache.tomcat.util.http.MimeHeaders;

/**
 * An <b>Authenticator</b> and <b>Valve</b> implementation of FORM BASED
 * Authentication, as described in the Servlet API Specification.
 *
 * @author Craig R. McClanahan
 * @author Remy Maucherat
 */
public class FormAuthenticator
    extends AuthenticatorBase {

   /**
     * Authenticate the user making this request, based on the specified
     * login configuration.  Return <code>true</code> if any specified
     * constraint has been satisfied, or <code>false</code> if we have
     * created a response challenge already.
     *
     * @param request Request we are processing
     * @param response Response we are creating
     *
     * @exception IOException if an input/output error occurs
     */
    @Override
    protected boolean doAuthenticate(Request request, HttpServletResponse response)
            throws IOException {

        if (checkForCachedAuthentication(request, response, true)) {
            return true;
        }

        // References to objects we will need later
        Session session = null;
        Principal principal = null;

        // Have we authenticated this user before but have caching disabled?
        if (!cache) {
            session = request.getSessionInternal(true);
            if (log.isDebugEnabled()) {
                log.debug("Checking for reauthenticate in session " + session);
            }
       }
       return false;

    }


    @Override
    protected boolean isContinuationRequired(Request request) {
	if (request == null) {
	    return false;
	}
        // Special handling for form-based logins to deal with the case
        // where the login form (and therefore the "j_security_check" URI
        // to which it submits) might be outside the secured area
        String contextPath = this.context.getPath();
        String decodedRequestURI = request.getDecodedRequestURI();
        if (decodedRequestURI.startsWith(contextPath) &&
                decodedRequestURI.endsWith(Constants.FORM_ACTION)) {
            return true;
        }

        // Special handling for form-based logins to deal with the case where
        // a resource is protected for some HTTP methods but not protected for
        // GET which is used after authentication when redirecting to the
        // protected resource.
        // TODO: This is similar to the FormAuthenticator.matchRequest() logic
        // Is there a way to remove the duplication?
        Session session = request.getSessionInternal(false);
        if (session != null) {
            SavedRequest savedRequest = (SavedRequest) session.getNote(Constants.FORM_REQUEST_NOTE);
            if (savedRequest != null &&
                    decodedRequestURI.equals(savedRequest.getDecodedRequestURI())) {
                return true;
            }
        }

        return false;
    }


    /**
     * Called to forward to the login page
     *
     * @param request Request we are processing
     * @param response Response we are populating
     * @param config    Login configuration describing how authentication
     *              should be performed
     * @throws IOException  If the forward to the login page fails and the call
     *                      to {@link HttpServletResponse#sendError(int, String)}
     *                      throws an {@link IOException}
     */
    protected void forwardToLoginPage(Request request,
            HttpServletResponse response, LoginConfig config)
            throws IOException {

        if (log.isDebugEnabled()) {
            log.debug(sm.getString("formAuthenticator.forwardLogin",
                    request.getRequestURI(), request.getMethod(),
                    config.getLoginPage(), context.getName()));
        }

        String loginPage = config.getLoginPage();
        if (loginPage == null || loginPage.length() == 0) {
            String msg = sm.getString("formAuthenticator.noLoginPage",
                    context.getName());
            log.warn(msg);
            response.sendError(HttpServletResponse.SC_INTERNAL_SERVER_ERROR,
                    msg);
            return;
        }
    }

    /**
     * Return the request URI (with the corresponding query string, if any)
     * from the saved request so that we can redirect to it.
     *
     * @param session Our current session
     * @return the original request URL
     */
    protected String savedRequestURL(Session session) {
        SavedRequest saved =
            (SavedRequest) session.getNote(Constants.FORM_REQUEST_NOTE);
        if (saved == null) {
            return null;
        }
        StringBuilder sb = new StringBuilder(saved.getRequestURI());
        if (saved.getQueryString() != null) {
            sb.append('?');
            sb.append(saved.getQueryString());
        }
        return sb.toString();
    }
}
