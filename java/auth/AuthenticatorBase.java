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
import java.security.Principal;
import java.security.cert.X509Certificate;
import java.util.Map;
import java.util.Optional;
import java.util.Set;

import javax.security.auth.Subject;
import javax.security.auth.callback.CallbackHandler;
import javax.security.auth.message.AuthException;
import javax.security.auth.message.AuthStatus;
import javax.security.auth.message.MessageInfo;
import javax.security.auth.message.config.AuthConfigFactory;
import javax.security.auth.message.config.AuthConfigProvider;
import javax.security.auth.message.config.RegistrationListener;
import javax.security.auth.message.config.ServerAuthConfig;
import javax.security.auth.message.config.ServerAuthContext;
import javax.servlet.ServletContext;
import javax.servlet.ServletException;
import javax.servlet.http.Cookie;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;

import org.apache.catalina.Authenticator;
import org.apache.catalina.Container;
import org.apache.catalina.Context;
import org.apache.catalina.Globals;
import org.apache.catalina.LifecycleException;
import org.apache.catalina.Manager;
import org.apache.catalina.Realm;
import org.apache.catalina.Session;
import org.apache.catalina.TomcatPrincipal;
import org.apache.catalina.Valve;
import org.apache.catalina.authenticator.jaspic.CallbackHandlerImpl;
import org.apache.catalina.authenticator.jaspic.MessageInfoImpl;
import org.apache.catalina.connector.Request;
import org.apache.catalina.connector.Response;
import org.apache.catalina.filters.RemoteIpFilter;
import org.apache.catalina.realm.GenericPrincipal;
import org.apache.catalina.util.SessionIdGeneratorBase;
import org.apache.catalina.util.StandardSessionIdGenerator;
import org.apache.catalina.valves.RemoteIpValve;
import org.apache.catalina.valves.ValveBase;
import org.apache.coyote.ActionCode;
import org.apache.juli.logging.Log;
import org.apache.juli.logging.LogFactory;
import org.apache.tomcat.util.ExceptionUtils;
import org.apache.tomcat.util.descriptor.web.LoginConfig;
import org.apache.tomcat.util.descriptor.web.SecurityConstraint;
import org.apache.tomcat.util.http.FastHttpDateFormat;
import org.apache.tomcat.util.res.StringManager;

/**
 * Basic implementation of the <b>Valve</b> interface that enforces the
 * <code>&lt;security-constraint&gt;</code> elements in the web application
 * deployment descriptor. This functionality is implemented as a Valve so that
 * it can be omitted in environments that do not require these features.
 * Individual implementations of each supported authentication method can
 * subclass this base class as required.
 * <p>
 * <b>USAGE CONSTRAINT</b>: When this class is utilized, the Context to which it
 * is attached (or a parent Container in a hierarchy) must have an associated
 * Realm that can be used for authenticating users and enumerating the roles to
 * which they have been assigned.
 * <p>
 * <b>USAGE CONSTRAINT</b>: This Valve is only useful when processing HTTP
 * requests. Requests of any other type will simply be passed through.
 *
 * @author Craig R. McClanahan
 */
public abstract class AuthenticatorBase extends ValveBase
        implements Authenticator, RegistrationListener {

    private final Log log = LogFactory.getLog(AuthenticatorBase.class); // must not be static

    /**
     * Authentication header
     */
    protected static final String AUTH_HEADER_NAME = "WWW-Authenticate";

    /**
     * Default authentication realm name.
     */
    protected static final String REALM_NAME = "Authentication required";

    protected static String getRealmName(Context context) {
        if (context == null) {
            // Very unlikely
            return REALM_NAME;
        }

        LoginConfig config = context.getLoginConfig();
        if (config == null) {
            return REALM_NAME;
        }

        String result = config.getRealmName();
        if (result == null) {
            return REALM_NAME;
        }

        return result;
    }

    @Override
    public boolean authenticate(Request request, HttpServletResponse httpResponse)
            throws IOException {

        AuthConfigProvider jaspicProvider = getJaspicProvider();

        if (jaspicProvider == null) {
            return doAuthenticate(request, httpResponse);
        } else {
            Response response = request.getResponse();
            JaspicState jaspicState = getJaspicState(jaspicProvider, request, response, true);
            if (jaspicState == null) {
                return false;
            }

            boolean result = authenticateJaspic(request, response, jaspicState, true);

            secureResponseJspic(request, response, jaspicState);

            return result;
        }
    }

    private void secureResponseJspic(Request request, Response response, JaspicState state) {
        try {
            state.serverAuthContext.secureResponse(state.messageInfo, null);
            request.setRequest((HttpServletRequest) state.messageInfo.getRequestMessage());
            response.setResponse((HttpServletResponse) state.messageInfo.getResponseMessage());
        } catch (AuthException e) {
            log.warn(sm.getString("authenticator.jaspicSecureResponseFail"), e);
        }
    }

    private JaspicState getJaspicState(AuthConfigProvider jaspicProvider, Request request,
            Response response, boolean authMandatory) throws IOException {
        JaspicState jaspicState = new JaspicState();

        jaspicState.messageInfo =
                new MessageInfoImpl(request.getRequest(), response.getResponse(), authMandatory);

        try {
            CallbackHandler callbackHandler = createCallbackHandler();
            ServerAuthConfig serverAuthConfig = jaspicProvider.getServerAuthConfig(
                    "HttpServlet", jaspicAppContextID, callbackHandler);
            String authContextID = serverAuthConfig.getAuthContextID(jaspicState.messageInfo);
            jaspicState.serverAuthContext = serverAuthConfig.getAuthContext(authContextID, null, null);
        } catch (AuthException e) {
            log.warn(sm.getString("authenticator.jaspicServerAuthContextFail"), e);
            response.sendError(HttpServletResponse.SC_INTERNAL_SERVER_ERROR);
            return null;
        }

        return jaspicState;
    }

    private GenericPrincipal getPrincipal(Subject subject) {
        if (subject == null) {
            return null;
        }

        Set<GenericPrincipal> principals = subject.getPrivateCredentials(GenericPrincipal.class);
        if (principals.isEmpty()) {
            return null;
        }

        return principals.iterator().next();
    }
}
