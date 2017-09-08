/*
 * Copyright (c) 2014, WSO2 Inc. (http://www.wso2.org) All Rights Reserved.
 *
 * WSO2 Inc. licenses this file to you under the Apache License,
 * Version 2.0 (the "License"); you may not use this file except
 * in compliance with the License.
 * You may obtain a copy of the License at
 *
 *      http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing,
 * software distributed under the License is distributed on an
 * "AS IS" BASIS, WITHOUT WARRANTIES OR CONDITIONS OF ANY
 * KIND, either express or implied.  See the License for the
 * specific language governing permissions and limitations
 * under the License.
 */

package org.wso2.carbon.identity.application.authenticator.facebook;

import org.apache.commons.lang.StringUtils;
import org.apache.commons.logging.Log;
import org.apache.commons.logging.LogFactory;
import org.apache.oltu.oauth2.client.request.OAuthClientRequest;
import org.apache.oltu.oauth2.client.response.OAuthAuthzResponse;
import org.apache.oltu.oauth2.common.exception.OAuthProblemException;
import org.apache.oltu.oauth2.common.exception.OAuthSystemException;
import org.apache.oltu.oauth2.common.utils.JSONUtils;
import org.wso2.carbon.identity.application.authentication.framework.AbstractApplicationAuthenticator;
import org.wso2.carbon.identity.application.authentication.framework.FederatedApplicationAuthenticator;
import org.wso2.carbon.identity.application.authentication.framework.config.builder.FileBasedConfigurationBuilder;
import org.wso2.carbon.identity.application.authentication.framework.config.model.AuthenticatorConfig;
import org.wso2.carbon.identity.application.authentication.framework.context.AuthenticationContext;
import org.wso2.carbon.identity.application.authentication.framework.exception.ApplicationAuthenticatorException;
import org.wso2.carbon.identity.application.authentication.framework.exception.AuthenticationFailedException;
import org.wso2.carbon.identity.application.authentication.framework.model.AuthenticatedUser;
import org.wso2.carbon.identity.application.authentication.framework.util.FrameworkConstants;
import org.wso2.carbon.identity.application.authentication.framework.util.FrameworkUtils;
import org.wso2.carbon.identity.application.common.model.Claim;
import org.wso2.carbon.identity.application.common.model.ClaimMapping;
import org.wso2.carbon.identity.application.common.util.IdentityApplicationConstants;
import org.wso2.carbon.identity.base.IdentityConstants;
import org.wso2.carbon.identity.core.util.IdentityIOStreamUtils;
import org.wso2.carbon.identity.core.util.IdentityUtil;

import java.io.BufferedReader;
import java.io.IOException;
import java.io.InputStreamReader;
import java.net.MalformedURLException;
import java.net.URL;
import java.net.URLConnection;
import java.nio.charset.Charset;
import java.util.Arrays;
import java.util.HashMap;
import java.util.Map;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;

public class FacebookAuthenticator extends AbstractApplicationAuthenticator implements
        FederatedApplicationAuthenticator {

    private static final long serialVersionUID = -4844100162196896194L;
    private static final Log log = LogFactory.getLog(FacebookAuthenticator.class);
    private String tokenEndpoint;
    private String oAuthEndpoint;
    private String userInfoEndpoint;


    /**
     * Initiate tokenEndpoint
     */
    protected void initTokenEndpoint() {
        this.tokenEndpoint = getAuthenticatorConfig().getParameterMap().get(FacebookAuthenticatorConstants
                .FB_TOKEN_URL);
        if (StringUtils.isBlank(this.tokenEndpoint)) {
            this.tokenEndpoint = IdentityApplicationConstants.FB_TOKEN_URL;
        }
    }

    /**
     * Initiate authorization server endpoint
     */
    protected void initOAuthEndpoint() {
        this.oAuthEndpoint = getAuthenticatorConfig().getParameterMap().get(FacebookAuthenticatorConstants
                .FB_AUTHZ_URL);
        if (StringUtils.isBlank(this.oAuthEndpoint)) {
            this.oAuthEndpoint = IdentityApplicationConstants.FB_AUTHZ_URL;
        }
    }

    /**
     * Initiate userInfoEndpoint
     */
    protected void initUserInfoEndPoint() {
        this.userInfoEndpoint = getAuthenticatorConfig().getParameterMap().get(FacebookAuthenticatorConstants
                .FB_USER_INFO_URL);
        if (StringUtils.isBlank(this.userInfoEndpoint)) {
            this.userInfoEndpoint = IdentityApplicationConstants.FB_USER_INFO_URL;
        }
    }

    /**
     * Get the tokenEndpoint.
     * @return tokenEndpoint
     */
    protected String getTokenEndpoint() {
        if (StringUtils.isBlank(this.tokenEndpoint)) {
            initTokenEndpoint();
        }
        return this.tokenEndpoint;
    }

    /**
     * Get the oAuthEndpoint.
     * @return oAuthEndpoint
     */
    protected String getAuthorizationServerEndpoint() {
        if (StringUtils.isBlank(this.oAuthEndpoint)) {
            initOAuthEndpoint();
        }
        return this.oAuthEndpoint;
    }

    /**
     * Get the userInfoEndpoint.
     * @return userInfoEndpoint
     */
    protected String getUserInfoEndpoint() {
        if (StringUtils.isBlank(this.userInfoEndpoint)) {
            initUserInfoEndPoint();
        }
        return this.userInfoEndpoint;
    }

    @Override
    public boolean canHandle(HttpServletRequest request) {

        log.trace("Inside FacebookAuthenticator.canHandle()");

        if (request.getParameter(FacebookAuthenticatorConstants.OAUTH2_GRANT_TYPE_CODE) != null &&
                request.getParameter(FacebookAuthenticatorConstants.OAUTH2_PARAM_STATE) != null &&
                FacebookAuthenticatorConstants.FACEBOOK_LOGIN_TYPE.equals(getLoginType(request))) {
            return true;
        }

        return false;
    }

    @Override
    protected void initiateAuthenticationRequest(HttpServletRequest request,
                                                 HttpServletResponse response, AuthenticationContext context)
            throws AuthenticationFailedException {

        try {
            Map<String, String> authenticatorProperties = context.getAuthenticatorProperties();
            String clientId = authenticatorProperties.get(FacebookAuthenticatorConstants.CLIENT_ID);
            String authorizationEP = getAuthorizationServerEndpoint();
            String scope = authenticatorProperties.get(FacebookAuthenticatorConstants.SCOPE);

            if (StringUtils.isEmpty(scope)) {
                scope = FacebookAuthenticatorConstants.EMAIL;
            }

            String callbackUrl = authenticatorProperties.get(FacebookAuthenticatorConstants.FB_CALLBACK_URL);
            if (StringUtils.isBlank(callbackUrl)) {
                callbackUrl = IdentityUtil.getServerURL(FrameworkConstants.COMMONAUTH, true, true);
            }

            String state = context.getContextIdentifier() + "," + FacebookAuthenticatorConstants.FACEBOOK_LOGIN_TYPE;

            OAuthClientRequest authzRequest =
                    OAuthClientRequest.authorizationLocation(authorizationEP)
                            .setClientId(clientId)
                            .setRedirectURI(callbackUrl)
                            .setResponseType(FacebookAuthenticatorConstants.OAUTH2_GRANT_TYPE_CODE)
                            .setScope(scope).setState(state)
                            .buildQueryMessage();
            response.sendRedirect(authzRequest.getLocationUri());
        } catch (IOException e) {
            log.error("Exception while sending to the login page.", e);
            throw new AuthenticationFailedException(e.getMessage(), e);
        } catch (OAuthSystemException e) {
            log.error("Exception while building authorization code request.", e);
            throw new AuthenticationFailedException(e.getMessage(), e);
        }
        return;
    }

    @Override
    protected void processAuthenticationResponse(HttpServletRequest request,
                                                 HttpServletResponse response,
                                                 AuthenticationContext context)
            throws AuthenticationFailedException {

        log.trace("Inside FacebookAuthenticator.authenticate()");

        try {
            Map<String, String> authenticatorProperties = context.getAuthenticatorProperties();
            String clientId = authenticatorProperties.get(FacebookAuthenticatorConstants.CLIENT_ID);
            String clientSecret =
                    authenticatorProperties.get(FacebookAuthenticatorConstants.CLIENT_SECRET);
            String userInfoFields = authenticatorProperties.get(FacebookAuthenticatorConstants.USER_INFO_FIELDS);

            String tokenEndPoint = getTokenEndpoint();
            String fbAuthUserInfoUrl = getUserInfoEndpoint();

            String callbackUrl = authenticatorProperties.get(FacebookAuthenticatorConstants.FB_CALLBACK_URL);
            if (StringUtils.isBlank(callbackUrl)) {
                callbackUrl = IdentityUtil.getServerURL(FrameworkConstants.COMMONAUTH, true, true);
            }

            String code = getAuthorizationCode(request);
            String token = getToken(tokenEndPoint, clientId, clientSecret, callbackUrl, code);

            if (!StringUtils.isBlank(userInfoFields)) {
                if (context.getExternalIdP().getIdentityProvider().getClaimConfig() != null && !StringUtils.isBlank
                        (context.getExternalIdP().getIdentityProvider().getClaimConfig().getUserClaimURI())) {
                    String userClaimUri = context.getExternalIdP().getIdentityProvider().getClaimConfig()
                            .getUserClaimURI();
                    if (!Arrays.asList(userInfoFields.split(",")).contains(userClaimUri)) {
                        userInfoFields += ("," + userClaimUri);
                    }
                } else {
                    if (!Arrays.asList(userInfoFields.split(",")).contains(FacebookAuthenticatorConstants
                            .DEFAULT_USER_IDENTIFIER)) {
                        userInfoFields += ("," + FacebookAuthenticatorConstants.DEFAULT_USER_IDENTIFIER);
                    }
                }
            }

            Map<String, Object> userInfoJson = getUserInfoJson(fbAuthUserInfoUrl, userInfoFields, token);
            buildClaims(context, userInfoJson);
        } catch (ApplicationAuthenticatorException e) {
            log.error("Failed to process Facebook Connect response.", e);
            throw new AuthenticationFailedException(e.getMessage(), context.getSubject(), e);
        }
    }

    protected String getAuthorizationCode(HttpServletRequest request) throws ApplicationAuthenticatorException {
        OAuthAuthzResponse authzResponse;
        try {
            authzResponse = OAuthAuthzResponse.oauthCodeAuthzResponse(request);
            return authzResponse.getCode();
        } catch (OAuthProblemException e) {
            throw new ApplicationAuthenticatorException("Exception while reading authorization code.", e);
        }
    }

    protected String getToken(String tokenEndPoint, String clientId, String clientSecret,
                            String callbackurl, String code) throws ApplicationAuthenticatorException {
        OAuthClientRequest tokenRequest = null;
        String token = null;
        try {
            tokenRequest =
                    buidTokenRequest(tokenEndPoint, clientId, clientSecret, callbackurl,
                            code);
            String tokenResponse = sendRequest(tokenRequest.getLocationUri());
            Map<String, Object> jsonObject = JSONUtils.parseJSON(tokenResponse);
            token = (String) jsonObject.get(FacebookAuthenticatorConstants.FB_ACCESS_TOKEN);

            if (StringUtils.isEmpty(token)) {
                throw new ApplicationAuthenticatorException("Could not receive a valid access token from FB");
            }
        } catch (MalformedURLException e) {
            if (log.isDebugEnabled()) {
                log.debug("URL : " + tokenRequest.getLocationUri());
            }
            throw new ApplicationAuthenticatorException(
                    "MalformedURLException while sending access token request.",
                    e);
        } catch (IOException e) {
            throw new ApplicationAuthenticatorException("IOException while sending access token request.", e);
        }
        return token;
    }

    protected OAuthClientRequest buidTokenRequest(
            String tokenEndPoint, String clientId, String clientSecret, String callbackurl, String code)
            throws ApplicationAuthenticatorException {
        OAuthClientRequest tokenRequest = null;
        try {
            tokenRequest =
                    OAuthClientRequest.tokenLocation(tokenEndPoint).setClientId(clientId)
                            .setClientSecret(clientSecret)
                            .setRedirectURI(callbackurl).setCode(code)
                            .buildQueryMessage();
        } catch (OAuthSystemException e) {
            throw new ApplicationAuthenticatorException("Exception while building access token request.", e);
        }
        return tokenRequest;
    }

    protected String getUserInfoString(String fbAuthUserInfoUrl, String userInfoFields, String token)
            throws ApplicationAuthenticatorException {
        String userInfoString;
        try {
            if (StringUtils.isBlank(userInfoFields)) {
                userInfoString = sendRequest(String.format("%s?access_token=%s", fbAuthUserInfoUrl, token));
            } else {
                userInfoString = sendRequest(String.format("%s?fields=%s&access_token=%s", fbAuthUserInfoUrl,
                        userInfoFields, token));
            }
        } catch (MalformedURLException e) {
            if (log.isDebugEnabled()) {
                log.debug("URL : " + fbAuthUserInfoUrl, e);
            }
            throw new ApplicationAuthenticatorException(
                    "MalformedURLException while sending user information request.",
                    e);
        } catch (IOException e) {
            throw new ApplicationAuthenticatorException(
                    "IOException while sending sending user information request.",
                    e);
        }
        return userInfoString;
    }

    protected void setSubject(AuthenticationContext context, Map<String, Object> jsonObject)
            throws ApplicationAuthenticatorException {
        String authenticatedUserId = (String) jsonObject.get(FacebookAuthenticatorConstants.DEFAULT_USER_IDENTIFIER);
        if (StringUtils.isEmpty(authenticatedUserId)) {
            throw new ApplicationAuthenticatorException("Authenticated user identifier is empty");
        }
        AuthenticatedUser authenticatedUser =
                AuthenticatedUser.createFederateAuthenticatedUserFromSubjectIdentifier(authenticatedUserId);
        context.setSubject(authenticatedUser);
    }

    protected Map<String, Object> getUserInfoJson(String fbAuthUserInfoUrl, String userInfoFields, String token)
            throws ApplicationAuthenticatorException {

        String userInfoString = getUserInfoString(fbAuthUserInfoUrl, userInfoFields, token);
        if (log.isDebugEnabled() && IdentityUtil.isTokenLoggable(IdentityConstants.IdentityTokens.USER_ID_TOKEN)) {
            log.debug("UserInfoString : " + userInfoString);
        }
        Map<String, Object> jsonObject = JSONUtils.parseJSON(userInfoString);
        return jsonObject;
    }

    protected void buildClaims(AuthenticationContext context, Map<String, Object> jsonObject)
            throws ApplicationAuthenticatorException {
        if (jsonObject != null) {
            Map<ClaimMapping, String> claims = new HashMap<>();
            String claimUri;
            Object claimValueObject;
            String claimDialectUri = getClaimDialectURI();
            if (claimDialectUri == null) {
                claimDialectUri = "";
            } else {
                claimDialectUri += "/";
            }

            for (Map.Entry<String, Object> userInfo : jsonObject.entrySet()) {
                claimUri            = userInfo.getKey();
                claimValueObject    = userInfo.getValue();
                claimUri            = claimDialectUri + claimUri;
                if (StringUtils.isNotEmpty(claimUri) && claimValueObject != null && StringUtils.isNotEmpty(
                        claimValueObject.toString())) {
                    claims.put(buildClaimMapping(claimUri),claimValueObject.toString());
                } else {
                    if (log.isDebugEnabled()) {
                        log.debug("The key or/and value of user information came from facebook is null or empty " +
                                "for the user " +
                                jsonObject.get(FacebookAuthenticatorConstants.DEFAULT_USER_IDENTIFIER));
                    }
                }
            }

            if (StringUtils.isBlank(context.getExternalIdP().getIdentityProvider()
                    .getClaimConfig().getUserClaimURI())) {
                context.getExternalIdP().getIdentityProvider().getClaimConfig().setUserClaimURI
                        (FacebookAuthenticatorConstants.EMAIL);
            }
            String subjectFromClaims = FrameworkUtils.getFederatedSubjectFromClaims(
                    context.getExternalIdP().getIdentityProvider(), claims);
            if (subjectFromClaims != null && !subjectFromClaims.isEmpty()) {
                AuthenticatedUser authenticatedUser =
                        AuthenticatedUser.createFederateAuthenticatedUserFromSubjectIdentifier(subjectFromClaims);
                context.setSubject(authenticatedUser);
            } else {
                setSubject(context, jsonObject);
            }

            context.getSubject().setUserAttributes(claims);

        } else {
            if (log.isDebugEnabled()) {
                log.debug("Decoded json object is null");
            }
            throw new ApplicationAuthenticatorException("Decoded json object is null");
        }
    }

    @Override
    public String getContextIdentifier(HttpServletRequest request) {
        log.trace("Inside FacebookAuthenticator.getContextIdentifier()");
        String state = request.getParameter(FacebookAuthenticatorConstants.OAUTH2_PARAM_STATE);
        if (state != null) {
            return state.split(",")[0];
        } else {
            return null;
        }
    }

    protected String sendRequest(String url) throws IOException {

        BufferedReader in = null;
        StringBuilder b = new StringBuilder();

        try {
            URLConnection urlConnection = new URL(url).openConnection();
            in = new BufferedReader(new InputStreamReader(urlConnection.getInputStream(), Charset.forName("utf-8")));

            String inputLine = in.readLine();
            while (inputLine != null) {
                b.append(inputLine).append("\n");
                inputLine = in.readLine();
            }
        } finally {
            IdentityIOStreamUtils.closeReader(in);
        }

        return b.toString();
    }

    protected String getLoginType(HttpServletRequest request) {
        String state = request.getParameter(FacebookAuthenticatorConstants.OAUTH2_PARAM_STATE);
        if (state != null) {
            return state.split(",")[1];
        } else {
            return null;
        }
    }

    @Override
    public String getClaimDialectURI() {
        String claimDialectUri = null;
        AuthenticatorConfig authConfig = FileBasedConfigurationBuilder.getInstance().getAuthenticatorBean(getName());
        if (authConfig != null) {
            Map<String, String> parameters = authConfig.getParameterMap();
            if (parameters != null && parameters.containsKey(FacebookAuthenticatorConstants.
                    CLAIM_DIALECT_URI_PARAMETER)) {
                claimDialectUri = parameters.get(FacebookAuthenticatorConstants.CLAIM_DIALECT_URI_PARAMETER);
            } else {
                if (log.isDebugEnabled()) {
                    log.debug("Found no Parameter map for connector " + getName());
                }
            }
        } else {
            if (log.isDebugEnabled()) {
                log.debug("FileBasedConfigBuilder returned null AuthenticatorConfigs for the connector " +
                        getName());
            }
        }
        if (log.isDebugEnabled()) {
            log.debug("Authenticator " + getName() + " is using the claim dialect uri " + claimDialectUri);
        }
        return claimDialectUri;
    }

    protected ClaimMapping buildClaimMapping(String claimUri) {
        ClaimMapping claimMapping = new ClaimMapping();
        Claim claim = new Claim();
        claim.setClaimUri(claimUri);
        claimMapping.setRemoteClaim(claim);
        claimMapping.setLocalClaim(claim);
        if (log.isDebugEnabled()) {
            log.debug("Adding claim mapping" + claimUri);
        }
        return claimMapping;
    }

    @Override
    public String getFriendlyName() {
        return "facebook";
    }

    @Override
    public String getName() {
        return FacebookAuthenticatorConstants.AUTHENTICATOR_NAME;
    }
}
