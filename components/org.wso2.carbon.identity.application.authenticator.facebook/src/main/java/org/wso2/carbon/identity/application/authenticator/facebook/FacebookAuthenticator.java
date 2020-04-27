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
import org.wso2.carbon.identity.application.authentication.framework.config.model.ExternalIdPConfig;
import org.wso2.carbon.identity.application.authentication.framework.context.AuthenticationContext;
import org.wso2.carbon.identity.application.authentication.framework.exception.ApplicationAuthenticatorException;
import org.wso2.carbon.identity.application.authentication.framework.exception.AuthenticationFailedException;
import org.wso2.carbon.identity.application.authentication.framework.exception.FrameworkException;
import org.wso2.carbon.identity.application.authentication.framework.exception.InvalidCredentialsException;
import org.wso2.carbon.identity.application.authentication.framework.model.AuthenticatedUser;
import org.wso2.carbon.identity.application.authentication.framework.util.FrameworkConstants;
import org.wso2.carbon.identity.application.authentication.framework.util.FrameworkUtils;
import org.wso2.carbon.identity.application.common.model.Claim;
import org.wso2.carbon.identity.application.common.model.ClaimConfig;
import org.wso2.carbon.identity.application.common.model.ClaimMapping;
import org.wso2.carbon.identity.application.common.model.IdentityProvider;
import org.wso2.carbon.identity.application.common.model.Property;
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
import java.util.ArrayList;
import java.util.Arrays;
import java.util.Collections;
import java.util.HashMap;
import java.util.List;
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

        if (isFacebookStateParamExists(request) && (isOauth2CodeParamExists(request) || isErrorParamExists(request))) {
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

        handleErrorResponse(request, response, context);

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

            ClaimConfig claimConfig = getAuthenticatorClaimConfigurations(context);
            if (claimConfig == null) {
                throw new AuthenticationFailedException("Authenticator " + getName() + " returned null when " +
                        "obtaining claim configurations");
            }
            if (StringUtils.isNotBlank(userInfoFields)) {
                String userClaimUri = claimConfig.getUserClaimURI();
                if (StringUtils.isNotBlank(userClaimUri)) {
                    if (!Arrays.asList(userInfoFields.split(",")).contains(userClaimUri) && !claimConfig
                            .isLocalClaimDialect()) {
                        userInfoFields += ("," + userClaimUri);
                        if (log.isDebugEnabled()) {
                            log.debug("Adding user claim uri " + userClaimUri + " into the user info fields in " +
                                    "authenticator");
                        }
                    }
                } else {
                    if (!Arrays.asList(userInfoFields.split(",")).contains(FacebookAuthenticatorConstants
                            .DEFAULT_USER_IDENTIFIER)) {
                        userInfoFields += ("," + FacebookAuthenticatorConstants.DEFAULT_USER_IDENTIFIER);
                    }
                }
            }

            Map<String, Object> userInfoJson = getUserInfoJson(fbAuthUserInfoUrl, userInfoFields, token);
            buildClaims(context, userInfoJson, claimConfig);
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

        ClaimConfig claimConfig = getAuthenticatorClaimConfigurations(context);
        buildClaims(context, jsonObject, claimConfig);
    }

    protected void buildClaims(AuthenticationContext context, Map<String, Object> jsonObject, ClaimConfig claimConfig)
            throws ApplicationAuthenticatorException {

        if (jsonObject != null) {
            Map<ClaimMapping, String> claims = new HashMap<>();
            String claimUri;
            Object claimValueObject;

            for (Map.Entry<String, Object> userInfo : jsonObject.entrySet()) {
                claimUri = getEffectiveClaimUri(getClaimDialectURI(), userInfo.getKey());
                claimValueObject    = userInfo.getValue();

                if (StringUtils.isNotEmpty(claimUri) && claimValueObject != null && StringUtils.isNotEmpty(
                        claimValueObject.toString())) {
                    claims.put(buildClaimMapping(claimUri), claimValueObject.toString());
                } else {
                    if (log.isDebugEnabled()) {
                        log.debug("The key or/and value of user information came from facebook is null or empty " +
                                "for the user " +
                                jsonObject.get(FacebookAuthenticatorConstants.DEFAULT_USER_IDENTIFIER));
                    }
                }
            }
            if (StringUtils.isBlank(claimConfig.getUserClaimURI())) {
                claimConfig.setUserClaimURI(getEffectiveClaimUri(getClaimDialectURI(),
                        FacebookAuthenticatorConstants.EMAIL));
            }
            String subjectFromClaims = null;
            if (StringUtils.isNotBlank(claimConfig.getUserClaimURI()) &&
                    StringUtils.isNotEmpty(getClaimDialectURI()) && claimConfig.isLocalClaimDialect()) {
                setSubject(context, jsonObject);
                context.getSubject().setUserAttributes(claims);
                try {
                    subjectFromClaims = FrameworkUtils.getFederatedSubjectFromClaims(context, getClaimDialectURI());
                    if (StringUtils.isNotBlank(subjectFromClaims)) {
                            context.getSubject().setAuthenticatedSubjectIdentifier(subjectFromClaims);
                    }
                } catch (FrameworkException e) {
                    if (log.isDebugEnabled()) {
                        log.debug("Couldn't find the subject claim from claim mappings ", e);
                    }
                }
            } else {
                subjectFromClaims = FrameworkUtils.getFederatedSubjectFromClaims(
                        context.getExternalIdP().getIdentityProvider(), claims);
                if (StringUtils.isNotBlank(subjectFromClaims)) {
                    AuthenticatedUser authenticatedUser =
                            AuthenticatedUser.createFederateAuthenticatedUserFromSubjectIdentifier(
                                    subjectFromClaims);
                    context.setSubject(authenticatedUser);
                } else {
                    setSubject(context, jsonObject);
                }
                context.getSubject().setUserAttributes(claims);
            }
        } else {
            if (log.isDebugEnabled()) {
                log.debug("Decoded json object is null");
            }
            throw new ApplicationAuthenticatorException("Decoded json object is null");
        }
    }

    /**
     * Prefix give ClaimDialactUri to given claimUri.
     */
    private String getEffectiveClaimUri(String claimDialectUri, String claimUri) {

        if (shouldPrefixClaimDialectUri() && StringUtils.isNotBlank(getClaimDialectURI())) {
            return claimDialectUri + FacebookAuthenticatorConstants.FORWARD_SLASH + claimUri;
        }
        return claimUri;
    }

    /**
     * This method decide whether to append cliam dialect uri to the claim uri
     * @return true if appended
     */
    protected boolean shouldPrefixClaimDialectUri() {

        Map<String, String> parameters = readParametersFromAuthenticatorConfig();
        return Boolean.parseBoolean(parameters.get(FacebookAuthenticatorConstants.PREFIE_CLAIM_DIALECT_URI_PARAMETER));
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
        if (StringUtils.isNotBlank(state) && state.split(",").length > 1) {
            return state.split(",")[1];
        } else {
            return null;
        }
    }

    /**
     * This method reads parameters from application-authentication.xml
     * @return emptyMap if there is no Parameters else returns map of parameters
     */
    private Map<String, String> readParametersFromAuthenticatorConfig() {
        AuthenticatorConfig authConfig = FileBasedConfigurationBuilder.getInstance().getAuthenticatorBean(getName());
        if (authConfig != null) {
            return authConfig.getParameterMap();
        } else {
            if (log.isDebugEnabled()) {
                log.debug("FileBasedConfigBuilder returned null AuthenticatorConfigs for the connector " +
                        getName());
            }
            return Collections.emptyMap();
        }
    }

    /**
     * This method get idp claim configurations
     * @param context
     * @return ClaimConfig
     */
    private ClaimConfig getAuthenticatorClaimConfigurations(AuthenticationContext context) {
        ClaimConfig claimConfig = null;
        if (context != null) {
            ExternalIdPConfig externalIdPConfig = context.getExternalIdP();
            if (externalIdPConfig != null) {
                IdentityProvider identityProvider = externalIdPConfig.getIdentityProvider();
                if (identityProvider != null) {
                    claimConfig = identityProvider.getClaimConfig();
                } else {
                    if (log.isDebugEnabled()) {
                        log.debug("Authenticator " + getName() + " recieved null IdentityProvider");
                    }
                }
            } else {
                if (log.isDebugEnabled()) {
                    log.debug("Authenticator " + getName() + " recieved null ExternalIdPConfig");
                }
            }
        } else {
            if (log.isDebugEnabled()) {
                log.debug("Authenticator " + getName() + " recieved null AuthenticationContext");
            }
        }
        return claimConfig;
    }

    private void handleErrorResponse(HttpServletRequest request, HttpServletResponse response,
                                     AuthenticationContext context)
            throws InvalidCredentialsException {
        if (isErrorParamExists(request)) {
            StringBuilder errorMessage = new StringBuilder();
            String error_code = request.getParameter(FacebookAuthenticatorConstants.OAUTH2_PARAM_ERROR_CODE);
            String error = request.getParameter(FacebookAuthenticatorConstants.OAUTH2_PARAM_ERROR);
            String error_description = request.getParameter(FacebookAuthenticatorConstants.OAUTH2_PARAM_ERROR_DESCRIPTION);
            String error_reason = request.getParameter(FacebookAuthenticatorConstants.OAUTH2_PARAM_ERROR_REASON);
            errorMessage.append("error_code: ").append(error_code).append(", error: ").append(error)
                    .append(", error_description: ").append(error_description)
                    .append(", error_reason: ").append(error_reason);
            if (log.isDebugEnabled()) {
                log.debug("Failed to authenticate via Facebook. " + errorMessage.toString());
            }
            throw new InvalidCredentialsException(errorMessage.toString());
        }
    }

    private boolean isErrorParamExists(HttpServletRequest request) {
        return request.getParameter(FacebookAuthenticatorConstants.OAUTH2_PARAM_ERROR) != null;
    }

    private boolean isOauth2CodeParamExists(HttpServletRequest request) {
        return request.getParameter(FacebookAuthenticatorConstants.OAUTH2_GRANT_TYPE_CODE) != null;
    }

    private boolean isFacebookStateParamExists(HttpServletRequest request) {
        return request.getParameter(FacebookAuthenticatorConstants.OAUTH2_PARAM_STATE) != null &&
                FacebookAuthenticatorConstants.FACEBOOK_LOGIN_TYPE.equals(getLoginType(request));
    }

    @Override
    public String getClaimDialectURI() {
        String claimDialectUri = null;
        Map<String, String> parameters = readParametersFromAuthenticatorConfig();
        claimDialectUri = parameters.get(FacebookAuthenticatorConstants.CLAIM_DIALECT_URI_PARAMETER);
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

    /**
     * Get Configuration Properties.
     */
    @Override
    public List<Property> getConfigurationProperties() {

        List<Property> configProperties = new ArrayList<>();
        Property clientId = new Property();
        clientId.setName(IdentityApplicationConstants.Authenticator.Facebook.CLIENT_ID);
        clientId.setDisplayName("Client Id");
        clientId.setRequired(true);
        clientId.setDescription("Enter Facebook client identifier value");
        clientId.setType("string");
        clientId.setDisplayOrder(1);
        configProperties.add(clientId);

        Property clientSecret = new Property();
        clientSecret.setName(IdentityApplicationConstants.Authenticator.Facebook.CLIENT_SECRET);
        clientSecret.setDisplayName("Client Secret");
        clientSecret.setRequired(true);
        clientSecret.setDescription("Enter Facebook client secret value");
        clientSecret.setType("string");
        clientSecret.setDisplayOrder(2);
        clientSecret.setConfidential(true);
        configProperties.add(clientSecret);

        Property scope = new Property();
        scope.setName(IdentityApplicationConstants.Authenticator.Facebook.SCOPE);
        scope.setDisplayName("Scope");
        scope.setRequired(false);
        scope.setDescription("Enter a comma separated list of permissions to request from the user");
        scope.setType("string");
        scope.setDefaultValue("email");
        scope.setDisplayOrder(3);
        configProperties.add(scope);

        Property userInfoFields = new Property();
        userInfoFields.setName(IdentityApplicationConstants.Authenticator.Facebook.USER_INFO_FIELDS);
        userInfoFields.setDisplayName("User Information Fields");
        userInfoFields.setRequired(false);
        userInfoFields.setDescription("Enter comma-separated user information fields you want to retrieve");
        userInfoFields.setType("string");
        userInfoFields.setDisplayOrder(4);
        configProperties.add(userInfoFields);

        Property callbackUrl = new Property();
        callbackUrl.setName(IdentityApplicationConstants.Authenticator.Facebook.CALLBACK_URL);
        callbackUrl.setDisplayName("Callback Url");
        callbackUrl.setRequired(false);
        callbackUrl.setDescription("Enter value corresponding to callback url");
        callbackUrl.setType("string");
        callbackUrl.setDisplayOrder(5);
        configProperties.add(callbackUrl);

        Property userInfoEndpoint = new Property();
        userInfoEndpoint.setName(IdentityApplicationConstants.Authenticator.Facebook.USER_INFO_ENDPOINT);
        userInfoEndpoint.setDisplayName(null);
        userInfoEndpoint.setRequired(false);
        userInfoEndpoint.setDescription(null);
        userInfoEndpoint.setType("string");
        userInfoEndpoint.setDisplayOrder(0);
        configProperties.add(userInfoEndpoint);

        Property authTokenEndpoint = new Property();
        authTokenEndpoint.setName(IdentityApplicationConstants.Authenticator.Facebook.AUTH_TOKEN_ENDPOINT);
        authTokenEndpoint.setDisplayName(null);
        authTokenEndpoint.setRequired(false);
        authTokenEndpoint.setDescription(null);
        authTokenEndpoint.setType("string");
        authTokenEndpoint.setDisplayOrder(0);
        configProperties.add(authTokenEndpoint);

        Property authnEndpoint = new Property();
        authnEndpoint.setName(IdentityApplicationConstants.Authenticator.Facebook.AUTH_ENDPOINT);
        authnEndpoint.setDisplayName(null);
        authnEndpoint.setRequired(false);
        authTokenEndpoint.setDescription(null);
        authnEndpoint.setType("string");
        authnEndpoint.setDisplayOrder(0);
        configProperties.add(authnEndpoint);

        return configProperties;
    }
}
