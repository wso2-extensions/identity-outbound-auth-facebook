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

import com.nimbusds.jose.JOSEException;
import com.nimbusds.jwt.JWTClaimsSet;
import com.nimbusds.jwt.SignedJWT;
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
import org.wso2.carbon.identity.application.authentication.framework.model.AdditionalData;
import org.wso2.carbon.identity.application.authentication.framework.model.AuthenticatedUser;
import org.wso2.carbon.identity.application.authentication.framework.model.AuthenticatorData;
import org.wso2.carbon.identity.application.authentication.framework.model.AuthenticatorMessage;
import org.wso2.carbon.identity.application.authentication.framework.util.FrameworkConstants;
import org.wso2.carbon.identity.application.authentication.framework.util.FrameworkUtils;
import org.wso2.carbon.identity.application.authenticator.oidc.OIDCAuthenticatorConstants;
import org.wso2.carbon.identity.application.authenticator.oidc.util.OIDCErrorConstants;
import org.wso2.carbon.identity.application.authenticator.oidc.util.OIDCTokenValidationUtil;
import org.wso2.carbon.identity.application.common.model.Claim;
import org.wso2.carbon.identity.application.common.model.ClaimConfig;
import org.wso2.carbon.identity.application.common.model.ClaimMapping;
import org.wso2.carbon.identity.application.common.model.FederatedAuthenticatorConfig;
import org.wso2.carbon.identity.application.common.model.IdentityProvider;
import org.wso2.carbon.identity.application.common.model.IdentityProviderProperty;
import org.wso2.carbon.identity.application.common.model.Property;
import org.wso2.carbon.identity.application.common.util.IdentityApplicationConstants;
import org.wso2.carbon.identity.application.common.util.IdentityApplicationManagementUtil;
import org.wso2.carbon.identity.base.IdentityConstants;
import org.wso2.carbon.identity.central.log.mgt.utils.LogConstants;
import org.wso2.carbon.identity.central.log.mgt.utils.LoggerUtils;
import org.wso2.carbon.identity.core.ServiceURLBuilder;
import org.wso2.carbon.identity.core.URLBuilderException;
import org.wso2.carbon.identity.core.util.IdentityIOStreamUtils;
import org.wso2.carbon.identity.core.util.IdentityUtil;
import org.wso2.carbon.identity.oauth2.IdentityOAuth2ClientException;
import org.wso2.carbon.identity.oauth2.IdentityOAuth2Exception;
import org.wso2.carbon.idp.mgt.IdentityProviderManagementException;
import org.wso2.carbon.idp.mgt.IdentityProviderManager;
import org.wso2.carbon.idp.mgt.util.IdPManagementConstants;
import org.wso2.carbon.utils.DiagnosticLog;

import java.io.BufferedReader;
import java.io.IOException;
import java.io.InputStreamReader;
import java.net.MalformedURLException;
import java.net.URL;
import java.net.URLConnection;
import java.nio.charset.Charset;
import java.text.ParseException;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.Collections;
import java.util.HashMap;
import java.util.List;
import java.util.Map;
import java.util.Optional;
import java.util.UUID;
import java.util.stream.Collectors;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;

import static org.wso2.carbon.identity.application.authenticator.facebook.FacebookAuthenticatorConstants.ACCESS_TOKEN_PARAM;
import static org.wso2.carbon.identity.application.authenticator.facebook.FacebookAuthenticatorConstants.ID_TOKEN_PARAM;
import static org.wso2.carbon.identity.application.authenticator.facebook.FacebookAuthenticatorConstants.LogConstants.ActionIDs.INITIATE_OUTBOUND_AUTH_REQUEST;
import static org.wso2.carbon.identity.application.authenticator.facebook.FacebookAuthenticatorConstants.LogConstants.ActionIDs.PROCESS_AUTHENTICATION_RESPONSE;
import static org.wso2.carbon.identity.application.authenticator.facebook.FacebookAuthenticatorConstants.LogConstants.DIAGNOSTIC_LOG_KEY_NAME;
import static org.wso2.carbon.identity.application.authenticator.facebook.FacebookAuthenticatorConstants.LogConstants.OUTBOUND_AUTH_FACEBOOK_SERVICE;

/**
 * This class holds the Facebook authenticator.
 */
public class FacebookAuthenticator extends AbstractApplicationAuthenticator implements
        FederatedApplicationAuthenticator {

    private static final long serialVersionUID = -4844100162196896194L;
    private static final Log log = LogFactory.getLog(FacebookAuthenticator.class);
    private static final String ERROR_REASON = "errorReason";
    private static final String INVALID_REQUEST = "invalid_request";
    private String tokenEndpoint;
    private String oAuthEndpoint;
    private String userInfoEndpoint;
    private static final String AUTHENTICATOR_MESSAGE = "authenticatorMessage";

    /**
     * Initiate tokenEndpoint.
     */
    protected void initTokenEndpoint() {
        this.tokenEndpoint = getAuthenticatorConfig().getParameterMap().get(FacebookAuthenticatorConstants
                .FB_TOKEN_URL);
        if (StringUtils.isBlank(this.tokenEndpoint)) {
            this.tokenEndpoint = IdentityApplicationConstants.FB_TOKEN_URL;
        }
    }

    /**
     * Initiate authorization server endpoint.
     */
    protected void initOAuthEndpoint() {
        this.oAuthEndpoint = getAuthenticatorConfig().getParameterMap().get(FacebookAuthenticatorConstants
                .FB_AUTHZ_URL);
        if (StringUtils.isBlank(this.oAuthEndpoint)) {
            this.oAuthEndpoint = IdentityApplicationConstants.FB_AUTHZ_URL;
        }
    }

    /**
     * Initiate userInfoEndpoint.
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

        boolean canHandle;
        if (isNativeSDKBasedFederationCall(request)) {
            canHandle = true;
        } else {
            canHandle = isFacebookStateParamExists(request) && (isOauth2CodeParamExists(request) ||
                    isErrorParamExists(request));
        }
        if (canHandle && LoggerUtils.isDiagnosticLogsEnabled()) {
            DiagnosticLog.DiagnosticLogBuilder diagnosticLogBuilder = new DiagnosticLog.DiagnosticLogBuilder(
                    OUTBOUND_AUTH_FACEBOOK_SERVICE, FrameworkConstants.LogConstants.ActionIDs.HANDLE_AUTH_STEP);
            diagnosticLogBuilder.resultStatus(DiagnosticLog.ResultStatus.SUCCESS)
                    .logDetailLevel(DiagnosticLog.LogDetailLevel.INTERNAL_SYSTEM)
                    .resultMessage("Outbound facebook authenticator handling the authentication.");
            LoggerUtils.triggerDiagnosticLogEvent(diagnosticLogBuilder);
        }
        return canHandle;
    }

    @Override
    protected void initiateAuthenticationRequest(HttpServletRequest request,
                                                 HttpServletResponse response, AuthenticationContext context)
            throws AuthenticationFailedException {

        if (LoggerUtils.isDiagnosticLogsEnabled()) {
            DiagnosticLog.DiagnosticLogBuilder diagnosticLogBuilder = new DiagnosticLog.DiagnosticLogBuilder(
                    OUTBOUND_AUTH_FACEBOOK_SERVICE, INITIATE_OUTBOUND_AUTH_REQUEST);
            diagnosticLogBuilder.logDetailLevel(DiagnosticLog.LogDetailLevel.APPLICATION)
                    .resultStatus(DiagnosticLog.ResultStatus.SUCCESS)
                    .inputParam(LogConstants.InputKeys.STEP, context.getCurrentStep())
                    .inputParam(LogConstants.InputKeys.IDP, context.getExternalIdP().getIdPName())
                    .inputParams(getApplicationDetails(context))
                    .resultMessage("Initiate outbound Facebook authentication request.");
            LoggerUtils.triggerDiagnosticLogEvent(diagnosticLogBuilder);
        }
        try {
            Map<String, String> authenticatorProperties = context.getAuthenticatorProperties();
            String clientId = authenticatorProperties.get(FacebookAuthenticatorConstants.CLIENT_ID);
            String authorizationEP = getAuthorizationServerEndpoint();
            String scope = authenticatorProperties.get(FacebookAuthenticatorConstants.SCOPE);

            if (StringUtils.isEmpty(scope)) {
                scope = FacebookAuthenticatorConstants.EMAIL;
            }

            String callbackUrl = getCallbackUrl(authenticatorProperties);
            if (context.getProperty(FacebookAuthenticatorConstants.IS_API_BASED) != null &&
                    Boolean.parseBoolean((String) context.getProperty(FacebookAuthenticatorConstants.IS_API_BASED))) {
                callbackUrl = (String) context.getProperty(FacebookAuthenticatorConstants.REDIRECT_URL);
            }

            String state;
            if (FrameworkUtils.isAPIBasedAuthenticationFlow(request)) {
                state = UUID.randomUUID() + "," + FacebookAuthenticatorConstants.FACEBOOK_LOGIN_TYPE;
            } else {
                state = context.getContextIdentifier() + "," + FacebookAuthenticatorConstants.FACEBOOK_LOGIN_TYPE;
            }
            context.setProperty(FacebookAuthenticatorConstants.AUTHENTICATOR_NAME +
                    FacebookAuthenticatorConstants.STATE_PARAM_SUFFIX, state);

            OAuthClientRequest authzRequest =
                    OAuthClientRequest.authorizationLocation(authorizationEP)
                            .setClientId(clientId)
                            .setRedirectURI(callbackUrl)
                            .setResponseType(FacebookAuthenticatorConstants.OAUTH2_GRANT_TYPE_CODE)
                            .setScope(scope).setState(state)
                            .buildQueryMessage();
            context.setProperty(FacebookAuthenticatorConstants.AUTHENTICATOR_NAME +
                            FacebookAuthenticatorConstants.REDIRECT_URL_SUFFIX, authzRequest.getLocationUri());
            response.sendRedirect(authzRequest.getLocationUri());
            if (LoggerUtils.isDiagnosticLogsEnabled()) {
                DiagnosticLog.DiagnosticLogBuilder diagnosticLogBuilder = new DiagnosticLog.DiagnosticLogBuilder(
                        OUTBOUND_AUTH_FACEBOOK_SERVICE, INITIATE_OUTBOUND_AUTH_REQUEST);
                diagnosticLogBuilder.logDetailLevel(DiagnosticLog.LogDetailLevel.APPLICATION)
                        .resultStatus(DiagnosticLog.ResultStatus.SUCCESS)
                        .inputParam(LogConstants.InputKeys.STEP, context.getCurrentStep())
                        .inputParam(LogConstants.InputKeys.IDP, context.getExternalIdP().getIdPName())
                        .inputParam("authenticator properties", authenticatorProperties.keySet())
                        .inputParam(LogConstants.InputKeys.SCOPE, scope)
                        .inputParams(getApplicationDetails(context))
                        .resultMessage("Redirecting to the Facebook login page.");
                LoggerUtils.triggerDiagnosticLogEvent(diagnosticLogBuilder);
            }
        } catch (IOException e) {
            log.error("Exception while sending to the login page.", e);
            throw new AuthenticationFailedException(e.getMessage(), e);
        } catch (OAuthSystemException e) {
            String message = "Exception while building the authorization code request.";
            setAuthenticatorMessageToContext(message, INVALID_REQUEST, null, context);
            log.error(message, e);
            throw new AuthenticationFailedException(e.getMessage(), e);
        }
    }

    /**
     * This method is responsible for obtaining authenticator-specific data needed to
     * initialize the authentication process within the provided authentication context.
     *
     * @param context The authentication context containing information about the current authentication attempt.
     * @return An {@code Optional} containing an {@code AuthenticatorData} object representing the initiation data.
     *         If the initiation data is available, it is encapsulated within the {@code Optional}; otherwise,
     *         an empty {@code Optional} is returned.
     */
    @Override
    public Optional<AuthenticatorData> getAuthInitiationData(AuthenticationContext context) {

        AuthenticatorData authenticatorData = new AuthenticatorData();
        authenticatorData.setName(getName());
        authenticatorData.setDisplayName(getFriendlyName());
        authenticatorData.setI18nKey(getI18nKey());
        String idpName = context.getExternalIdP().getIdPName();
        authenticatorData.setIdp(idpName);

        List<String> requiredParameterList = new ArrayList<>();
        if (isTrustedTokenIssuer(context)) {
            requiredParameterList.add(FacebookAuthenticatorConstants.ACCESS_TOKEN_PARAM);
            requiredParameterList.add(FacebookAuthenticatorConstants.ID_TOKEN_PARAM);
            authenticatorData.setPromptType(FrameworkConstants.AuthenticatorPromptType.INTERNAL_PROMPT);
            authenticatorData.setAdditionalData(getAdditionalData(context, true));
        } else {
            requiredParameterList.add(FacebookAuthenticatorConstants.OAUTH2_GRANT_TYPE_CODE);
            requiredParameterList.add(FacebookAuthenticatorConstants.OAUTH2_PARAM_STATE);
            authenticatorData.setPromptType(FrameworkConstants.AuthenticatorPromptType.REDIRECTION_PROMPT);
            authenticatorData.setAdditionalData(getAdditionalData(context, false));
        }
        authenticatorData.setRequiredParams(requiredParameterList);
        if (context.getProperty(AUTHENTICATOR_MESSAGE) != null) {
            authenticatorData.setMessage((AuthenticatorMessage) context.getProperty(AUTHENTICATOR_MESSAGE));
        }

        return Optional.of(authenticatorData);
    }

    private static AdditionalData getAdditionalData(
            AuthenticationContext context, boolean isNativeSDKBasedFederationCall) {

        AdditionalData additionalData = new AdditionalData();

        if (isNativeSDKBasedFederationCall) {
            Map<String, String> additionalAuthenticationParams = new HashMap<>();
            additionalAuthenticationParams.put(FacebookAuthenticatorConstants.CLIENT_ID_PARAM,
                    context.getAuthenticatorProperties().get(FacebookAuthenticatorConstants.CLIENT_ID));
            additionalData.setAdditionalAuthenticationParams(additionalAuthenticationParams);
        } else {
            additionalData.setRedirectUrl((String) context.getProperty(
                    FacebookAuthenticatorConstants.AUTHENTICATOR_NAME +
                    FacebookAuthenticatorConstants.REDIRECT_URL_SUFFIX));
            Map<String, String> additionalAuthenticationParams = new HashMap<>();
            String state = (String) context.getProperty(FacebookAuthenticatorConstants.AUTHENTICATOR_NAME +
                    FacebookAuthenticatorConstants.STATE_PARAM_SUFFIX);
            additionalAuthenticationParams.put(FacebookAuthenticatorConstants.OAUTH2_PARAM_STATE, state);
            additionalData.setAdditionalAuthenticationParams(additionalAuthenticationParams);
        }
        return additionalData;
    }

    @Override
    public String getI18nKey() {

        return FacebookAuthenticatorConstants.AUTHENTICATOR_FACEBOOK;
    }

    @Override
    protected void processAuthenticationResponse(HttpServletRequest request,
                                                 HttpServletResponse response,
                                                 AuthenticationContext context)
            throws AuthenticationFailedException {

        log.trace("Inside FacebookAuthenticator.authenticate()");
        if (LoggerUtils.isDiagnosticLogsEnabled()) {
            DiagnosticLog.DiagnosticLogBuilder diagnosticLogBuilder = new DiagnosticLog.DiagnosticLogBuilder(
                    OUTBOUND_AUTH_FACEBOOK_SERVICE, PROCESS_AUTHENTICATION_RESPONSE);
            diagnosticLogBuilder.logDetailLevel(DiagnosticLog.LogDetailLevel.APPLICATION)
                    .resultStatus(DiagnosticLog.ResultStatus.SUCCESS)
                    .inputParam(LogConstants.InputKeys.STEP, context.getCurrentStep())
                    .inputParam(LogConstants.InputKeys.IDP, context.getExternalIdP().getIdPName())
                    .inputParams(getApplicationDetails(context))
                    .resultMessage("Processing outbound Facebook authentication response.");
            LoggerUtils.triggerDiagnosticLogEvent(diagnosticLogBuilder);
        }

        handleErrorResponse(request, response, context);

        try {
            Map<String, String> authenticatorProperties = context.getAuthenticatorProperties();
            String clientId = authenticatorProperties.get(FacebookAuthenticatorConstants.CLIENT_ID);
            String clientSecret =
                    authenticatorProperties.get(FacebookAuthenticatorConstants.CLIENT_SECRET);
            String userInfoFields = authenticatorProperties.get(FacebookAuthenticatorConstants.USER_INFO_FIELDS);

            String tokenEndPoint = getTokenEndpoint();
            String fbAuthUserInfoUrl = getUserInfoEndpoint();

            String token;
            if (isTrustedTokenIssuer(context) && isNativeSDKBasedFederationCall(request)) {
                String idToken = request.getParameter(ID_TOKEN_PARAM);
                token = request.getParameter(ACCESS_TOKEN_PARAM);
                try {
                    validateJWTToken(context, idToken);
                } catch (ParseException | IdentityOAuth2ClientException | JOSEException e) {
                    throw new AuthenticationFailedException("JWT token is invalid.");
                } catch (IdentityOAuth2Exception e) {
                    throw new AuthenticationFailedException("JWT token validation Failed.", e);
                }
            } else {
                String callbackUrl = getCallbackUrl(authenticatorProperties);
                if (Boolean.parseBoolean((String) context.getProperty(FacebookAuthenticatorConstants.IS_API_BASED))) {
                    callbackUrl = (String) context.getProperty(FacebookAuthenticatorConstants.REDIRECT_URL);
                }
                String code = getAuthorizationCode(request);
                token = getToken(tokenEndPoint, clientId, clientSecret, callbackUrl, code);
            }

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
            DiagnosticLog.DiagnosticLogBuilder diagnosticLogBuilder = null;
            if (LoggerUtils.isDiagnosticLogsEnabled()) {
                diagnosticLogBuilder = new DiagnosticLog.DiagnosticLogBuilder(
                        OUTBOUND_AUTH_FACEBOOK_SERVICE, PROCESS_AUTHENTICATION_RESPONSE);
                diagnosticLogBuilder.logDetailLevel(DiagnosticLog.LogDetailLevel.APPLICATION)
                        .inputParam(LogConstants.InputKeys.STEP, context.getCurrentStep())
                        .inputParams(getApplicationDetails(context));
                context.setProperty(DIAGNOSTIC_LOG_KEY_NAME, diagnosticLogBuilder);
            }
            Map<String, Object> userInfoJson = getUserInfoJson(fbAuthUserInfoUrl, userInfoFields, token);
            buildClaims(context, userInfoJson, claimConfig);
            if (LoggerUtils.isDiagnosticLogsEnabled() && diagnosticLogBuilder != null) {
                diagnosticLogBuilder.resultMessage("Outbound Facebook authentication response processed successfully.")
                        .resultStatus(DiagnosticLog.ResultStatus.SUCCESS);
                LoggerUtils.triggerDiagnosticLogEvent(diagnosticLogBuilder);
            }
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
            DiagnosticLog.DiagnosticLogBuilder diagnosticLogBuilder = null;
            if (LoggerUtils.isDiagnosticLogsEnabled()) {
                diagnosticLogBuilder = (DiagnosticLog.DiagnosticLogBuilder) context.getProperty(
                        DIAGNOSTIC_LOG_KEY_NAME);
                context.removeProperty(DIAGNOSTIC_LOG_KEY_NAME);
            }
            if (diagnosticLogBuilder != null) {
                if (context.getSubject().getUserAttributes() != null) {
                    diagnosticLogBuilder.inputParam("user attributes (local claim : remote claim)",
                            getUserAttributeClaimMappingList(context.getSubject()));
                }
            }
        } else {
            if (log.isDebugEnabled()) {
                log.debug("Decoded json object is null");
            }
            throw new ApplicationAuthenticatorException("Decoded json object is null");
        }
    }

    /**
     * Prefix give ClaimDialectUri to given claimUri.
     */
    private String getEffectiveClaimUri(String claimDialectUri, String claimUri) {

        if (shouldPrefixClaimDialectUri() && StringUtils.isNotBlank(getClaimDialectURI())) {
            return claimDialectUri + FacebookAuthenticatorConstants.FORWARD_SLASH + claimUri;
        }
        return claimUri;
    }

    /**
     * This method decide whether to append claim dialect uri to the claim uri.
     * @return true if appended
     */
    protected boolean shouldPrefixClaimDialectUri() {

        Map<String, String> parameters = readParametersFromAuthenticatorConfig();
        return Boolean.parseBoolean(parameters.get(FacebookAuthenticatorConstants.PREFIE_CLAIM_DIALECT_URI_PARAMETER));
    }

    @Override
    public String getContextIdentifier(HttpServletRequest request) {
        log.trace("Inside FacebookAuthenticator.getContextIdentifier()");

        if (FrameworkUtils.isAPIBasedAuthenticationFlow(request)) {
            return request.getParameter(FacebookAuthenticatorConstants.SESSION_DATA_KEY_PARAM);
        }

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
     * This method reads parameters from application-authentication.xml.
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
     * This method get idp claim configurations.
     * @param context Authentication Context
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
                        log.debug("Authenticator " + getName() + " received null IdentityProvider");
                    }
                }
            } else {
                if (log.isDebugEnabled()) {
                    log.debug("Authenticator " + getName() + " received null ExternalIdPConfig");
                }
            }
        } else {
            if (log.isDebugEnabled()) {
                log.debug("Authenticator " + getName() + " received null AuthenticationContext");
            }
        }
        return claimConfig;
    }

    private void validateJWTToken(AuthenticationContext context, String idToken) throws
            ParseException, AuthenticationFailedException, JOSEException, IdentityOAuth2Exception {

        SignedJWT signedJWT = SignedJWT.parse(idToken);
        JWTClaimsSet claimsSet = signedJWT.getJWTClaimsSet();
        OIDCTokenValidationUtil.validateIssuerClaim(claimsSet);
        String tenantDomain = context.getTenantDomain();
        String idpIdentifier = OIDCTokenValidationUtil.getIssuer(claimsSet);
        IdentityProvider identityProvider = getIdentityProvider(idpIdentifier, tenantDomain);

        OIDCTokenValidationUtil.validateSignature(signedJWT, identityProvider);
        OIDCTokenValidationUtil.validateAudience(claimsSet.getAudience(), identityProvider, tenantDomain);
    }

    /**
     * Get the identity provider from issuer and tenant domain.
     *
     * @param jwtIssuer   JWT issuer.
     * @param tenantDomain Tenant domain.
     * @return IdentityProvider.
     * @throws AuthenticationFailedException If there is an issue while getting the identity provider.
     */
    private IdentityProvider getIdentityProvider(String jwtIssuer, String tenantDomain)
            throws AuthenticationFailedException {

        IdentityProvider identityProvider;
        OIDCErrorConstants.ErrorMessages errorMessages =
                OIDCErrorConstants.ErrorMessages.NO_REGISTERED_IDP_FOR_ISSUER;
        try {
            identityProvider = IdentityProviderManager.getInstance().getIdPByMetadataProperty(
                    IdentityApplicationConstants.IDP_ISSUER_NAME, jwtIssuer, tenantDomain, false);

            if (identityProvider == null) {
                identityProvider = IdentityProviderManager.getInstance().getIdPByName(jwtIssuer, tenantDomain);
            }
            if (identityProvider != null && StringUtils.equalsIgnoreCase(identityProvider.getIdentityProviderName(),
                    OIDCAuthenticatorConstants.BackchannelLogout.DEFAULT_IDP_NAME)) {
                // Check whether this jwt was issued by the resident identity provider.
                identityProvider = getResidentIDPForIssuer(tenantDomain, jwtIssuer);

                if (identityProvider == null) {
                    throw new AuthenticationFailedException(errorMessages.getCode(), errorMessages.getMessage());
                }
            }
        } catch (IdentityProviderManagementException e) {
            throw new AuthenticationFailedException(errorMessages.getCode(), errorMessages.getMessage(), e);
        }
        return identityProvider;
    }

    /**
     * Get the resident identity provider from issuer and tenant domain.
     *
     * @param tenantDomain Tenant domain.
     * @param jwtIssuer   Issuer of the jwt.
     * @return IdentityProvider.
     * @throws AuthenticationFailedException If there is an issue while getting the resident identity provider.
     */
    private IdentityProvider getResidentIDPForIssuer(String tenantDomain, String jwtIssuer)
            throws AuthenticationFailedException {

        String issuer = StringUtils.EMPTY;
        IdentityProvider residentIdentityProvider;
        try {
            residentIdentityProvider = IdentityProviderManager.getInstance().getResidentIdP(tenantDomain);
        } catch (IdentityProviderManagementException e) {
            String errorMsg = OIDCErrorConstants.ErrorMessages.GETTING_RESIDENT_IDP_FAILED.getCode() + " - " +
                    String.format(OIDCErrorConstants.ErrorMessages.GETTING_RESIDENT_IDP_FAILED.getMessage(),
                            tenantDomain);
            throw new AuthenticationFailedException(errorMsg);
        }
        FederatedAuthenticatorConfig[] fedAuthnConfigs = residentIdentityProvider.getFederatedAuthenticatorConfigs();
        FederatedAuthenticatorConfig oauthAuthenticatorConfig =
                IdentityApplicationManagementUtil.getFederatedAuthenticator(fedAuthnConfigs,
                        IdentityApplicationConstants.Authenticator.OIDC.NAME);
        if (oauthAuthenticatorConfig != null) {
            issuer = IdentityApplicationManagementUtil.getProperty(oauthAuthenticatorConfig.getProperties(),
                    OIDCAuthenticatorConstants.BackchannelLogout.OIDC_IDP_ENTITY_ID).getValue();
        }
        return jwtIssuer.equals(issuer) ? residentIdentityProvider : null;
    }

    private void handleErrorResponse(HttpServletRequest request, HttpServletResponse response,
                                     AuthenticationContext context)
            throws InvalidCredentialsException {
        if (isErrorParamExists(request)) {
            StringBuilder errorMessage = new StringBuilder();
            String errorCode = request.getParameter(FacebookAuthenticatorConstants.OAUTH2_PARAM_ERROR_CODE);
            String error = request.getParameter(FacebookAuthenticatorConstants.OAUTH2_PARAM_ERROR);
            String errorDescription = request
                    .getParameter(FacebookAuthenticatorConstants.OAUTH2_PARAM_ERROR_DESCRIPTION);
            String errorReason = request.getParameter(FacebookAuthenticatorConstants.OAUTH2_PARAM_ERROR_REASON);
            errorMessage.append("errorCode: ").append(errorCode).append(", error: ").append(error)
                    .append(", error_description: ").append(errorDescription)
                    .append(", error_reason: ").append(errorReason);
            if (log.isDebugEnabled()) {
                log.debug("Failed to authenticate via Facebook. " + errorMessage.toString());
            }
            setAuthenticatorMessageToContext(error, errorCode, errorReason, context);
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

    @Override
    public boolean isAPIBasedAuthenticationSupported() {
        return true;
    }

    /**
     * Get application details from the authentication context.
     * @param context Authentication context.
     * @return Map of application details.
     */
    private Map<String, String> getApplicationDetails(AuthenticationContext context) {

        Map<String, String> applicationDetailsMap = new HashMap<>();
        FrameworkUtils.getApplicationResourceId(context).ifPresent(applicationId ->
                applicationDetailsMap.put(LogConstants.InputKeys.APPLICATION_ID, applicationId));
        FrameworkUtils.getApplicationName(context).ifPresent(applicationName ->
                applicationDetailsMap.put(LogConstants.InputKeys.APPLICATION_NAME,
                        applicationName));
        return applicationDetailsMap;
    }

    private static List<String> getUserAttributeClaimMappingList(AuthenticatedUser authenticatedUser) {

        return authenticatedUser.getUserAttributes().keySet().stream()
                .map(claimMapping -> {
                    String localClaim = claimMapping.getLocalClaim().getClaimUri();
                    String remoteClaim = claimMapping.getRemoteClaim().getClaimUri();
                    return localClaim + " : " + remoteClaim;
                })
                .collect(Collectors.toList());
    }

    /**
     * Get the callback URL.
     *
     * @param authenticatorProperties Authenticator properties.
     * @return Callback URL.
     */
    protected String getCallbackUrl(Map<String, String> authenticatorProperties) {

        if (StringUtils.isNotEmpty(authenticatorProperties.get(FacebookAuthenticatorConstants.FB_CALLBACK_URL))) {
            return authenticatorProperties.get(FacebookAuthenticatorConstants.FB_CALLBACK_URL);
        }
        try {
            return ServiceURLBuilder.create().addPath(FrameworkConstants.COMMONAUTH).build().getAbsolutePublicURL();
        } catch (URLBuilderException e) {
            throw new RuntimeException("Error occurred while building URL.", e);
        }
    }

    private boolean isTrustedTokenIssuer(AuthenticationContext context) {

        ExternalIdPConfig externalIdPConfig = context.getExternalIdP();
        if (externalIdPConfig == null) {
            return false;
        }

        IdentityProvider externalIdentityProvider = externalIdPConfig.getIdentityProvider();
        if (externalIdentityProvider == null) {
            return false;
        }

        IdentityProviderProperty[] identityProviderProperties = externalIdentityProvider.getIdpProperties();
        for (IdentityProviderProperty identityProviderProperty: identityProviderProperties) {
            if (IdPManagementConstants.IS_TRUSTED_TOKEN_ISSUER.equals(identityProviderProperty.getName())) {
                return Boolean.parseBoolean(identityProviderProperty.getValue());
            }
        }

        return false;
    }

    private boolean isNativeSDKBasedFederationCall(HttpServletRequest request) {

        return request.getParameter(ACCESS_TOKEN_PARAM) != null && request.getParameter(ID_TOKEN_PARAM) != null;
    }

    private static void setAuthenticatorMessageToContext(String errorMessage, String errorCode, String errorReason,
                                                         AuthenticationContext context) {

        Map<String, String> messageContext = new HashMap<>();
        if (StringUtils.isNotEmpty(errorReason)) {
            messageContext.put(ERROR_REASON, errorReason);
        }

        AuthenticatorMessage authenticatorMessage = new AuthenticatorMessage(FrameworkConstants.
                AuthenticatorMessageType.ERROR, errorCode, errorMessage, messageContext);
        context.setProperty(AUTHENTICATOR_MESSAGE, authenticatorMessage);
    }
}
