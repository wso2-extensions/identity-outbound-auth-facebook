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
            String userInfoValue;
            String userInfoKey;

            for (Map.Entry<String, Object> userInfo : jsonObject.entrySet()) {
                userInfoValue = userInfo.getValue().toString();
                userInfoKey = userInfo.getKey();
                if (StringUtils.isNotEmpty(userInfoKey) && StringUtils.isNotEmpty(userInfoValue)) {
                    switch (userInfoKey) {
                        case FacebookAuthenticatorConstants.FacebookPermissions.ID:
                            claimUri = FacebookAuthenticatorConstants.CLAIM_DIALECT_URI + "/" +
                                    FacebookAuthenticatorConstants.FacebookPermissions.ID;
                            generateClaims(claimUri, claims, userInfoValue);
                            break;
                        case FacebookAuthenticatorConstants.FacebookPermissions.COVER:
                            claimUri = FacebookAuthenticatorConstants.CLAIM_DIALECT_URI + "/" +
                                    FacebookAuthenticatorConstants.FacebookPermissions.COVER;
                            generateClaims(claimUri, claims, userInfoValue);
                            break;
                        case FacebookAuthenticatorConstants.FacebookPermissions.NAME:
                            claimUri = FacebookAuthenticatorConstants.CLAIM_DIALECT_URI + "/" +
                                    FacebookAuthenticatorConstants.FacebookPermissions.NAME;
                            generateClaims(claimUri, claims, userInfoValue);
                            break;
                        case FacebookAuthenticatorConstants.FacebookPermissions.FIRST_NAME:
                            claimUri = FacebookAuthenticatorConstants.CLAIM_DIALECT_URI + "/" +
                                    FacebookAuthenticatorConstants.FacebookPermissions.FIRST_NAME;
                            generateClaims(claimUri, claims, userInfoValue);
                            break;
                        case FacebookAuthenticatorConstants.FacebookPermissions.LAST_NAME:
                            claimUri = FacebookAuthenticatorConstants.CLAIM_DIALECT_URI + "/" +
                                    FacebookAuthenticatorConstants.FacebookPermissions.LAST_NAME;
                            generateClaims(claimUri, claims, userInfoValue);
                            break;
                        case FacebookAuthenticatorConstants.FacebookPermissions.AGE_RANGE:
                            claimUri = FacebookAuthenticatorConstants.CLAIM_DIALECT_URI + "/" +
                                    FacebookAuthenticatorConstants.FacebookPermissions.AGE_RANGE;
                            generateClaims(claimUri, claims, userInfoValue);
                            break;
                        case FacebookAuthenticatorConstants.FacebookPermissions.LINK:
                            claimUri = FacebookAuthenticatorConstants.CLAIM_DIALECT_URI + "/" +
                                    FacebookAuthenticatorConstants.FacebookPermissions.LINK;
                            generateClaims(claimUri, claims, userInfoValue);
                            break;
                        case FacebookAuthenticatorConstants.FacebookPermissions.GENDER:
                            claimUri = FacebookAuthenticatorConstants.CLAIM_DIALECT_URI + "/" +
                                    FacebookAuthenticatorConstants.FacebookPermissions.GENDER;
                            generateClaims(claimUri, claims, userInfoValue);
                            break;
                        case FacebookAuthenticatorConstants.FacebookPermissions.LOCALE:
                            claimUri = FacebookAuthenticatorConstants.CLAIM_DIALECT_URI + "/" +
                                    FacebookAuthenticatorConstants.FacebookPermissions.LOCALE;
                            generateClaims(claimUri, claims, userInfoValue);
                            break;
                        case FacebookAuthenticatorConstants.FacebookPermissions.PICTURE:
                            claimUri = FacebookAuthenticatorConstants.CLAIM_DIALECT_URI + "/" +
                                    FacebookAuthenticatorConstants.FacebookPermissions.PICTURE;
                            generateClaims(claimUri, claims, userInfoValue);
                            break;
                        case FacebookAuthenticatorConstants.FacebookPermissions.TIMEZONE:
                            claimUri = FacebookAuthenticatorConstants.CLAIM_DIALECT_URI + "/" +
                                    FacebookAuthenticatorConstants.FacebookPermissions.TIMEZONE;
                            generateClaims(claimUri, claims, userInfoValue);
                            break;
                        case FacebookAuthenticatorConstants.FacebookPermissions.UPDATED_TIME:
                            claimUri = FacebookAuthenticatorConstants.CLAIM_DIALECT_URI + "/" +
                                    FacebookAuthenticatorConstants.FacebookPermissions.UPDATED_TIME;
                            generateClaims(claimUri, claims, userInfoValue);
                            break;
                        case FacebookAuthenticatorConstants.FacebookPermissions.VERIFIED:
                            claimUri = FacebookAuthenticatorConstants.CLAIM_DIALECT_URI + "/" +
                                    FacebookAuthenticatorConstants.FacebookPermissions.VERIFIED;
                            generateClaims(claimUri, claims, userInfoValue);
                            break;
                        case FacebookAuthenticatorConstants.FacebookPermissions.USER_FRIENDS:
                            claimUri = FacebookAuthenticatorConstants.CLAIM_DIALECT_URI + "/" +
                                    FacebookAuthenticatorConstants.FacebookPermissions.USER_FRIENDS;
                            generateClaims(claimUri, claims, userInfoValue);
                            break;
                        case FacebookAuthenticatorConstants.FacebookPermissions.EMAIL:
                            claimUri = FacebookAuthenticatorConstants.CLAIM_DIALECT_URI + "/" +
                                    FacebookAuthenticatorConstants.FacebookPermissions.EMAIL;
                            generateClaims(claimUri, claims, userInfoValue);
                            break;
                        case FacebookAuthenticatorConstants.FacebookPermissions.USER_ABOUT_ME:
                            claimUri = FacebookAuthenticatorConstants.CLAIM_DIALECT_URI + "/" +
                                    FacebookAuthenticatorConstants.FacebookPermissions.USER_ABOUT_ME;
                            generateClaims(claimUri, claims, userInfoValue);
                            break;
                        case FacebookAuthenticatorConstants.FacebookPermissions.USER_ACTIONS_BOOKS:
                            claimUri = FacebookAuthenticatorConstants.CLAIM_DIALECT_URI + "/" +
                                    FacebookAuthenticatorConstants.FacebookPermissions.USER_ACTIONS_BOOKS;
                            generateClaims(claimUri, claims, userInfoValue);
                            break;
                        case FacebookAuthenticatorConstants.FacebookPermissions.USER_ACTIONS_FITNESS:
                            claimUri = FacebookAuthenticatorConstants.CLAIM_DIALECT_URI + "/" +
                                    FacebookAuthenticatorConstants.FacebookPermissions.USER_ACTIONS_FITNESS;
                            generateClaims(claimUri, claims, userInfoValue);
                            break;
                        case FacebookAuthenticatorConstants.FacebookPermissions.USER_ACTIONS_MUSIC:
                            claimUri = FacebookAuthenticatorConstants.CLAIM_DIALECT_URI + "/" +
                                    FacebookAuthenticatorConstants.FacebookPermissions.USER_ACTIONS_MUSIC;
                            generateClaims(claimUri, claims, userInfoValue);
                            break;
                        case FacebookAuthenticatorConstants.FacebookPermissions.USER_ACTIONS_NEWS:
                            claimUri = FacebookAuthenticatorConstants.CLAIM_DIALECT_URI + "/" +
                                    FacebookAuthenticatorConstants.FacebookPermissions.USER_ACTIONS_NEWS;
                            generateClaims(claimUri, claims, userInfoValue);
                            break;
                        case FacebookAuthenticatorConstants.FacebookPermissions.USER_ACTIONS_VIDEO:
                            claimUri = FacebookAuthenticatorConstants.CLAIM_DIALECT_URI + "/" +
                                    FacebookAuthenticatorConstants.FacebookPermissions.USER_ACTIONS_VIDEO;
                            generateClaims(claimUri, claims, userInfoValue);
                            break;
                        case FacebookAuthenticatorConstants.FacebookPermissions.USER_BIRTHDAY:
                            claimUri = FacebookAuthenticatorConstants.CLAIM_DIALECT_URI + "/" +
                                    FacebookAuthenticatorConstants.FacebookPermissions.USER_BIRTHDAY;
                            generateClaims(claimUri, claims, userInfoValue);
                            break;
                        case FacebookAuthenticatorConstants.FacebookPermissions.USER_EDUCATION_HISTORY:
                            claimUri = FacebookAuthenticatorConstants.CLAIM_DIALECT_URI + "/" +
                                    FacebookAuthenticatorConstants.FacebookPermissions.USER_EDUCATION_HISTORY;
                            generateClaims(claimUri, claims, userInfoValue);
                            break;
                        case FacebookAuthenticatorConstants.FacebookPermissions.USER_EVENTS:
                            claimUri = FacebookAuthenticatorConstants.CLAIM_DIALECT_URI + "/" +
                                    FacebookAuthenticatorConstants.FacebookPermissions.USER_EVENTS;
                            generateClaims(claimUri, claims, userInfoValue);
                            break;
                        case FacebookAuthenticatorConstants.FacebookPermissions.USER_GAMES_ACTIVITY:
                            claimUri = FacebookAuthenticatorConstants.CLAIM_DIALECT_URI + "/" +
                                    FacebookAuthenticatorConstants.FacebookPermissions.USER_GAMES_ACTIVITY;
                            generateClaims(claimUri, claims, userInfoValue);
                            break;
                        case FacebookAuthenticatorConstants.FacebookPermissions.USER_HOMETOWN:
                            claimUri = FacebookAuthenticatorConstants.CLAIM_DIALECT_URI + "/" +
                                    FacebookAuthenticatorConstants.FacebookPermissions.USER_HOMETOWN;
                            generateClaims(claimUri, claims, userInfoValue);
                            break;
                        case FacebookAuthenticatorConstants.FacebookPermissions.USER_LIKES:
                            claimUri = FacebookAuthenticatorConstants.CLAIM_DIALECT_URI + "/" +
                                    FacebookAuthenticatorConstants.FacebookPermissions.USER_LIKES;
                            generateClaims(claimUri, claims, userInfoValue);
                            break;
                        case FacebookAuthenticatorConstants.FacebookPermissions.USER_LOCATION:
                            claimUri = FacebookAuthenticatorConstants.CLAIM_DIALECT_URI + "/" +
                                    FacebookAuthenticatorConstants.FacebookPermissions.USER_LOCATION;
                            generateClaims(claimUri, claims, userInfoValue);
                            break;
                        case FacebookAuthenticatorConstants.FacebookPermissions.USER_MANAGED_GROUPS:
                            claimUri = FacebookAuthenticatorConstants.CLAIM_DIALECT_URI + "/" +
                                    FacebookAuthenticatorConstants.FacebookPermissions.USER_MANAGED_GROUPS;
                            generateClaims(claimUri, claims, userInfoValue);
                            break;
                        case FacebookAuthenticatorConstants.FacebookPermissions.USER_PHOTOS:
                            claimUri = FacebookAuthenticatorConstants.CLAIM_DIALECT_URI + "/" +
                                    FacebookAuthenticatorConstants.FacebookPermissions.USER_PHOTOS;
                            generateClaims(claimUri, claims, userInfoValue);
                            break;
                        case FacebookAuthenticatorConstants.FacebookPermissions.USER_POSTS:
                            claimUri = FacebookAuthenticatorConstants.CLAIM_DIALECT_URI + "/" +
                                    FacebookAuthenticatorConstants.FacebookPermissions.USER_POSTS;
                            generateClaims(claimUri, claims, userInfoValue);
                            break;
                        case FacebookAuthenticatorConstants.FacebookPermissions.USER_RELATIONSHIPS:
                            claimUri = FacebookAuthenticatorConstants.CLAIM_DIALECT_URI + "/" +
                                    FacebookAuthenticatorConstants.FacebookPermissions.USER_RELATIONSHIPS;
                            generateClaims(claimUri, claims, userInfoValue);
                            break;
                        case FacebookAuthenticatorConstants.FacebookPermissions.USER_RELATIONSHIP_DETAILS:
                            claimUri = FacebookAuthenticatorConstants.CLAIM_DIALECT_URI + "/" +
                                    FacebookAuthenticatorConstants.FacebookPermissions.USER_RELATIONSHIP_DETAILS;
                            generateClaims(claimUri, claims, userInfoValue);
                            break;
                        case FacebookAuthenticatorConstants.FacebookPermissions.USER_RELIGION_POLITICS:
                            claimUri = FacebookAuthenticatorConstants.CLAIM_DIALECT_URI + "/" +
                                    FacebookAuthenticatorConstants.FacebookPermissions.USER_RELIGION_POLITICS;
                            generateClaims(claimUri, claims, userInfoValue);
                            break;
                        case FacebookAuthenticatorConstants.FacebookPermissions.USER_TAGGED_PLACES:
                            claimUri = FacebookAuthenticatorConstants.CLAIM_DIALECT_URI + "/" +
                                    FacebookAuthenticatorConstants.FacebookPermissions.USER_TAGGED_PLACES;
                            generateClaims(claimUri, claims, userInfoValue);
                            break;
                        case FacebookAuthenticatorConstants.FacebookPermissions.USER_VIDEOS:
                            claimUri = FacebookAuthenticatorConstants.CLAIM_DIALECT_URI + "/" +
                                    FacebookAuthenticatorConstants.FacebookPermissions.USER_VIDEOS;
                            generateClaims(claimUri, claims, userInfoValue);
                            break;
                        case FacebookAuthenticatorConstants.FacebookPermissions.USER_WEBSITE:
                            claimUri = FacebookAuthenticatorConstants.CLAIM_DIALECT_URI + "/" +
                                    FacebookAuthenticatorConstants.FacebookPermissions.USER_WEBSITE;
                            generateClaims(claimUri, claims, userInfoValue);
                            break;
                        case FacebookAuthenticatorConstants.FacebookPermissions.USER_WORK_HISTORY:
                            claimUri = FacebookAuthenticatorConstants.CLAIM_DIALECT_URI + "/" +
                                    FacebookAuthenticatorConstants.FacebookPermissions.USER_WORK_HISTORY;
                            generateClaims(claimUri, claims, userInfoValue);
                            break;
                        case FacebookAuthenticatorConstants.FacebookPermissions.READ_CUSTOM_FRIENDLISTS:
                            claimUri = FacebookAuthenticatorConstants.CLAIM_DIALECT_URI + "/" +
                                    FacebookAuthenticatorConstants.FacebookPermissions.READ_CUSTOM_FRIENDLISTS;
                            generateClaims(claimUri, claims, userInfoValue);
                            break;
                        case FacebookAuthenticatorConstants.FacebookPermissions.READ_INSIGHTS:
                            claimUri = FacebookAuthenticatorConstants.CLAIM_DIALECT_URI + "/" +
                                    FacebookAuthenticatorConstants.FacebookPermissions.READ_INSIGHTS;
                            generateClaims(claimUri, claims, userInfoValue);
                            break;
                        case FacebookAuthenticatorConstants.FacebookPermissions.READ_AUDIENCE_NETWORK_INSIGHTS:
                            claimUri = FacebookAuthenticatorConstants.CLAIM_DIALECT_URI + "/" +
                                    FacebookAuthenticatorConstants.FacebookPermissions.READ_AUDIENCE_NETWORK_INSIGHTS;
                            generateClaims(claimUri, claims, userInfoValue);
                            break;
                        case FacebookAuthenticatorConstants.FacebookPermissions.READ_PAGE_MAILBOX:
                            claimUri = FacebookAuthenticatorConstants.CLAIM_DIALECT_URI + "/" +
                                    FacebookAuthenticatorConstants.FacebookPermissions.READ_PAGE_MAILBOX;
                            generateClaims(claimUri, claims, userInfoValue);
                            break;
                        case FacebookAuthenticatorConstants.FacebookPermissions.MANAGE_PAGES:
                            claimUri = FacebookAuthenticatorConstants.CLAIM_DIALECT_URI + "/" +
                                    FacebookAuthenticatorConstants.FacebookPermissions.MANAGE_PAGES;
                            generateClaims(claimUri, claims, userInfoValue);
                            break;
                        case FacebookAuthenticatorConstants.FacebookPermissions.PUBLISH_PAGES:
                            claimUri = FacebookAuthenticatorConstants.CLAIM_DIALECT_URI + "/" +
                                    FacebookAuthenticatorConstants.FacebookPermissions.PUBLISH_PAGES;
                            generateClaims(claimUri, claims, userInfoValue);
                            break;
                        case FacebookAuthenticatorConstants.FacebookPermissions.PUBLISH_ACTIONS:
                            claimUri = FacebookAuthenticatorConstants.CLAIM_DIALECT_URI + "/" +
                                    FacebookAuthenticatorConstants.FacebookPermissions.PUBLISH_ACTIONS;
                            generateClaims(claimUri, claims, userInfoValue);
                            break;
                        case FacebookAuthenticatorConstants.FacebookPermissions.RSVP_EVENTS:
                            claimUri = FacebookAuthenticatorConstants.CLAIM_DIALECT_URI + "/" +
                                    FacebookAuthenticatorConstants.FacebookPermissions.RSVP_EVENTS;
                            generateClaims(claimUri, claims, userInfoValue);
                            break;
                        case FacebookAuthenticatorConstants.FacebookPermissions.PAGES_SHOW_LIST:
                            claimUri = FacebookAuthenticatorConstants.CLAIM_DIALECT_URI + "/" +
                                    FacebookAuthenticatorConstants.FacebookPermissions.PAGES_SHOW_LIST;
                            generateClaims(claimUri, claims, userInfoValue);
                            break;
                        case FacebookAuthenticatorConstants.FacebookPermissions.PAGES_MANAGE_CTA:
                            claimUri = FacebookAuthenticatorConstants.CLAIM_DIALECT_URI + "/" +
                                    FacebookAuthenticatorConstants.FacebookPermissions.PAGES_MANAGE_CTA;
                            generateClaims(claimUri, claims, userInfoValue);
                            break;
                        case FacebookAuthenticatorConstants.FacebookPermissions.PAGES_MANAGE_INSTANT_ARTICLES:
                            claimUri = FacebookAuthenticatorConstants.CLAIM_DIALECT_URI + "/" +
                                    FacebookAuthenticatorConstants.FacebookPermissions.PAGES_MANAGE_INSTANT_ARTICLES;
                            generateClaims(claimUri, claims, userInfoValue);
                            break;
                        case FacebookAuthenticatorConstants.FacebookPermissions.ADS_READ:
                            claimUri = FacebookAuthenticatorConstants.CLAIM_DIALECT_URI + "/" +
                                    FacebookAuthenticatorConstants.FacebookPermissions.ADS_READ;
                            generateClaims(claimUri, claims, userInfoValue);
                            break;
                        case FacebookAuthenticatorConstants.FacebookPermissions.ADS_MANAGEMENT:
                            claimUri = FacebookAuthenticatorConstants.CLAIM_DIALECT_URI + "/" +
                                    FacebookAuthenticatorConstants.FacebookPermissions.ADS_MANAGEMENT;
                            generateClaims(claimUri, claims, userInfoValue);
                            break;
                        case FacebookAuthenticatorConstants.FacebookPermissions.BUSINESS_MANAGEMENT:
                            claimUri = FacebookAuthenticatorConstants.CLAIM_DIALECT_URI + "/" +
                                    FacebookAuthenticatorConstants.FacebookPermissions.BUSINESS_MANAGEMENT;
                            generateClaims(claimUri, claims, userInfoValue);
                            break;
                        case FacebookAuthenticatorConstants.FacebookPermissions.PAGES_MESSAGING:
                            claimUri = FacebookAuthenticatorConstants.CLAIM_DIALECT_URI + "/" +
                                    FacebookAuthenticatorConstants.FacebookPermissions.PAGES_MESSAGING;
                            generateClaims(claimUri, claims, userInfoValue);
                            break;
                        case FacebookAuthenticatorConstants.FacebookPermissions.PAGES_MESSAGING_SUBSCRIPTIONS:
                            claimUri = FacebookAuthenticatorConstants.CLAIM_DIALECT_URI + "/" +
                                    FacebookAuthenticatorConstants.FacebookPermissions.PAGES_MESSAGING_SUBSCRIPTIONS;
                            generateClaims(claimUri, claims, userInfoValue);
                            break;
                        case FacebookAuthenticatorConstants.FacebookPermissions.PAGES_MESSAGING_PAYMENTS:
                            claimUri = FacebookAuthenticatorConstants.CLAIM_DIALECT_URI + "/" +
                                    FacebookAuthenticatorConstants.FacebookPermissions.PAGES_MESSAGING_PAYMENTS;
                            generateClaims(claimUri, claims, userInfoValue);
                            break;
                        case FacebookAuthenticatorConstants.FacebookPermissions.PAGES_MESSAGING_PHONE_NUMBER:
                            claimUri = FacebookAuthenticatorConstants.CLAIM_DIALECT_URI + "/" +
                                    FacebookAuthenticatorConstants.FacebookPermissions.PAGES_MESSAGING_PHONE_NUMBER;
                            generateClaims(claimUri, claims, userInfoValue);
                            break;
                        default:
                            //Check whether the claim is specific to particular facebook app, which is decide on runtime
                            if (userInfoKey.toLowerCase().contains(FacebookAuthenticatorConstants.
                                        FacebookPermissions.USER_ACTIONS_APP_NAMESPACE.toLowerCase())) {
                                claimUri = FacebookAuthenticatorConstants.CLAIM_DIALECT_URI + "/" +
                                        userInfoKey;
                                generateClaims(claimUri, claims, userInfoValue);
                            } else {
                                if (log.isErrorEnabled()) {
                                    log.error("The recieved user information from facebook cannot be mapped to any " +
                                            "user information constants");
                                }
                                throw new ApplicationAuthenticatorException("User claim building failure");
                            }
                    }
                } else {
                    if (log.isWarnEnabled()) {
                        log.warn("The key or/and value of user information came from facebook is null or empty");
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
        return FacebookAuthenticatorConstants.CLAIM_DIALECT_URI;
    }

    /**
     * This method is to associate the specified value with the specified key in MAP.
     *
     * @param claimUri The Claim URI
     * @param claims   The map
     * @param value    The value needs to be added in the MAP
     */
    private void generateClaims(String claimUri, Map<ClaimMapping, String> claims, String value) {
        if (log.isDebugEnabled()) {
            log.debug("Adding claim mapping" + claimUri);
        }
        ClaimMapping claimMapping = new ClaimMapping();
        Claim claim = new Claim();
        claim.setClaimUri(claimUri);
        claimMapping.setRemoteClaim(claim);
        claimMapping.setLocalClaim(claim);
        claims.put(claimMapping, value);
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
