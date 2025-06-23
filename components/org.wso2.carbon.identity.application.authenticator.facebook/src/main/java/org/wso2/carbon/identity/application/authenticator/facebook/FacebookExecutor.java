/*
 * Copyright (c) 2025, WSO2 LLC. (http://www.wso2.com).
 *
 * WSO2 LLC. licenses this file to you under the Apache License,
 * Version 2.0 (the "License"); you may not use this file except
 * in compliance with the License.
 * You may obtain a copy of the License at
 *
 * http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing,
 * software distributed under the License is distributed on an
 * "AS IS" BASIS, WITHOUT WARRANTIES OR CONDITIONS OF ANY
 * KIND, either express or implied.  See the License for the
 * specific language governing permissions and limitations
 * under the License.
 */

package org.wso2.carbon.identity.application.authenticator.facebook;

import org.apache.commons.codec.binary.Base64;
import org.apache.commons.lang.StringUtils;
import org.apache.commons.logging.Log;
import org.apache.commons.logging.LogFactory;
import org.apache.oltu.oauth2.client.OAuthClient;
import org.apache.oltu.oauth2.client.URLConnectionClient;
import org.apache.oltu.oauth2.client.request.OAuthClientRequest;
import org.apache.oltu.oauth2.client.response.OAuthClientResponse;
import org.apache.oltu.oauth2.common.exception.OAuthProblemException;
import org.apache.oltu.oauth2.common.exception.OAuthSystemException;
import org.apache.oltu.oauth2.common.utils.JSONUtils;
import org.wso2.carbon.identity.application.authentication.framework.config.builder.FileBasedConfigurationBuilder;
import org.wso2.carbon.identity.application.authentication.framework.config.model.AuthenticatorConfig;
import org.wso2.carbon.identity.application.authenticator.oidc.util.OIDCCommonUtil;
import org.wso2.carbon.identity.application.common.model.ClaimConfig;
import org.wso2.carbon.identity.application.common.model.ClaimMapping;
import org.wso2.carbon.identity.flow.execution.engine.Constants;
import org.wso2.carbon.identity.flow.execution.engine.exception.FlowEngineException;
import org.wso2.carbon.identity.flow.execution.engine.exception.FlowEngineServerException;
import org.wso2.carbon.identity.flow.execution.engine.graph.Executor;
import org.wso2.carbon.identity.flow.execution.engine.model.ExecutorResponse;
import org.wso2.carbon.identity.flow.execution.engine.model.FlowExecutionContext;

import java.io.IOException;
import java.util.Arrays;
import java.util.Collections;
import java.util.HashMap;
import java.util.List;
import java.util.Map;
import java.util.UUID;

import static org.wso2.carbon.identity.application.authentication.framework.util.FrameworkConstants.USERNAME_CLAIM;
import static org.wso2.carbon.identity.application.authenticator.facebook.FacebookAuthenticatorConstants.CLAIM_DIALECT_URI_PARAMETER;
import static org.wso2.carbon.identity.application.authenticator.facebook.FacebookAuthenticatorConstants.CLIENT_ID;
import static org.wso2.carbon.identity.application.authenticator.facebook.FacebookAuthenticatorConstants.CLIENT_SECRET;
import static org.wso2.carbon.identity.application.authenticator.facebook.FacebookAuthenticatorConstants.FB_ACCESS_TOKEN;
import static org.wso2.carbon.identity.application.authenticator.facebook.FacebookAuthenticatorConstants.FB_AUTHZ_URL;
import static org.wso2.carbon.identity.application.authenticator.facebook.FacebookAuthenticatorConstants.FB_TOKEN_URL;
import static org.wso2.carbon.identity.application.authenticator.facebook.FacebookAuthenticatorConstants.FB_USER_INFO_URL;
import static org.wso2.carbon.identity.application.authenticator.facebook.FacebookAuthenticatorConstants.OAUTH2_GRANT_TYPE_CODE;
import static org.wso2.carbon.identity.application.authenticator.facebook.FacebookAuthenticatorConstants.OAUTH2_PARAM_STATE;
import static org.wso2.carbon.identity.application.authenticator.facebook.FacebookAuthenticatorConstants.PREFIE_CLAIM_DIALECT_URI_PARAMETER;
import static org.wso2.carbon.identity.application.authenticator.facebook.FacebookAuthenticatorConstants.SCOPE;
import static org.wso2.carbon.identity.application.authenticator.facebook.FacebookAuthenticatorConstants.USER_INFO_FIELDS;
import static org.wso2.carbon.identity.flow.execution.engine.Constants.ExecutorStatus.STATUS_COMPLETE;
import static org.wso2.carbon.identity.flow.execution.engine.Constants.ExecutorStatus.STATUS_EXTERNAL_REDIRECTION;

/**
 * Facebook Executor for handling the OAuth2 login flow.
 */
public class FacebookExecutor implements Executor {

    private static final Log LOG = LogFactory.getLog(FacebookExecutor.class);
    private static final String EXECUTOR_NAME = "FacebookExecutor";
    private static final String DEFAULT_SCOPE = "email";
    private static final String DEFAULT_USER_FIELDS = "id,email,name";

    @Override
    public String getName() {

        return EXECUTOR_NAME;
    }

    @Override
    public ExecutorResponse execute(FlowExecutionContext context) {

        try {
            if (isInitiation(context)) {
                return initiateAuthentication(context);
            } else {
                return handleResponse(context);
            }
        } catch (FlowEngineException e) {
            ExecutorResponse response = new ExecutorResponse();
            response.setResult(Constants.ExecutorStatus.STATUS_ERROR);
            response.setErrorMessage(e.getMessage());
            return response;
        }
    }

    @Override
    public List<String> getInitiationData() {

        return Collections.emptyList();
    }

    @Override
    public ExecutorResponse rollback(FlowExecutionContext context) {

        return null;
    }

    private static boolean isInitiation(FlowExecutionContext flowExecutionContext) {

        Map<String, String> input = flowExecutionContext.getUserInputData();
        return input == null || !input.containsKey(OAUTH2_GRANT_TYPE_CODE);
    }

    private ExecutorResponse initiateAuthentication(FlowExecutionContext context) throws FlowEngineException {

        String state = UUID.randomUUID().toString();
        String authorizationUrl = buildAuthorizationRequestUrl(context, state);

        if (LOG.isDebugEnabled()) {
            LOG.debug("Redirecting to Facebook: " + authorizationUrl);
        }

        ExecutorResponse response = new ExecutorResponse();
        response.setResult(STATUS_EXTERNAL_REDIRECTION);
        response.setRequiredData(Arrays.asList(OAUTH2_GRANT_TYPE_CODE, OAUTH2_PARAM_STATE));

        Map<String, Object> contextProps = new HashMap<>();
        contextProps.put(OAUTH2_PARAM_STATE, state);
        response.setContextProperty(contextProps);

        Map<String, String> additionalInfo = new HashMap<>();
        additionalInfo.put(Constants.REDIRECT_URL, authorizationUrl);
        additionalInfo.put(OAUTH2_PARAM_STATE, state);
        response.setAdditionalInfo(additionalInfo);

        return response;
    }

    private ExecutorResponse handleResponse(FlowExecutionContext context) throws FlowEngineException {

        validateStateParam(context);

        String code = context.getUserInputData().get(OAUTH2_GRANT_TYPE_CODE);
        String accessToken = fetchAccessToken(context, code);
        Map<String, Object> claims = fetchUserInfo(context, accessToken);
        ExecutorResponse response = new ExecutorResponse(STATUS_COMPLETE);
        response.setUpdatedUserClaims(claims);
        return response;
    }

    private String buildAuthorizationRequestUrl(FlowExecutionContext context, String state) throws FlowEngineException {

        try {
            String clientId = context.getAuthenticatorProperties().get(CLIENT_ID);
            String callbackUrl = getValidatedPortalUrl(context);
            String scope = context.getAuthenticatorProperties().getOrDefault(SCOPE, DEFAULT_SCOPE);
            String authzEndpoint = getAuthenticatorConfig(FB_AUTHZ_URL);

            return OAuthClientRequest
                    .authorizationLocation(authzEndpoint)
                    .setClientId(clientId)
                    .setRedirectURI(callbackUrl)
                    .setResponseType(OAUTH2_GRANT_TYPE_CODE)
                    .setScope(scope)
                    .setState(state)
                    .buildQueryMessage()
                    .getLocationUri();
        } catch (OAuthSystemException e) {
            LOG.error("Error building Facebook authorization URL.", e);
            throw buildExecutorFailure("Error building Facebook authorization URL.");
        }
    }

    private void validateStateParam(FlowExecutionContext context) throws FlowEngineException {

        String received = context.getUserInputData().get(OAUTH2_PARAM_STATE);
        String expected = (String) context.getProperty(OAUTH2_PARAM_STATE);
        if (!StringUtils.equals(received, expected)) {
            LOG.error("State mismatch. Expected: " + expected + ", Received: " + received);
            throw buildExecutorFailure("State parameter mismatch.");
        }
    }

    private String fetchAccessToken(FlowExecutionContext context, String code) throws FlowEngineException {

        Map<String, String> props = context.getAuthenticatorProperties();
        String clientId = props.get(CLIENT_ID);
        String clientSecret = props.get(CLIENT_SECRET);
        String callback = getValidatedPortalUrl(context);
        String tokenEndpoint = getAuthenticatorConfig(FB_TOKEN_URL);

        try {
            OAuthClientRequest request = buildAccessTokenRequest(tokenEndpoint, clientId, clientSecret, callback, code);
            OAuthClient client = new OAuthClient(new URLConnectionClient());
            OAuthClientResponse response = client.accessToken(request);

            String accessToken = response.getParam(FB_ACCESS_TOKEN);
            if (StringUtils.isBlank(accessToken)) {
                LOG.error("Access token is empty in Facebook token response.");
                throw buildExecutorFailure("Access token is null or empty.");
            }

            return accessToken;
        } catch (OAuthSystemException | OAuthProblemException e) {
            LOG.error("Failed to retrieve access token from Facebook.", e);
            throw buildExecutorFailure("Failed to retrieve access token from Facebook.");
        }
    }

    private OAuthClientRequest buildAccessTokenRequest(String tokenEndpoint, String clientId, String clientSecret,
                                                       String callback, String code) throws OAuthSystemException {

        OAuthClientRequest request = OAuthClientRequest
                .tokenLocation(tokenEndpoint)
                .setClientId(clientId)
                .setClientSecret(clientSecret)
                .setRedirectURI(callback)
                .setCode(code)
                .setGrantType(org.apache.oltu.oauth2.common.message.types.GrantType.AUTHORIZATION_CODE)
                .buildBodyMessage();
        String authHeader = Base64.encodeBase64String((clientId + ":" + clientSecret).getBytes());
        request.addHeader("Authorization", "Basic " + authHeader);
        return request;
    }

    private Map<String, Object> fetchUserInfo(FlowExecutionContext context, String token) throws FlowEngineException {

        String fields = context.getAuthenticatorProperties().getOrDefault(USER_INFO_FIELDS, DEFAULT_USER_FIELDS);
        String url = getAuthenticatorConfig(FB_USER_INFO_URL)
                + "?fields=" + fields + "&access_token=" + token;

        try {
            String json = OIDCCommonUtil.triggerRequest(url, token);

            Map<String, Object> result = JSONUtils.parseJSON(json);
            if (result.isEmpty()) {
                LOG.error("User info response from Facebook is empty.");
                throw buildExecutorFailure("User info response is empty.");
            }

            String claimDialectUri = getAuthenticatorConfig(CLAIM_DIALECT_URI_PARAMETER);
            ClaimConfig claimConfig = context.getExternalIdPConfig().getIdentityProvider().getClaimConfig();
            if (StringUtils.isBlank(claimConfig.getUserClaimURI())) {
                claimConfig.setUserClaimURI(getEffectiveClaimUri(claimDialectUri,
                        FacebookAuthenticatorConstants.EMAIL));
            }

            String userIdClaimURI = context.getExternalIdPConfig().getUserIdClaimUri();
            if (StringUtils.isNotBlank(userIdClaimURI)) {
                userIdClaimURI = getEffectiveClaimUri(claimDialectUri, userIdClaimURI);
            }

            Map<String, Object> mappedClaims = new HashMap<>();
            for (Map.Entry<String, Object> entry : result.entrySet()) {
                String claimUri = getEffectiveClaimUri(claimDialectUri, entry.getKey());
                Object claimValueObject = entry.getValue();
                if (StringUtils.isNotEmpty(claimUri) && claimValueObject != null && StringUtils.isNotEmpty(
                        claimValueObject.toString())) {
                    String mappedClaimUri = getMappedLocalClaim(claimConfig, claimUri);
                    if (StringUtils.isNotBlank(mappedClaimUri)) {
                        mappedClaims.put(mappedClaimUri, claimValueObject.toString());
                    }
                }
                // Set user ID claim if available.
                if (userIdClaimURI != null && userIdClaimURI.equals(entry.getKey())
                        && StringUtils.isNotBlank(userIdClaimURI) && claimValueObject != null) {
                    mappedClaims.put(USERNAME_CLAIM, claimValueObject.toString());
                }
            }

            return mappedClaims;
        } catch (IOException e) {
            LOG.error("Failed to retrieve user info from Facebook.", e);
            throw buildExecutorFailure("Failed to retrieve user info from Facebook.");
        }
    }

    protected String getMappedLocalClaim(ClaimConfig claimConfig, String claimUri) {

        ClaimMapping mappedClaim = Arrays.stream(claimConfig.getClaimMappings()).filter(
                        claimMapping -> claimMapping.getRemoteClaim().getClaimUri().equals(claimUri)).findFirst()
                .orElse(null);
        if (mappedClaim != null) {
            return mappedClaim.getLocalClaim().getClaimUri();
        }
        return null;
    }

    private String getValidatedPortalUrl(FlowExecutionContext context) throws FlowEngineException {

        String portalUrl = context.getPortalUrl();
        if (StringUtils.isBlank(portalUrl)) {
            LOG.error("Portal URL is missing in FlowExecutionContext.");
            throw buildExecutorFailure("Portal URL is required but not provided.");
        }
        return portalUrl;
    }

    private FlowEngineServerException buildExecutorFailure(String message) {

        return new FlowEngineServerException(message);
    }

    private String getAuthenticatorConfig(String key) {

        AuthenticatorConfig authConfig = FileBasedConfigurationBuilder.getInstance()
                .getAuthenticatorBean(FacebookAuthenticatorConstants.AUTHENTICATOR_NAME);
        if (authConfig == null) {
            return null;
        }
        return authConfig.getParameterMap().get(key);
    }

    private String getEffectiveClaimUri(String claimDialectUri, String claimUri) {

        boolean shouldPrefixClaimDialectUri =
                Boolean.parseBoolean(getAuthenticatorConfig(PREFIE_CLAIM_DIALECT_URI_PARAMETER));
        if (shouldPrefixClaimDialectUri && StringUtils.isNotBlank(claimDialectUri)) {
            return claimDialectUri + FacebookAuthenticatorConstants.FORWARD_SLASH + claimUri;
        }
        return claimUri;
    }
}
