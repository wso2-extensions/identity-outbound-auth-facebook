/*
 * Copyright (c) 2017, WSO2 Inc. (http://www.wso2.org) All Rights Reserved.
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

import org.apache.commons.logging.Log;
import org.apache.oltu.oauth2.client.response.OAuthAuthzResponse;
import org.apache.oltu.oauth2.common.exception.OAuthProblemException;
import org.mockito.Mock;
import org.mockito.MockedStatic;
import org.mockito.MockitoAnnotations;
import org.testng.Assert;
import org.testng.annotations.AfterMethod;
import org.testng.annotations.BeforeMethod;
import org.testng.annotations.Test;
import org.wso2.carbon.identity.application.authentication.framework.config.builder.FileBasedConfigurationBuilder;
import org.wso2.carbon.identity.application.authentication.framework.config.model.AuthenticatorConfig;
import org.wso2.carbon.identity.application.authentication.framework.config.model.ExternalIdPConfig;
import org.wso2.carbon.identity.application.authentication.framework.context.AuthenticationContext;
import org.wso2.carbon.identity.application.authentication.framework.exception.ApplicationAuthenticatorException;
import org.wso2.carbon.identity.application.authentication.framework.exception.AuthenticationFailedException;
import org.wso2.carbon.identity.application.authentication.framework.model.AuthenticatedUser;
import org.wso2.carbon.identity.application.common.model.ClaimConfig;
import org.wso2.carbon.identity.application.common.model.IdentityProvider;
import org.wso2.carbon.identity.application.common.model.IdentityProviderProperty;
import org.wso2.carbon.identity.central.log.mgt.utils.LoggerUtils;
import org.wso2.carbon.identity.core.ServiceURLBuilder;
import org.wso2.carbon.identity.core.util.IdentityUtil;

import java.io.IOException;
import java.lang.reflect.Field;
import java.net.MalformedURLException;
import java.util.HashMap;
import java.util.Map;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;

import static org.mockito.ArgumentMatchers.any;
import static org.mockito.ArgumentMatchers.anyString;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.mockStatic;
import static org.mockito.Mockito.when;

public class FacebookProcessResponseTests {

    @Mock
    private Log mockedLog;
    private FacebookAuthenticator facebookAuthenticator;
    @Mock
    private HttpServletRequest mockHttpServletRequest;
    @Mock
    private HttpServletResponse mockHttpServletResponse;
    @Mock
    private AuthenticationContext mockAuthenticationContext;
    @Mock
    private ClaimConfig mockClaimConfig;
    @Mock
    private ExternalIdPConfig mockExternalIdPConfig;
    @Mock
    private IdentityProvider mockIdentityProvider;
    @Mock
    private AuthenticatedUser mockAuthenticatedUser;
    
    private FacebookAuthenticator mockFBAuthenticator;
    private MockedStatic<LoggerUtils> mockedLoggerUtils;
    private MockedStatic<ServiceURLBuilder> mockedServiceURLBuilder;
    private MockedStatic<OAuthAuthzResponse> mockedOAuthAuthzResponse;
    private MockedStatic<IdentityUtil> mockedIdentityUtil;
    private MockedStatic<FileBasedConfigurationBuilder> mockedFileBasedConfigBuilder;

    @BeforeMethod
    public void setUp() throws Exception {
        MockitoAnnotations.openMocks(this);
        facebookAuthenticator = new FacebookAuthenticator();
        mockFBAuthenticator = new FacebookAuthenticator();
    }

    @AfterMethod
    public void tearDown() {
        if (mockedLoggerUtils != null) {
            try {
                mockedLoggerUtils.close();
            } catch (Exception e) {
                // Ignore
            }
            mockedLoggerUtils = null;
        }
        if (mockedServiceURLBuilder != null) {
            try {
                mockedServiceURLBuilder.close();
            } catch (Exception e) {
                // Ignore
            }
            mockedServiceURLBuilder = null;
        }
        if (mockedOAuthAuthzResponse != null) {
            try {
                mockedOAuthAuthzResponse.close();
            } catch (Exception e) {
                // Ignore
            }
            mockedOAuthAuthzResponse = null;
        }
        if (mockedIdentityUtil != null) {
            try {
                mockedIdentityUtil.close();
            } catch (Exception e) {
                // Ignore
            }
            mockedIdentityUtil = null;
        }
        if (mockedFileBasedConfigBuilder != null) {
            try {
                mockedFileBasedConfigBuilder.close();
            } catch (Exception e) {
                // Ignore
            }
            mockedFileBasedConfigBuilder = null;
        }
    }

    @Test(expectedExceptions = AuthenticationFailedException.class)
    public void testProcessAuthResponseWithoutCode() throws Exception {
        mockedLoggerUtils = mockStatic(LoggerUtils.class);
        mockedLoggerUtils.when(LoggerUtils::isDiagnosticLogsEnabled).thenReturn(false);
        
        setupProcessAuthnReqMocks(TestConstants.customFacebookEndpoint, "profile", TestConstants.callbackURL);
        mockFBAuthenticator.processAuthenticationResponse(mockHttpServletRequest, mockHttpServletResponse,
                mockAuthenticationContext);
    }

    @Test(expectedExceptions = AuthenticationFailedException.class)
    public void testProcessAuthResponseWithFailedTokenReq() throws Exception {
        mockedLoggerUtils = mockStatic(LoggerUtils.class);
        mockedLoggerUtils.when(LoggerUtils::isDiagnosticLogsEnabled).thenReturn(false);
        
        mockedServiceURLBuilder = mockStatic(ServiceURLBuilder.class);
        TestUtils.mockServiceURLBuilder(mockedServiceURLBuilder);
        
        OAuthAuthzResponse mockAuthzResponse = mock(OAuthAuthzResponse.class);
        mockedOAuthAuthzResponse = mockStatic(OAuthAuthzResponse.class);
        mockedOAuthAuthzResponse.when(() -> OAuthAuthzResponse.oauthCodeAuthzResponse(any(HttpServletRequest.class)))
                .thenReturn(mockAuthzResponse);
        when(mockAuthzResponse.getCode()).thenReturn(TestConstants.dummyAuthCode);

        setupProcessAuthnReqMocks(TestConstants.customFacebookEndpoint, "profile", null);
        mockFBAuthenticator.processAuthenticationResponse(mockHttpServletRequest, mockHttpServletResponse,
                mockAuthenticationContext);
    }

    @Test
    public void testProcessAuthResponseWithCode() throws Exception {
        TestUtils.enableDebugLogs(mockedLog, FacebookAuthenticator.class);
        
        mockedLoggerUtils = mockStatic(LoggerUtils.class);
        mockedLoggerUtils.when(LoggerUtils::isDiagnosticLogsEnabled).thenReturn(false);
        
        mockedServiceURLBuilder = mockStatic(ServiceURLBuilder.class);
        TestUtils.mockServiceURLBuilder(mockedServiceURLBuilder);
        
        mockTokenAndUserInfoCalls(TestConstants.tokenResponse, TestConstants.userInfoResponse);
        
        OAuthAuthzResponse mockAuthzResponse = mock(OAuthAuthzResponse.class);
        mockedOAuthAuthzResponse = mockStatic(OAuthAuthzResponse.class);
        mockedOAuthAuthzResponse.when(() -> OAuthAuthzResponse.oauthCodeAuthzResponse(any(HttpServletRequest.class)))
                .thenReturn(mockAuthzResponse);
        when(mockAuthzResponse.getCode()).thenReturn(TestConstants.dummyAuthCode);
        
        mockedIdentityUtil = mockStatic(IdentityUtil.class);
        mockedIdentityUtil.when(() -> IdentityUtil.isTokenLoggable(anyString())).thenReturn(true);
        
        // Mock ExternalIdPConfig and ClaimConfig to prevent null claim configuration error
        when(mockAuthenticationContext.getExternalIdP()).thenReturn(mockExternalIdPConfig);
        when(mockExternalIdPConfig.getIdentityProvider()).thenReturn(mockIdentityProvider);
        when(mockIdentityProvider.getClaimConfig()).thenReturn(mockClaimConfig);
        when(mockClaimConfig.getUserClaimURI()).thenReturn("http://wso2.org/claims");
        
        // Mock getIdpProperties() to return empty array to prevent NullPointerException in isTrustedTokenIssuer()
        when(mockIdentityProvider.getIdpProperties()).thenReturn(new IdentityProviderProperty[0]);
        
        // Mock getSubject() to return AuthenticatedUser to prevent NullPointerException in buildClaims()
        when(mockAuthenticationContext.getSubject()).thenReturn(mockAuthenticatedUser);
        
        setupProcessAuthnReqMocks(TestConstants.customFacebookEndpoint, "profile", null);
        mockFBAuthenticator.processAuthenticationResponse(mockHttpServletRequest, mockHttpServletResponse,
                mockAuthenticationContext);
    }

    @Test(expectedExceptions = AuthenticationFailedException.class)
    public void testProcessAuthResponseWithErrorTokenResponse() throws Exception {
        mockedLoggerUtils = mockStatic(LoggerUtils.class);
        mockedLoggerUtils.when(LoggerUtils::isDiagnosticLogsEnabled).thenReturn(false);
        
        mockedServiceURLBuilder = mockStatic(ServiceURLBuilder.class);
        TestUtils.mockServiceURLBuilder(mockedServiceURLBuilder);
        
        mockTokenAndUserInfoCalls(TestConstants.tokenResponse.replace("$token", ""), TestConstants.userInfoResponse);
        
        OAuthAuthzResponse mockAuthzResponse = mock(OAuthAuthzResponse.class);
        mockedOAuthAuthzResponse = mockStatic(OAuthAuthzResponse.class);
        mockedOAuthAuthzResponse.when(() -> OAuthAuthzResponse.oauthCodeAuthzResponse(any(HttpServletRequest.class)))
                .thenReturn(mockAuthzResponse);
        when(mockAuthzResponse.getCode()).thenReturn(TestConstants.dummyAuthCode);
        
        setupProcessAuthnReqMocks(TestConstants.customFacebookEndpoint, "profile", null);
        mockFBAuthenticator.processAuthenticationResponse(mockHttpServletRequest, mockHttpServletResponse,
                mockAuthenticationContext);
    }

    @Test(expectedExceptions = ApplicationAuthenticatorException.class)
    public void testGetTokenWithMalformedURI() throws Exception {
        TestUtils.enableDebugLogs(mockedLog, FacebookAuthenticator.class);
        mockTokenAndUserInfoCalls(TestConstants.tokenResponse, TestConstants.userInfoResponse);
        
        // Mock sendRequest to throw MalformedURLException
        FacebookAuthenticator spyAuthenticator = new FacebookAuthenticator() {
            @Override
            protected String sendRequest(String url) throws IOException {
                throw new MalformedURLException("Error while building url");
            }
        };
        
        spyAuthenticator.getToken("abcd", TestConstants.dummyClientId, TestConstants
                .CLIENT_SECRET, null, TestConstants.dummyAuthCode);
    }

    @Test
    public void testGetUserInfoWithFields() throws Exception {
        mockTokenAndUserInfoCalls(TestConstants.tokenResponse, TestConstants.userInfoResponse);
        String userInfoString = mockFBAuthenticator.getUserInfoString(TestConstants.facebookTokenEndpoint,
                TestConstants.FIRST_NAME + "," + TestConstants.LAST_NAME, TestConstants.dummyAuthCode);
        Assert.assertEquals(userInfoString, TestConstants.tokenResponse, "Incorrect UserInfo response received");
    }

    @Test(expectedExceptions = ApplicationAuthenticatorException.class)
    public void getUserInfoWithMalformedURL() throws Exception {
        TestUtils.enableDebugLogs(mockedLog, FacebookAuthenticator.class);
        mockTokenAndUserInfoCalls(TestConstants.tokenResponse, TestConstants.userInfoResponse);
        
        FacebookAuthenticator spyAuthenticator = new FacebookAuthenticator() {
            @Override
            protected String sendRequest(String url) throws IOException {
                throw new MalformedURLException("Error while building url");
            }
        };
        
        spyAuthenticator.getUserInfoString(TestConstants.facebookTokenEndpoint,
                TestConstants.FIRST_NAME + "," + TestConstants.LAST_NAME, TestConstants.dummyAuthCode);
    }

    @Test(expectedExceptions = ApplicationAuthenticatorException.class)
    public void getUserInfoWithIOException() throws Exception {
        mockTokenAndUserInfoCalls(TestConstants.tokenResponse, TestConstants.userInfoResponse);
        
        FacebookAuthenticator spyAuthenticator = new FacebookAuthenticator() {
            @Override
            protected String sendRequest(String url) throws IOException {
                throw new IOException("Error while building url");
            }
        };
        
        spyAuthenticator.getUserInfoString(TestConstants.facebookTokenEndpoint,
                TestConstants.FIRST_NAME + "," + TestConstants.LAST_NAME, TestConstants.dummyAuthCode);
    }

    @Test
    public void getClaimDialectURIFromConfig() throws Exception {
        TestUtils.enableDebugLogs(mockedLog, FacebookAuthenticator.class);
        
        AuthenticatorConfig authenticatorConfig = new AuthenticatorConfig();
        Map<String, String> parameters = new HashMap<>();
        parameters.put(FacebookAuthenticatorConstants.CLAIM_DIALECT_URI_PARAMETER, TestConstants.customClaimDialect);
        authenticatorConfig.setParameterMap(parameters);
        
        FileBasedConfigurationBuilder mockBuilder = mock(FileBasedConfigurationBuilder.class);
        mockedFileBasedConfigBuilder = mockStatic(FileBasedConfigurationBuilder.class);
        mockedFileBasedConfigBuilder.when(FileBasedConfigurationBuilder::getInstance).thenReturn(mockBuilder);
        when(mockBuilder.getAuthenticatorBean(anyString())).thenReturn(authenticatorConfig);
        
        Assert.assertEquals(mockFBAuthenticator.getClaimDialectURI(), TestConstants.customClaimDialect, "Configured facebook " +
                "claim dialect is not present in authenticator configs");
    }

    @Test(expectedExceptions = ApplicationAuthenticatorException.class)
    public void testGetAuthorizationCodeError() throws Exception {
        mockedOAuthAuthzResponse = mockStatic(OAuthAuthzResponse.class);
        mockedOAuthAuthzResponse.when(() -> OAuthAuthzResponse.oauthCodeAuthzResponse(mockHttpServletRequest))
                .thenThrow(OAuthProblemException.error("Something went wrong"));
        
        mockFBAuthenticator.getAuthorizationCode(mockHttpServletRequest);
    }

    @Test(expectedExceptions = ApplicationAuthenticatorException.class)
    public void testBuildClaimsWithNullClaims() throws Exception {
        TestUtils.enableDebugLogs(mockedLog, FacebookAuthenticator.class);
        mockFBAuthenticator.buildClaims(mockAuthenticationContext, null, mockClaimConfig);
    }

    private void setupProcessAuthnReqMocks(final String fbURL, final String scope, final String callbackURL) throws Exception {
        AuthenticatorConfig authenticatorConfig = new AuthenticatorConfig();
        Map parameters = new HashMap();
        parameters.put(FacebookAuthenticatorConstants.FB_AUTHZ_URL, fbURL);
        authenticatorConfig.setParameterMap(parameters);
        
        if (mockedFileBasedConfigBuilder == null) {
            FileBasedConfigurationBuilder mockBuilder = mock(FileBasedConfigurationBuilder.class);
            mockedFileBasedConfigBuilder = mockStatic(FileBasedConfigurationBuilder.class);
            mockedFileBasedConfigBuilder.when(FileBasedConfigurationBuilder::getInstance).thenReturn(mockBuilder);
            when(mockBuilder.getAuthenticatorBean(anyString())).thenReturn(authenticatorConfig);
        }

        Map authParams = new HashMap();
        authParams.put(FacebookAuthenticatorConstants.CLIENT_ID, TestConstants.dummyClientId);
        authParams.put(FacebookAuthenticatorConstants.SCOPE, scope);
        authParams.put(FacebookAuthenticatorConstants.FB_CALLBACK_URL, callbackURL);
        
        when(mockAuthenticationContext.getAuthenticatorProperties()).thenReturn(authParams);
    }

    private void mockTokenAndUserInfoCalls(final String tokenResponse, final String userInfoResponse) throws Exception {
        // Create a custom FacebookAuthenticator that overrides sendRequest
        FacebookAuthenticator customAuthenticator = new FacebookAuthenticator() {
            private int callCount = 0;
            
            @Override
            protected String sendRequest(String url) throws IOException {
                callCount++;
                if (callCount == 1) {
                    return tokenResponse;
                } else {
                    return userInfoResponse;
                }
            }
        };
        
        // Replace mockFBAuthenticator with customAuthenticator
        mockFBAuthenticator = customAuthenticator;
    }
}
