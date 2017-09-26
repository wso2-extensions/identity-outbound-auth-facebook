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

import mockit.Deencapsulation;
import mockit.Expectations;
import mockit.Mocked;
import mockit.Tested;
import org.apache.commons.logging.Log;
import org.apache.oltu.oauth2.client.response.OAuthAuthzResponse;
import org.apache.oltu.oauth2.common.exception.OAuthProblemException;
import org.testng.Assert;
import org.testng.annotations.BeforeMethod;
import org.testng.annotations.Test;
import org.wso2.carbon.identity.application.authentication.framework.config.builder.FileBasedConfigurationBuilder;
import org.wso2.carbon.identity.application.authentication.framework.config.model.AuthenticatorConfig;
import org.wso2.carbon.identity.application.authentication.framework.context.AuthenticationContext;
import org.wso2.carbon.identity.application.authentication.framework.exception.ApplicationAuthenticatorException;
import org.wso2.carbon.identity.application.authentication.framework.exception.AuthenticationFailedException;
import org.wso2.carbon.identity.core.util.IdentityUtil;

import java.io.IOException;
import java.net.MalformedURLException;
import java.util.HashMap;
import java.util.Map;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;

public class FacebookProcessResponseTests {

    @Mocked
    Log mockedLog;
    private FacebookAuthenticator facebookAuthenticator;
    @Mocked
    HttpServletRequest mockHttpServletRequest;
    @Mocked
    HttpServletResponse mockHttpServletResponse;
    @Mocked
    AuthenticationContext mockAuthenticationContext;
    @Tested
    FacebookAuthenticator mockFBAuthenticator;
    @Mocked
    IdentityUtil mockIdentityUtil;
    @Mocked
    OAuthAuthzResponse mockAuthzResponse;
    @Mocked
    FileBasedConfigurationBuilder mockFileBasedConfigBuilder;


    @BeforeMethod
    public void setUp() throws Exception {
        facebookAuthenticator = new FacebookAuthenticator();
    }

    @Test(expectedExceptions = AuthenticationFailedException.class)
    public void testProcessAuthResponseWithoutCode() throws Exception {
        buildExpectationsForProcessAuthnReq(TestConstants.customFacebookEndpoint, "profile", TestConstants.callbackURL);
        mockFBAuthenticator.processAuthenticationResponse(mockHttpServletRequest, mockHttpServletResponse,
                mockAuthenticationContext);
    }

    @Test(expectedExceptions = AuthenticationFailedException.class)
    public void testProcessAuthResponseWithFailedTokenReq() throws Exception {
        mockIdentityUtil();
        new Expectations() {
            {
                mockAuthzResponse.oauthCodeAuthzResponse((HttpServletRequest) withNotNull());
                result = mockAuthzResponse;
                mockAuthzResponse.getCode();
                result = TestConstants.dummyAuthCode;
            }
        };

        buildExpectationsForProcessAuthnReq(TestConstants.customFacebookEndpoint, "profile", null);
        mockFBAuthenticator.processAuthenticationResponse(mockHttpServletRequest, mockHttpServletResponse,
                mockAuthenticationContext);
    }

    @Test
    public void testProcessAuthResponseWithCode() throws Exception {
        TestUtils.enableDebugLogs(mockedLog);
        mockIdentityUtil();
        mockTokenAndUserInfoCalls(TestConstants.tokenResponse, TestConstants.userInfoResponse);
        new Expectations() {
            {
                mockAuthzResponse.oauthCodeAuthzResponse((HttpServletRequest) withNotNull());
                result = mockAuthzResponse;
                mockAuthzResponse.getCode();
                result = TestConstants.dummyAuthCode;
            }
        };
        new Expectations() {
            {
                mockIdentityUtil.isTokenLoggable(anyString);
                result = true;
            }
        };
        buildExpectationsForProcessAuthnReq(TestConstants.customFacebookEndpoint, "profile", null);
        mockFBAuthenticator.processAuthenticationResponse(mockHttpServletRequest, mockHttpServletResponse,
                mockAuthenticationContext);
    }

    @Test(expectedExceptions = AuthenticationFailedException.class)
    public void testProcessAuthResponseWithErrorTokenResponse() throws Exception {
        mockIdentityUtil();
        mockTokenAndUserInfoCalls(TestConstants.tokenResponse.replace("$token", ""), TestConstants.userInfoResponse);
        new Expectations() {
            {
                mockAuthzResponse.oauthCodeAuthzResponse((HttpServletRequest) withNotNull());
                result = mockAuthzResponse;
                mockAuthzResponse.getCode();
                result = TestConstants.dummyAuthCode;
            }
        };
        buildExpectationsForProcessAuthnReq(TestConstants.customFacebookEndpoint, "profile", null);
        mockFBAuthenticator.processAuthenticationResponse(mockHttpServletRequest, mockHttpServletResponse,
                mockAuthenticationContext);
    }

    @Test(expectedExceptions = ApplicationAuthenticatorException.class)
    public void testGetTokenWithMalformedURI() throws Exception {
        TestUtils.enableDebugLogs(mockedLog);
        mockTokenAndUserInfoCalls(TestConstants.tokenResponse, TestConstants.userInfoResponse);
        new Expectations(mockFBAuthenticator) {{
            Deencapsulation.invoke(mockFBAuthenticator, "sendRequest", anyString);
            result = new MalformedURLException("Error while building url");
        }};
        mockFBAuthenticator.getToken("abcd", TestConstants.dummyClientId, TestConstants
                .CLIENT_SECRET, null, TestConstants.dummyAuthCode);
    }

    @Test
    public void testGetUserInfoWithFields() throws Exception {
        mockTokenAndUserInfoCalls(TestConstants.tokenResponse, TestConstants.userInfoResponse);
        String userInfoString = mockFBAuthenticator.getUserInfoString(TestConstants.facebookTokenEndpoint,
                "first_name,last_name", TestConstants.dummyAuthCode);
        Assert.assertEquals(userInfoString, TestConstants.tokenResponse);
    }

    @Test(expectedExceptions = ApplicationAuthenticatorException.class)
    public void getUserInfoWithMalformedURL() throws Exception {
        TestUtils.enableDebugLogs(mockedLog);
        mockTokenAndUserInfoCalls(TestConstants.tokenResponse, TestConstants.userInfoResponse);
        new Expectations(mockFBAuthenticator) {{
            Deencapsulation.invoke(mockFBAuthenticator, "sendRequest", anyString);
            result = new MalformedURLException("Error while building url");
        }};
        mockFBAuthenticator.getUserInfoString(TestConstants.facebookTokenEndpoint,
                "first_name,last_name", TestConstants.dummyAuthCode);
    }

    @Test(expectedExceptions = ApplicationAuthenticatorException.class)
    public void getUserInfoWithIOException() throws Exception {
        mockTokenAndUserInfoCalls(TestConstants.tokenResponse, TestConstants.userInfoResponse);
        new Expectations(mockFBAuthenticator) {{
            Deencapsulation.invoke(mockFBAuthenticator, "sendRequest", anyString);
            result = new IOException("Error while building url");
        }};
        mockFBAuthenticator.getUserInfoString(TestConstants.facebookTokenEndpoint,
                "first_name,last_name", TestConstants.dummyAuthCode);
    }

    @Test
    public void getClaimDialectURIFromConfig() throws Exception {
        TestUtils.enableDebugLogs(mockedLog);
        new Expectations() {{
            mockFileBasedConfigBuilder.getAuthenticatorBean(anyString);
            AuthenticatorConfig authenticatorConfig = new AuthenticatorConfig();
            Map<String, String> parameters = new HashMap<>();
            parameters.put(FacebookAuthenticatorConstants.CLAIM_DIALECT_URI_PARAMETER, "http://custom/claim");
            authenticatorConfig.setParameterMap(parameters);
            result = authenticatorConfig;
        }};
        Assert.assertEquals(mockFBAuthenticator.getClaimDialectURI(), "http://custom/claim");
    }

    @Test(expectedExceptions = ApplicationAuthenticatorException.class)
    public void testGetAuthorizationCodeError() throws Exception {
        new Expectations() {{
            mockAuthzResponse.oauthCodeAuthzResponse(mockHttpServletRequest);
            result = OAuthProblemException.error("Something went wrong");
        }};
        mockFBAuthenticator.getAuthorizationCode(mockHttpServletRequest);
    }

    @Test(expectedExceptions = ApplicationAuthenticatorException.class)
    public void testSetSubjectWithoutSubject() throws Exception {
        new Expectations() {{
            mockAuthzResponse.oauthCodeAuthzResponse(mockHttpServletRequest);
            result = OAuthProblemException.error("Something went wrong");
        }};
        mockFBAuthenticator.getAuthorizationCode(mockHttpServletRequest);
    }

    private void buildExpectationsForProcessAuthnReq(final String fbURL, final String scope, final String callbackURL) {
        new Expectations(mockFBAuthenticator) {{
            Deencapsulation.invoke(mockFBAuthenticator, "getAuthenticatorConfig");
            AuthenticatorConfig authenticatorConfig = new AuthenticatorConfig();
            Map parameters = new HashMap();
            parameters.put(FacebookAuthenticatorConstants.FB_AUTHZ_URL, fbURL);
            authenticatorConfig.setParameterMap(parameters);
            result = authenticatorConfig;
        }};

        new Expectations() {
            {
                Map parameters = new HashMap();
                parameters.put(FacebookAuthenticatorConstants.CLIENT_ID, TestConstants.dummyClientId);
                parameters.put(FacebookAuthenticatorConstants.SCOPE, scope);
                parameters.put(FacebookAuthenticatorConstants.CLIENT_ID, TestConstants.dummyClientId);
                parameters.put(FacebookAuthenticatorConstants.FB_CALLBACK_URL, callbackURL);
                mockAuthenticationContext.getAuthenticatorProperties();
                result = parameters;
            }
        };
    }

    private void mockIdentityUtil() {
        final String customHost = "https://somehost:9443/commonauth";
        new Expectations() {
            { /* define in static block */
                mockIdentityUtil.getServerURL(anyString, anyBoolean, anyBoolean);
                result = customHost;
            }
        };
    }

    private void mockTokenAndUserInfoCalls(final String tokenResponse, final String userInfoResponse) {
        new Expectations(mockFBAuthenticator) {{
            Deencapsulation.invoke(mockFBAuthenticator, "sendRequest", anyString);
            returns(tokenResponse, userInfoResponse);
        }};
    }
}
