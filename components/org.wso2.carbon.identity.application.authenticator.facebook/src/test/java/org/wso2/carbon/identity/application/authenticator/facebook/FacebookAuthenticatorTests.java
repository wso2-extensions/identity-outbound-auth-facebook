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
import mockit.Delegate;
import mockit.Expectations;
import mockit.Mocked;
import mockit.Tested;
import org.apache.oltu.oauth2.client.request.OAuthClientRequest;
import org.apache.oltu.oauth2.common.exception.OAuthSystemException;
import org.testng.Assert;
import org.testng.annotations.BeforeMethod;
import org.testng.annotations.Test;
import org.wso2.carbon.identity.application.authentication.framework.config.model.AuthenticatorConfig;
import org.wso2.carbon.identity.application.authentication.framework.context.AuthenticationContext;
import org.wso2.carbon.identity.application.authentication.framework.exception.ApplicationAuthenticatorException;
import org.wso2.carbon.identity.application.authentication.framework.exception.AuthenticationFailedException;
import org.wso2.carbon.identity.application.common.util.IdentityApplicationConstants;
import org.wso2.carbon.identity.core.util.IdentityUtil;

import java.io.IOException;
import java.util.HashMap;
import java.util.Map;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;

public class FacebookAuthenticatorTests {

    private FacebookAuthenticator facebookAuthenticator;

    @Mocked
    private HttpServletRequest mockHttpServletRequest;
    @Mocked
    private HttpServletResponse mockHttpServletResponse;
    @Mocked
    private AuthenticationContext mockAuthenticationContext;
    @Tested
    private FacebookAuthenticator mockFBAuthenticator;
    @Mocked
    private IdentityUtil mockIdentityUtil;
    @Mocked
    private OAuthClientRequest.TokenRequestBuilder mockTokenRequestBuilder;

    @BeforeMethod
    public void setUp() throws Exception {
        facebookAuthenticator = new FacebookAuthenticator();
    }

    @Test(expectedExceptions = ApplicationAuthenticatorException.class)
    public void testTokenRequestException() throws Exception {

        new Expectations() {{
            mockTokenRequestBuilder.buildQueryMessage();
            result = new Delegate() {
                OAuthClientRequest buildQueryMessage() throws OAuthSystemException {
                    throw new OAuthSystemException();
                }
            };
        }};
        OAuthClientRequest oAuthClientRequest = facebookAuthenticator.buidTokenRequest(TestConstants
                        .facebookTokenEndpoint, TestConstants.dummyClientId, TestConstants.dummyClientSecret,
                TestConstants.callbackURL, TestConstants.dummyAuthCode);
    }

    @Test
    public void testInvalidTokenRequest() throws Exception {

        new Expectations() {
            { /* define in static block */
                mockHttpServletRequest.getParameter("state");
                returns(TestConstants.dummyCommonAuthId, null);
            }
        };
        Assert.assertEquals(facebookAuthenticator.getContextIdentifier(mockHttpServletRequest), TestConstants
                .dummyCommonAuthId);
        Assert.assertNull(facebookAuthenticator.getContextIdentifier(mockHttpServletRequest));
    }

    @Test
    public void testCanHandle() throws Exception {

        new Expectations() {
            { /* define in static block */
                mockHttpServletRequest.getParameter(FacebookAuthenticatorConstants.OAUTH2_PARAM_STATE);
                result =
                        (TestConstants.dummyCommonAuthId + ",facebook");
                mockHttpServletRequest.getParameter(FacebookAuthenticatorConstants.OAUTH2_GRANT_TYPE_CODE);
                result = ("Authorization");
            }
        };
        Assert.assertEquals(facebookAuthenticator.canHandle(mockHttpServletRequest), true);
    }

    @Test
    public void canHandleFalse() throws Exception {

        new Expectations() {
            { /* define in static block */
                mockHttpServletRequest.getParameter(FacebookAuthenticatorConstants.OAUTH2_PARAM_STATE);
                result = null;
            }
        };
        Assert.assertEquals(facebookAuthenticator.canHandle(mockHttpServletRequest), false);

        new Expectations() {
            { /* define in static block */
                mockHttpServletRequest.getParameter(FacebookAuthenticatorConstants.OAUTH2_PARAM_STATE);
                result = TestConstants.dummyCommonAuthId + ",nothing";
            }
        };
        Assert.assertEquals(facebookAuthenticator.canHandle(mockHttpServletRequest), false);
        new Expectations() {
            { /* define in static block */
                mockHttpServletRequest.getParameter(FacebookAuthenticatorConstants.OAUTH2_PARAM_STATE);
                result = TestConstants.dummyCommonAuthId + ",facebook";
                mockHttpServletRequest.getParameter(FacebookAuthenticatorConstants.OAUTH2_PARAM_ERROR);
                result = null;
                mockHttpServletRequest.getParameter(FacebookAuthenticatorConstants.OAUTH2_GRANT_TYPE_CODE);
                result = null;
            }
        };
        Assert.assertEquals(facebookAuthenticator.canHandle(mockHttpServletRequest), false);
    }

    @Test
    public void initTokenEndpointWithoutConfigs() throws Exception {

        new Expectations(mockFBAuthenticator) {{
            Deencapsulation.invoke(mockFBAuthenticator, "getAuthenticatorConfig");
            AuthenticatorConfig authenticatorConfig = new AuthenticatorConfig();
            authenticatorConfig.setParameterMap(new HashMap<String, String>());
            result = authenticatorConfig;
        }};
        Assert.assertEquals(mockFBAuthenticator.getTokenEndpoint(), IdentityApplicationConstants.FB_TOKEN_URL);
        // Get it from static variable for the second time
        Assert.assertEquals(mockFBAuthenticator.getTokenEndpoint(), IdentityApplicationConstants.FB_TOKEN_URL);
    }

    @Test
    public void initTokenEndpointWithConfigs() throws Exception {

        new Expectations(mockFBAuthenticator) {{
            Deencapsulation.invoke(mockFBAuthenticator, "getAuthenticatorConfig");
            AuthenticatorConfig authenticatorConfig = new AuthenticatorConfig();
            Map parameters = new HashMap();
            parameters.put(FacebookAuthenticatorConstants
                    .FB_TOKEN_URL, TestConstants.customFacebookEndpoint);
            authenticatorConfig.setParameterMap(parameters);
            result = authenticatorConfig;
        }};
        Assert.assertEquals(mockFBAuthenticator.getTokenEndpoint(), TestConstants.customFacebookEndpoint);
        // Get it from static variable for the second time
        Assert.assertEquals(mockFBAuthenticator.getTokenEndpoint(), TestConstants.customFacebookEndpoint);
    }

    @Test
    public void initUserInfoEndpointWithConfigs() throws Exception {

        new Expectations(mockFBAuthenticator) {{
            Deencapsulation.invoke(mockFBAuthenticator, "getAuthenticatorConfig");
            AuthenticatorConfig authenticatorConfig = new AuthenticatorConfig();
            Map parameters = new HashMap();
            parameters.put(FacebookAuthenticatorConstants
                    .FB_USER_INFO_URL, TestConstants.customUserInfoEndpoint);
            authenticatorConfig.setParameterMap(parameters);
            result = authenticatorConfig;
        }};
        Assert.assertEquals(mockFBAuthenticator.getUserInfoEndpoint(), TestConstants.customUserInfoEndpoint);
        // Get it from static variable for the second time
        Assert.assertEquals(mockFBAuthenticator.getUserInfoEndpoint(), TestConstants.customUserInfoEndpoint);
    }

    @Test
    public void getStateTest() throws Exception {

        new Expectations(mockFBAuthenticator) {{
            Deencapsulation.invoke(mockFBAuthenticator, "getAuthenticatorConfig");
            AuthenticatorConfig authenticatorConfig = new AuthenticatorConfig();
            Map parameters = new HashMap();
            parameters.put(FacebookAuthenticatorConstants
                    .FB_USER_INFO_URL, TestConstants.customUserInfoEndpoint);
            authenticatorConfig.setParameterMap(parameters);
            result = authenticatorConfig;
        }};
        Assert.assertEquals(mockFBAuthenticator.getUserInfoEndpoint(), TestConstants.customUserInfoEndpoint);
        // Get it from static variable for the second time
        Assert.assertEquals(mockFBAuthenticator.getUserInfoEndpoint(), TestConstants.customUserInfoEndpoint);
    }

    @Test
    public void initUserInfoEndpointWithoutConfigs() throws Exception {

        new Expectations(mockFBAuthenticator) {{
            Deencapsulation.invoke(mockFBAuthenticator, "getAuthenticatorConfig");
            AuthenticatorConfig authenticatorConfig = new AuthenticatorConfig();
            authenticatorConfig.setParameterMap(new HashMap<String, String>());
            result = authenticatorConfig;
        }};
        Assert.assertEquals(mockFBAuthenticator.getUserInfoEndpoint(), IdentityApplicationConstants.FB_USER_INFO_URL);
        // Get it from instance variable for the second time
        Assert.assertEquals(mockFBAuthenticator.getUserInfoEndpoint(), IdentityApplicationConstants.FB_USER_INFO_URL);
    }

    @Test(expectedExceptions = IOException.class)
    public void testSendRequestError() throws Exception {

        facebookAuthenticator.sendRequest(TestConstants.facebookTokenEndpoint);
    }

    @Test
    public void testSendRequest() throws Exception {

        Assert.assertNotNull(facebookAuthenticator.sendRequest("https://google.com"), "An error occured while doing " +
                "redirection");
    }


    @Test
    public void testAuthenticatorNames() {
        Assert.assertEquals(facebookAuthenticator.getName(), FacebookAuthenticatorConstants.AUTHENTICATOR_NAME, "FB " +
                "Authenticator did not return expected name");
        Assert.assertEquals(facebookAuthenticator.getFriendlyName(), "facebook", "FB authenticator did not return " +
                "expected friendly name");
    }

    @Test
    public void testGetLoginTypeWithNull() throws Exception {
        new Expectations() {
            {
                mockHttpServletRequest.getParameter("state");
                result = null;
            }
        };
        Assert.assertNull(facebookAuthenticator.getLoginType(mockHttpServletRequest), "getLoginType returned an " +
                "unexpected result");
    }

    @Test
    public void testInitiateAuthRequest() throws Exception {

        final String[] redirectedUrl = new String[1];
        buildExpectationsForInitiateReq(TestConstants.customFacebookEndpoint, "profile", TestConstants.callbackURL);
        new Expectations() {{
            mockHttpServletResponse.sendRedirect(anyString);
            result = new Delegate() {
                void sendRedirect(String redirectURL) {
                    redirectedUrl[0] = redirectURL;
                }
            };
        }};
        mockFBAuthenticator.initiateAuthenticationRequest(mockHttpServletRequest, mockHttpServletResponse,
                mockAuthenticationContext);

        Assert.assertTrue(redirectedUrl[0].contains("scope=profile"), "Scope is not present in redirect url");
        Assert.assertTrue(redirectedUrl[0].contains("response_type=code"), "Response type is not present in redirect " +
                "url");
        Assert.assertTrue(redirectedUrl[0].contains("client_id=" + TestConstants.dummyClientId), "Client ID is not " +
                "present in redirect url");
        Assert.assertTrue(redirectedUrl[0].contains("state=" + TestConstants.dummyCommonAuthId + "%2Cfacebook"),
                "State parameter is not present in redirect url");
    }

    @Test(expectedExceptions = AuthenticationFailedException.class)
    public void testInitAuthReqWithOAuthSystemException() throws Exception {

        buildExpectationsForInitiateReq(TestConstants.customFacebookEndpoint, "profile", TestConstants.callbackURL);
        new Expectations() {{
            mockHttpServletResponse.sendRedirect(anyString);
            result = new Delegate() {
                void sendRedirect(String redirectURL) throws OAuthSystemException {
                    throw new OAuthSystemException("Error while doing IO operation");
                }
            };
        }};
        mockFBAuthenticator.initiateAuthenticationRequest(mockHttpServletRequest, mockHttpServletResponse,
                mockAuthenticationContext);
    }

    @Test(expectedExceptions = AuthenticationFailedException.class)
    public void testInitiateAuthReqWithIOException() throws Exception {

        buildExpectationsForInitiateReq(TestConstants.customFacebookEndpoint, "profile", TestConstants.callbackURL);
        new Expectations() {{
            mockHttpServletResponse.sendRedirect(anyString);
            result = new Delegate() {
                void sendRedirect(String redirectURL) throws IOException {
                    throw new IOException("Error while doing IO operation");
                }
            };
        }};
        mockFBAuthenticator.initiateAuthenticationRequest(mockHttpServletRequest, mockHttpServletResponse,
                mockAuthenticationContext);
    }

    @Test
    public void testInitiateAuthReqWithDefaultConfigs() throws Exception {

        final String[] redirectedUrl = new String[1];
        final String customHost = "https://somehost:9443/commonauth";
        new Expectations() {
            { /* define in static block */
                mockIdentityUtil.getServerURL(anyString, anyBoolean, anyBoolean);
                result = customHost;
            }
        };
        buildExpectationsForInitiateReq(null, null, null);
        new Expectations() {{
            mockHttpServletResponse.sendRedirect(anyString);
            result = new Delegate() {
                void sendRedirect(String redirectURL) {
                    redirectedUrl[0] = redirectURL;
                }
            };
        }};
        mockFBAuthenticator.initiateAuthenticationRequest(mockHttpServletRequest, mockHttpServletResponse,
                mockAuthenticationContext);
        Assert.assertTrue(redirectedUrl[0].contains("scope=email"), "Scope is not present in redirection url");
        Assert.assertTrue(redirectedUrl[0].contains("response_type=code"), "Response type is not present in redirect " +
                "url");
        Assert.assertTrue(redirectedUrl[0].contains("client_id=" + TestConstants.dummyClientId), "Client ID is not " +
                "present in redirect url");
        Assert.assertTrue(redirectedUrl[0].contains("state=" + TestConstants.dummyCommonAuthId + "%2Cfacebook"),
                "State parameter is not present in redirect url");
    }

    private void buildExpectationsForInitiateReq(final String fbURL, final String scope, final String callbackURL) {

        new Expectations(mockFBAuthenticator) {{
            Deencapsulation.invoke(mockFBAuthenticator, "getAuthenticatorConfig");
            AuthenticatorConfig authenticatorConfig = new AuthenticatorConfig();
            Map parameters = new HashMap();
            parameters.put(FacebookAuthenticatorConstants.FB_AUTHZ_URL, fbURL);
            authenticatorConfig.setParameterMap(parameters);
            result = authenticatorConfig;
        }};

        new Expectations() {
            { /* define in static block */
                Map parameters = new HashMap();
                parameters.put(FacebookAuthenticatorConstants.CLIENT_ID, TestConstants.dummyClientId);
                parameters.put(FacebookAuthenticatorConstants.SCOPE, scope);
                parameters.put(FacebookAuthenticatorConstants.CLIENT_ID, TestConstants.dummyClientId);
                parameters.put(FacebookAuthenticatorConstants.FB_CALLBACK_URL, callbackURL);
                mockAuthenticationContext.getAuthenticatorProperties();
                result = parameters;
            }
        };

        new Expectations() {
            { /* define in static block */
                mockAuthenticationContext.getContextIdentifier();
                result = TestConstants.dummyCommonAuthId;
            }
        };
    }
}
