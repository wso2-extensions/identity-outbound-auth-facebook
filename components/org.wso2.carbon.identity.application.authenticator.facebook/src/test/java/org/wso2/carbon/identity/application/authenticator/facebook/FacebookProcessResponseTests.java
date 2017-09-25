package org.wso2.carbon.identity.application.authenticator.facebook;

import mockit.Deencapsulation;
import mockit.Expectations;
import mockit.Mocked;
import mockit.Tested;
import org.apache.commons.logging.Log;
import org.apache.commons.logging.LogFactory;
import org.apache.oltu.oauth2.client.response.OAuthAuthzResponse;
import org.apache.oltu.oauth2.common.exception.OAuthProblemException;
import org.apache.oltu.oauth2.common.exception.OAuthSystemException;
import org.testng.Assert;
import org.testng.annotations.BeforeMethod;
import org.testng.annotations.Test;
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
    Log mockedLog = LogFactory.getLog(FacebookAuthenticator.class);
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


    @BeforeMethod
    public void setUp() throws Exception {
        facebookAuthenticator = new FacebookAuthenticator();
    }

    @Test(expectedExceptions = AuthenticationFailedException.class)
    public void testProcessAuthResponseWithoutCode() throws ApplicationAuthenticatorException, OAuthSystemException,
            AuthenticationFailedException, IOException {
        buildExpectationsForInitiateReq(TestConstants.customFacebookEndpoint, "profile", TestConstants.callbackURL);
        mockFBAuthenticator.processAuthenticationResponse(mockHttpServletRequest, mockHttpServletResponse,
                mockAuthenticationContext);
    }

    @Test(expectedExceptions = AuthenticationFailedException.class)
    public void testProcessAuthResponseWithFailedTokenReq() throws ApplicationAuthenticatorException,
            OAuthSystemException,
            AuthenticationFailedException, IOException, OAuthProblemException {
        mockIdentityUtil();
        new Expectations() {
            {
                mockAuthzResponse.oauthCodeAuthzResponse((HttpServletRequest) withNotNull());
                result = mockAuthzResponse;
                mockAuthzResponse.getCode();
                result = TestConstants.dummyAuthCode;
            }
        };

        buildExpectationsForInitiateReq(TestConstants.customFacebookEndpoint, "profile", null);
        mockFBAuthenticator.processAuthenticationResponse(mockHttpServletRequest, mockHttpServletResponse,
                mockAuthenticationContext);
    }

    @Test
    public void testProcessAuthResponseWithCode() throws ApplicationAuthenticatorException, OAuthSystemException,
            AuthenticationFailedException, IOException, OAuthProblemException {
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
        buildExpectationsForInitiateReq(TestConstants.customFacebookEndpoint, "profile", null);
        mockFBAuthenticator.processAuthenticationResponse(mockHttpServletRequest, mockHttpServletResponse,
                mockAuthenticationContext);
    }

    @Test(expectedExceptions = AuthenticationFailedException.class)
    public void testProcessAuthResponseWithErrorTokenResponse() throws ApplicationAuthenticatorException,
            OAuthSystemException,
            AuthenticationFailedException, IOException, OAuthProblemException {
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
        buildExpectationsForInitiateReq(TestConstants.customFacebookEndpoint, "profile", null);
        mockFBAuthenticator.processAuthenticationResponse(mockHttpServletRequest, mockHttpServletResponse,
                mockAuthenticationContext);
    }

    @Test(expectedExceptions = ApplicationAuthenticatorException.class)
    public void testGetTokenWithMalformedURI() throws ApplicationAuthenticatorException,
            OAuthSystemException,
            AuthenticationFailedException, IOException, OAuthProblemException {
        mockTokenAndUserInfoCalls(TestConstants.tokenResponse, TestConstants.userInfoResponse);
        new Expectations(mockFBAuthenticator) {{
            Deencapsulation.invoke(mockFBAuthenticator, "sendRequest", anyString);
            result = new MalformedURLException("Error while building url");
        }};
        mockFBAuthenticator.getToken("abcd", TestConstants.dummyClientId, TestConstants
                .CLIENT_SECRET, null, TestConstants.dummyAuthCode);
    }

    @Test
    public void getUserInforWithFields() throws ApplicationAuthenticatorException,
            OAuthSystemException,
            AuthenticationFailedException, IOException, OAuthProblemException {
        mockTokenAndUserInfoCalls(TestConstants.tokenResponse, TestConstants.userInfoResponse);
        String userInfoString = mockFBAuthenticator.getUserInfoString(TestConstants.facebookTokenEndpoint,
                "first_name,last_name", TestConstants.dummyAuthCode);
        Assert.assertEquals(userInfoString, TestConstants.tokenResponse);
    }

    @Test(expectedExceptions = ApplicationAuthenticatorException.class)
    public void getUserInfoWithMalformedURL() throws ApplicationAuthenticatorException,
            OAuthSystemException,
            AuthenticationFailedException, IOException, OAuthProblemException {
        mockTokenAndUserInfoCalls(TestConstants.tokenResponse, TestConstants.userInfoResponse);
        new Expectations(mockFBAuthenticator) {{
            Deencapsulation.invoke(mockFBAuthenticator, "sendRequest", anyString);
            result = new MalformedURLException("Error while building url");
        }};
        mockFBAuthenticator.getUserInfoString(TestConstants.facebookTokenEndpoint,
                "first_name,last_name", TestConstants.dummyAuthCode);
    }

    @Test(expectedExceptions = ApplicationAuthenticatorException.class)
    public void getUserInfoWithIOExceptionL() throws ApplicationAuthenticatorException,
            OAuthSystemException,
            AuthenticationFailedException, IOException, OAuthProblemException {
        mockTokenAndUserInfoCalls(TestConstants.tokenResponse, TestConstants.userInfoResponse);
        new Expectations(mockFBAuthenticator) {{
            Deencapsulation.invoke(mockFBAuthenticator, "sendRequest", anyString);
            result = new IOException("Error while building url");
        }};
        mockFBAuthenticator.getUserInfoString(TestConstants.facebookTokenEndpoint,
                "first_name,last_name", TestConstants.dummyAuthCode);
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
