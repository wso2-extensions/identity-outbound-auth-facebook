package org.wso2.carbon.identity.application.authenticator.facebook;

import org.apache.oltu.oauth2.client.request.OAuthClientRequest;
import org.testng.Assert;
import org.testng.annotations.BeforeMethod;
import org.testng.annotations.Test;
import org.wso2.carbon.identity.application.authentication.framework.exception.ApplicationAuthenticatorException;

public class TestWithoutMockRequestBuilder {
    private FacebookAuthenticator facebookAuthenticator;

    @BeforeMethod
    public void setUp() throws Exception {
        facebookAuthenticator = new FacebookAuthenticator();
    }

    @Test
    public void testTokenRequest() throws ApplicationAuthenticatorException {
        OAuthClientRequest oAuthClientRequest = facebookAuthenticator.buidTokenRequest(TestConstants.facebookTokenEndpoint,
                TestConstants.dummyClientId, TestConstants.dummyClientSecret, TestConstants.callbackURL, TestConstants.dummyAuthCode);
        Assert.assertNotNull(oAuthClientRequest);
        Assert.assertEquals(oAuthClientRequest.getLocationUri(), TestUtils.getTokenRequestUrl());
    }

}
