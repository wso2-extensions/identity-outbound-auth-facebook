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

import org.apache.oltu.oauth2.client.request.OAuthClientRequest;
import org.testng.Assert;
import org.testng.annotations.BeforeMethod;
import org.testng.annotations.Test;

import java.net.URLEncoder;

public class TestWithoutMockRequestBuilder {
    private FacebookAuthenticator facebookAuthenticator;

    @BeforeMethod
    public void setUp() throws Exception {
        facebookAuthenticator = new FacebookAuthenticator();
    }

    @Test
    public void testTokenRequest() throws Exception {

        OAuthClientRequest oAuthClientRequest = facebookAuthenticator.buidTokenRequest(TestConstants.facebookTokenEndpoint,
                TestConstants.dummyClientId, TestConstants.dummyClientSecret, TestConstants.callbackURL, TestConstants.dummyAuthCode);
        Assert.assertTrue(oAuthClientRequest.getLocationUri().contains("client_secret=" + TestConstants
                .dummyClientSecret), "Client secret does not contain in the token request");
        Assert.assertTrue(oAuthClientRequest.getLocationUri().contains(TestConstants.REDIRECT_URI + "=" + URLEncoder
                .encode(TestConstants.callbackURL)), "Redirection URI is not present in the token request");
        Assert.assertTrue(oAuthClientRequest.getLocationUri().contains("code=" + TestConstants.dummyAuthCode),
                "Authorization code does not contain in the token request");
        Assert.assertTrue(oAuthClientRequest.getLocationUri().contains("client_id=" + TestConstants.dummyClientId),
                "Client ID does not contain in the token request");
    }

}
