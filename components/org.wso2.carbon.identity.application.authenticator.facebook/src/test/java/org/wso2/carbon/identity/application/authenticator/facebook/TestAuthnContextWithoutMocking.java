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
import org.testng.Assert;
import org.testng.annotations.BeforeMethod;
import org.testng.annotations.Test;
import org.wso2.carbon.identity.application.authentication.framework.config.model.ExternalIdPConfig;
import org.wso2.carbon.identity.application.authentication.framework.context.AuthenticationContext;
import org.wso2.carbon.identity.application.authentication.framework.exception.ApplicationAuthenticatorException;
import org.wso2.carbon.identity.application.authentication.framework.util.FrameworkUtils;
import org.wso2.carbon.identity.application.common.model.ClaimConfig;
import org.wso2.carbon.identity.application.common.model.ClaimMapping;
import org.wso2.carbon.identity.application.common.model.IdentityProvider;

import java.util.HashMap;
import java.util.Map;

public class TestAuthnContextWithoutMocking {

    @Mocked
    private Log mockedLog;
    private FacebookAuthenticator facebookAuthenticator;
    @Mocked
    private ExternalIdPConfig externalIdPConfig;
    @Tested
    private FacebookAuthenticator mockFBAuthenticator;
    @Mocked
    FrameworkUtils mockFrameworkUtils;

    @BeforeMethod
    public void setUp() throws Exception {
        facebookAuthenticator = new FacebookAuthenticator();
    }

    @Test
    public void testSetSubject() throws Exception {

        AuthenticationContext authenticationContext = new AuthenticationContext();
        Map<String, Object> jsonMap = new HashMap<>();
        jsonMap.put(FacebookAuthenticatorConstants.DEFAULT_USER_IDENTIFIER, TestConstants.dummyUsername);
        facebookAuthenticator.setSubject(authenticationContext, jsonMap);
        Assert.assertEquals(authenticationContext.getSubject().getAuthenticatedSubjectIdentifier(), TestConstants
                .dummyUsername, "Username which was set to context not available in the context");
    }

    @Test(expectedExceptions = ApplicationAuthenticatorException.class)
    public void testSetSubjectWithoutSubject() throws Exception {

        AuthenticationContext authenticationContext = new AuthenticationContext();
        Map<String, Object> jsonMap = new HashMap<>();
        facebookAuthenticator.setSubject(authenticationContext, jsonMap);
    }

    @Test
    public void testBuildClaims() throws Exception {

        boolean usernameFound = false;
        boolean firstNameFound = false;
        AuthenticationContext authenticationContext = buildClaims(TestConstants.customClaimDialect);
        Assert.assertEquals(authenticationContext.getSubject().getAuthenticatedSubjectIdentifier(), TestConstants
                .dummyUsername, "User was not set from buildClaims");
        Assert.assertEquals(authenticationContext.getSubject().getUserAttributes().size(), 2, "User attributes were " +
                "not fully set");

        for (Map.Entry<ClaimMapping, String> entry : authenticationContext.getSubject().getUserAttributes().entrySet
                ()) {
            if ((TestConstants.FIRST_NAME + "_value").equals(entry.getValue())) {
                if ((TestConstants.customClaimDialect + "/" + TestConstants.FIRST_NAME).equals(entry.getKey()
                        .getLocalClaim()
                        .getClaimUri())) {
                    firstNameFound = true;
                }
            }
            if (TestConstants.dummyUsername.equals(entry.getValue())) {
                if ((TestConstants.customClaimDialect + "/id").equals(entry.getKey().getLocalClaim()
                        .getClaimUri())) {
                    usernameFound = true;
                }
            }
        }
        Assert.assertTrue(firstNameFound, "First name not found in user attributes");
        Assert.assertTrue(usernameFound, "User ID not found in user attributes");
    }

    @Test
    public void testBuildClaimWithoutCustomDialect() throws Exception {

        boolean usernameFound = false;
        boolean firstNameFound = false;
        AuthenticationContext authenticationContext = buildClaims(null);
        Assert.assertEquals(authenticationContext.getSubject().getAuthenticatedSubjectIdentifier(), TestConstants
                .dummyUsername, "User was not set from buildClaims");
        Assert.assertEquals(authenticationContext.getSubject().getUserAttributes().size(), 2, "User attributes were " +
                "not fully set");

        for (Map.Entry<ClaimMapping, String> entry : authenticationContext.getSubject().getUserAttributes().entrySet
                ()) {
            if ((TestConstants.FIRST_NAME + "_value").equals(entry.getValue())) {
                if (TestConstants.FIRST_NAME.equals(entry.getKey()
                        .getLocalClaim()
                        .getClaimUri())) {
                    firstNameFound = true;
                }
            }
            if (TestConstants.dummyUsername.equals(entry.getValue())) {
                if ("id".equals(entry.getKey().getLocalClaim()
                        .getClaimUri())) {
                    usernameFound = true;
                }
            }
        }
        Assert.assertTrue(firstNameFound, "First name not found in user attributes");
        Assert.assertTrue(usernameFound, "User ID not found in user attributes");
    }

    private AuthenticationContext buildClaims(final String claimDialect) throws Exception {

        TestUtils.enableDebugLogs(mockedLog, FacebookAuthenticator.class);
        AuthenticationContext authenticationContext = new AuthenticationContext();
        ExternalIdPConfig externalIdPConfig = new ExternalIdPConfig(new IdentityProvider());
        ClaimConfig claimConfig = new ClaimConfig();
        claimConfig.setUserClaimURI("http://something");
        externalIdPConfig.getIdentityProvider().setClaimConfig(claimConfig);
        authenticationContext.setExternalIdP(externalIdPConfig);
        new Expectations(mockFBAuthenticator) {{
            Deencapsulation.invoke(mockFBAuthenticator, "getClaimDialectURI");
            result = claimDialect;
        }};
        new Expectations(mockFBAuthenticator) {{
            Deencapsulation.invoke(mockFBAuthenticator, "shouldPrefixClaimDialectUri");
            if (claimDialect == null) {
                result = false;
            } else {
                result = true;
            }
        }};
        Map<String, Object> jsonMap = new HashMap<>();
        jsonMap.put(FacebookAuthenticatorConstants.DEFAULT_USER_IDENTIFIER, TestConstants.dummyUsername);
        jsonMap.put("someTestKey", null);
        jsonMap.put(TestConstants.FIRST_NAME, TestConstants.FIRST_NAME + "_value");
        mockFBAuthenticator.buildClaims(authenticationContext, jsonMap, claimConfig);
        return authenticationContext;
    }

}
