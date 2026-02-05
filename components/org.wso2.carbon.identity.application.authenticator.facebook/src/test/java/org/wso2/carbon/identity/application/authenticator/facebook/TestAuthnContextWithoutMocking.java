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
import org.mockito.Mock;
import org.mockito.MockedStatic;
import org.mockito.MockitoAnnotations;
import org.testng.Assert;
import org.testng.annotations.AfterMethod;
import org.testng.annotations.BeforeMethod;
import org.testng.annotations.Test;
import org.wso2.carbon.identity.application.authentication.framework.config.model.ExternalIdPConfig;
import org.wso2.carbon.identity.application.authentication.framework.context.AuthenticationContext;
import org.wso2.carbon.identity.application.authentication.framework.exception.ApplicationAuthenticatorException;
import org.wso2.carbon.identity.application.common.model.ClaimConfig;
import org.wso2.carbon.identity.application.common.model.ClaimMapping;
import org.wso2.carbon.identity.application.common.model.IdentityProvider;
import org.wso2.carbon.identity.central.log.mgt.utils.LogConstants;
import org.wso2.carbon.identity.central.log.mgt.utils.LoggerUtils;
import org.wso2.carbon.utils.DiagnosticLog;

import java.lang.reflect.Method;
import java.util.HashMap;
import java.util.Map;

import static org.mockito.Mockito.mockStatic;
import static org.wso2.carbon.identity.application.authenticator.facebook.FacebookAuthenticatorConstants.LogConstants.ActionIDs.PROCESS_AUTHENTICATION_RESPONSE;
import static org.wso2.carbon.identity.application.authenticator.facebook.FacebookAuthenticatorConstants.LogConstants.DIAGNOSTIC_LOG_KEY_NAME;
import static org.wso2.carbon.identity.application.authenticator.facebook.FacebookAuthenticatorConstants.LogConstants.OUTBOUND_AUTH_FACEBOOK_SERVICE;

public class TestAuthnContextWithoutMocking {

    @Mock
    private Log mockedLog;
    private FacebookAuthenticator facebookAuthenticator;
    @Mock
    private ExternalIdPConfig externalIdPConfig;
    
    private FacebookAuthenticator mockFBAuthenticator;
    private MockedStatic<LoggerUtils> mockedLoggerUtils;

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
        mockedLoggerUtils = mockStatic(LoggerUtils.class);
        mockedLoggerUtils.when(LoggerUtils::isDiagnosticLogsEnabled).thenReturn(false);
        
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
        mockedLoggerUtils = mockStatic(LoggerUtils.class);
        mockedLoggerUtils.when(LoggerUtils::isDiagnosticLogsEnabled).thenReturn(true);
        
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
        addDiagnosticLogBuilderToAuthContext(authenticationContext);
        ExternalIdPConfig externalIdPConfig = new ExternalIdPConfig(new IdentityProvider());
        ClaimConfig claimConfig = new ClaimConfig();
        claimConfig.setUserClaimURI("http://something");
        externalIdPConfig.getIdentityProvider().setClaimConfig(claimConfig);
        authenticationContext.setExternalIdP(externalIdPConfig);
        
        // Use custom authenticator with overridden methods
        FacebookAuthenticator customAuthenticator = new FacebookAuthenticator() {
            @Override
            public String getClaimDialectURI() {
                return claimDialect;
            }
            
            @Override
            public boolean shouldPrefixClaimDialectUri() {
                return claimDialect != null;
            }
        };
        
        Map<String, Object> jsonMap = new HashMap<>();
        jsonMap.put(FacebookAuthenticatorConstants.DEFAULT_USER_IDENTIFIER, TestConstants.dummyUsername);
        jsonMap.put("someTestKey", null);
        jsonMap.put(TestConstants.FIRST_NAME, TestConstants.FIRST_NAME + "_value");
        customAuthenticator.buildClaims(authenticationContext, jsonMap, claimConfig);
        return authenticationContext;
    }

    private void addDiagnosticLogBuilderToAuthContext(AuthenticationContext authenticationContext) {

        DiagnosticLog.DiagnosticLogBuilder diagnosticLogBuilder = new DiagnosticLog.DiagnosticLogBuilder(
                    OUTBOUND_AUTH_FACEBOOK_SERVICE, PROCESS_AUTHENTICATION_RESPONSE);
            diagnosticLogBuilder.inputParam(LogConstants.InputKeys.STEP, authenticationContext.getCurrentStep())
                    .logDetailLevel(DiagnosticLog.LogDetailLevel.APPLICATION);
        authenticationContext.setProperty(DIAGNOSTIC_LOG_KEY_NAME, diagnosticLogBuilder);
    }

}
