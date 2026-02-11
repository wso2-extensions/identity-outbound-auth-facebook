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
import org.mockito.MockitoAnnotations;
import org.osgi.framework.BundleContext;
import org.osgi.framework.ServiceRegistration;
import org.osgi.service.component.ComponentContext;
import org.testng.Assert;
import org.testng.annotations.BeforeMethod;
import org.testng.annotations.Test;
import org.wso2.carbon.identity.application.authentication.framework.ApplicationAuthenticator;
import org.wso2.carbon.identity.application.authenticator.facebook.internal.SocialAuthenticatorServiceComponent;

import java.lang.reflect.Method;
import java.util.Dictionary;

import static org.mockito.ArgumentMatchers.any;
import static org.mockito.ArgumentMatchers.anyString;
import static org.mockito.ArgumentMatchers.eq;
import static org.mockito.ArgumentMatchers.isNull;
import static org.mockito.Mockito.doAnswer;
import static org.mockito.Mockito.when;

public class ServiceComponentTests {

    SocialAuthenticatorServiceComponent socialAuthenticatorServiceComponent;
    @Mock
    ComponentContext mockComponentContext;
    @Mock
    BundleContext mockBundleContext;
    @Mock
    private Log mockedLog;

    @BeforeMethod
    public void setUp() throws Exception {
        MockitoAnnotations.openMocks(this);
        socialAuthenticatorServiceComponent = new SocialAuthenticatorServiceComponent();
    }

    @Test
    public void testSuccessfulActivate() throws Exception {
        TestUtils.enableDebugLogs(mockedLog, SocialAuthenticatorServiceComponent.class);
        
        final String[] classNameResult = new String[1];
        final Object[] authenticatorResult = new Object[1];
        final boolean[] firstCall = {true};
        
        when(mockComponentContext.getBundleContext()).thenReturn(mockBundleContext);
        
        doAnswer(invocation -> {
            // Capture only the first service registration (ApplicationAuthenticator)
            if (firstCall[0]) {
                classNameResult[0] = invocation.getArgument(0);
                authenticatorResult[0] = invocation.getArgument(1);
                firstCall[0] = false;
            }
            return null;
        }).when(mockBundleContext).registerService(anyString(), any(), isNull());
        
        // Use reflection to call protected activate method
        Method activateMethod = SocialAuthenticatorServiceComponent.class.getDeclaredMethod("activate", ComponentContext.class);
        activateMethod.setAccessible(true);
        activateMethod.invoke(socialAuthenticatorServiceComponent, mockComponentContext);
        
        Assert.assertEquals(classNameResult[0], String.valueOf(ApplicationAuthenticator.class.getCanonicalName()), "Registered " +
                "authenticator is not an application authenticator");
        Assert.assertTrue(authenticatorResult[0] instanceof FacebookAuthenticator, "Registered authenticator is not a" +
                " FacebookAuthenticator");
    }

    @Test
    public void testErroneousActivate() throws Exception {
        when(mockComponentContext.getBundleContext()).thenThrow(new RuntimeException("Throwable is returned while getting bundle context"));
        
        // Use reflection to call protected activate method
        Method activateMethod = SocialAuthenticatorServiceComponent.class.getDeclaredMethod("activate", ComponentContext.class);
        activateMethod.setAccessible(true);
        activateMethod.invoke(socialAuthenticatorServiceComponent, mockComponentContext);
        // Should not throw any exception even if a nullPointerException occurs inside.
    }

    @Test
    public void testDeactivate() throws Exception {
        TestUtils.enableDebugLogs(mockedLog, SocialAuthenticatorServiceComponent.class);
        
        // Use reflection to call protected deactivate method
        Method deactivateMethod = SocialAuthenticatorServiceComponent.class.getDeclaredMethod("deactivate", ComponentContext.class);
        deactivateMethod.setAccessible(true);
        deactivateMethod.invoke(socialAuthenticatorServiceComponent, mockComponentContext);
        // Deactivate method should be implemented within the service component and should run without giving exceptions
    }
}
