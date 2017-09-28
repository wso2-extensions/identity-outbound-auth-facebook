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
import org.apache.commons.logging.Log;
import org.osgi.framework.BundleContext;
import org.osgi.framework.ServiceRegistration;
import org.osgi.service.component.ComponentContext;
import org.testng.Assert;
import org.testng.annotations.BeforeMethod;
import org.testng.annotations.Test;
import org.wso2.carbon.identity.application.authentication.framework.ApplicationAuthenticator;
import org.wso2.carbon.identity.application.authenticator.facebook.internal.SocialAuthenticatorServiceComponent;

import java.util.Dictionary;

public class ServiceComponentTests {

    SocialAuthenticatorServiceComponent socialAuthenticatorServiceComponent;
    @Mocked
    ComponentContext mockComponentContext;
    @Mocked
    BundleContext mockBundleContext;
    @Mocked
    private Log mockedLog;

    @BeforeMethod
    public void setUp() throws Exception {
        socialAuthenticatorServiceComponent = new SocialAuthenticatorServiceComponent();
    }

    @Test
    public void testSuccessfulActivate() throws Exception {

        TestUtils.enableDebugLogs(mockedLog, SocialAuthenticatorServiceComponent.class);
        final String[] classNameResult = new String[1];
        final Object[] authenticatorResult = new Object[1];
        new Expectations() {{
            mockComponentContext.getBundleContext();
            result = new Delegate() {
                BundleContext getBundleContext() {
                    return mockBundleContext;
                }
            };
        }};
        new Expectations() {{
            mockBundleContext.registerService(anyString, any, (Dictionary<String, ?>) any);
            result = new Delegate() {
                ServiceRegistration<?> registerService(String className, Object authenticator, Dictionary<String, ?>
                        params) {
                    classNameResult[0] = className;
                    authenticatorResult[0] = authenticator;
                    return null;
                }
            };
        }};
        Deencapsulation.invoke(socialAuthenticatorServiceComponent, "activate", mockComponentContext);
        Assert.assertEquals(classNameResult[0], String.valueOf(ApplicationAuthenticator.class.getCanonicalName()), "Registered " +
                "authenticator is not an application authenticator");
        Assert.assertTrue(authenticatorResult[0] instanceof FacebookAuthenticator, "Registered authenticator is not a" +
                " FacebookAuthenticator");
    }

    @Test
    public void testErroneousActivate() throws Exception {

        final String[] classNameResult = new String[1];
        final Object[] authenticatorResult = new Object[1];
        new Expectations() {{
            mockComponentContext.getBundleContext();
            result = new Delegate() {
                BundleContext getBundleContext() throws Throwable {
                    throw new Throwable("Throwable is returned while getting bundle context");
                }
            };
        }};
        Deencapsulation.invoke(socialAuthenticatorServiceComponent, "activate", mockComponentContext);
        // Should not throw any exception even if a nullPointerException occurs inside.
    }

    @Test
    public void testDeactivate() throws Exception {

        TestUtils.enableDebugLogs(mockedLog, SocialAuthenticatorServiceComponent.class);
        Deencapsulation.invoke(socialAuthenticatorServiceComponent, "deactivate", mockComponentContext);
        // Deactivate method should be implemented within the service component and should run without giving exceptions
    }
}
