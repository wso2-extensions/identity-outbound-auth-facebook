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
import org.mockito.MockedStatic;
import org.wso2.carbon.identity.application.authentication.framework.util.FrameworkConstants;
import org.wso2.carbon.identity.central.log.mgt.utils.LoggerUtils;
import org.wso2.carbon.identity.core.ServiceURL;
import org.wso2.carbon.identity.core.ServiceURLBuilder;
import org.wso2.carbon.identity.core.URLBuilderException;

import java.lang.reflect.Field;
import java.lang.reflect.Modifier;

import static org.mockito.ArgumentMatchers.any;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.when;

public class TestUtils {

    public static void enableDebugLogs(final Log mockedLog, Class className) throws NoSuchFieldException,
            IllegalAccessException {
        when(mockedLog.isDebugEnabled()).thenReturn(true);
        
        try {
            Field field = className.getDeclaredField("log");
            field.setAccessible(true);
            
            // Remove final modifier if possible (Java 11 and earlier)
            try {
                Field modifiersField = Field.class.getDeclaredField("modifiers");
                modifiersField.setAccessible(true);
                modifiersField.setInt(field, field.getModifiers() & ~Modifier.FINAL);
                field.set(null, mockedLog);
            } catch (NoSuchFieldException e) {
                // Java 12+ doesn't allow modifying modifiers field
                // Skip setting the mocked log as we can't modify final static fields
                // The actual log will be used instead
            }
        } catch (Exception e) {
            // If we can't set the log field, that's okay - tests will use the actual logger
        }
    }

    public static void mockServiceURLBuilder(MockedStatic<ServiceURLBuilder> mockedServiceURLBuilder) 
            throws URLBuilderException {
        final String customHost = "https://somehost:9443/commonauth";
        
        ServiceURLBuilder mockBuilder = mock(ServiceURLBuilder.class);
        ServiceURL mockServiceURL = mock(ServiceURL.class);
        
        mockedServiceURLBuilder.when(ServiceURLBuilder::create).thenReturn(mockBuilder);
        when(mockBuilder.addPath(FrameworkConstants.COMMONAUTH)).thenReturn(mockBuilder);
        when(mockBuilder.build()).thenReturn(mockServiceURL);
        when(mockServiceURL.getAbsolutePublicURL()).thenReturn(customHost);
    }
}
