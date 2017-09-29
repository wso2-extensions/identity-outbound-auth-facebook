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

public class TestConstants {

    public static final String facebookTokenEndpoint = "https://graph.facebook.com/oauth/access_token";
    public static final String callbackURL = "https://localhost:9443/commonauth";
    public static final String dummyClientId = "clientIDqwertyuio123456789zxcvbnm";
    public static final String dummyClientSecret = "clientSecretpoiuytrewqlkjhgfdsa09876543";
    public static final String dummyAuthCode = "code67890765432tyuio";
    public static final String dummyUsername = "testUser";
    public static final String REDIRECT_URI = "redirect_uri";
    public static final String FIRST_NAME = "first_name";
    public static final String LAST_NAME = "last_name";
    public static final String queryParamSeparator = "&";
    public static final String queryParamStarter = "?";
    public static final String queryParamValueSeparator = "=";
    public static final String CLIENT_SECRET = "client_secret";
    public static final String CLIENT_ID = "client_id";
    public static final String dummyCommonAuthId = "1234567890";
    public static final String customUserInfoEndpoint = "https://facebook.custom.userinfo.com";
    public static final String customFacebookEndpoint = "https://facebook.custom.com";
    public static final String customClaimDialect = "http://custom.claim.dialect";

    public static final String tokenResponse =
            "{\"access_token\":\"$token\"," +
                    "\"token_type\":\"bearer\",\"expires_in\":5183760}";

    public static final String userInfoResponse = "{\"first_name\":\"darshan\",\"last_name\":\"dlasname\"," +
            "\"gender\":\"male\",\"email\":\"testmail\\u0040hotmail.com\",\"id\":\"4567890987654\"}";
}
