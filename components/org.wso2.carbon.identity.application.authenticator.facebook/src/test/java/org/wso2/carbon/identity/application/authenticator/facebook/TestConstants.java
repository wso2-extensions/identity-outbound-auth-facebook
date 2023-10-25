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
    public static String accessToken = "4952b467-86b2-31df-b63c-0bf25cec4f86s";
    public static String idToken = "eyJ4NXQiOiJOVEF4Wm1NeE5ETXlaRGczTVRVMVpHTTBNekV6T0RKaFpXSTRORE5" +
            "sWkRVMU9HRmtOakZpTVEiLCJraWQiOiJOVEF4Wm1NeE5ETXlaRGczTVRVMVpHTTBNekV6T0RKaFpXSTRORE5sWkRVMU9" +
            "HRmtOakZpTVEiLCJhbGciOiJSUzI1NiJ9.eyJzdWIiOiJhZG1pbiIsImF1ZCI6WyJ1NUZJZkc1eHpMdkJHaWFtb0FZenpjc" +
            "XBCcWdhIl0sImF6cCI6InU1RklmRzV4ekx2QkdpYW1vQVl6emNxcEJxZ2EiLCJhdXRoX3RpbWUiOjE1MDY1NzYwODAsImlzcyI6" +
            "Imh0dHBzOlwvXC9sb2NhbGhvc3Q6OTQ0M1wvb2F1dGgyXC90b2tlbiIsImV4cCI6MTUwNjU3OTY4NCwibm9uY2UiOiI" +
            "wZWQ4ZjFiMy1lODNmLTQ2YzAtOGQ1Mi1mMGQyZTc5MjVmOTgiLCJpYXQiOjE1MDY1NzYwODQsInNpZCI6Ijg3MDZmNWR" +
            "hLTU0ZmMtNGZiMC1iNGUxLTY5MDZmYTRiMDRjMiJ9.HopPYFs4lInXvGztNEkJKh8Kdy52eCGbzYy6PiVuM_BlCcGff3SHO" +
            "oZxDH7JbIkPpKBe0cnYQWBxfHuGTUWhvnu629ek6v2YLkaHlb_Lm04xLD9FNxuZUNQFw83pQtDVpoX5r1V-F0DdUc7gA1RKN3" +
            "xMVYgRyfslRDveGYplxVVNQ1LU3lrZhgaTfcMEsC6rdbd1HjdzG71EPS4674HCSAUelOisNKGa2NgORpldDQsj376QD0G9Mhc8WtW" +
            "oguftrCCGjBy1kKT4VqFLOqlA-8wUhOj_rZT9SUIBQRDPu0RZobvsskqYo40GEZrUoa";
    public static String sessionDataKey = "7b1c8131-c6bd-4682-892e-1a948a9e57e8";
    public static String redirectUrl = "https://accounts.facebook.com/o/oauth2/v2/auth?scope=openid&" +
            "response_type=code&redirect_uri=https%3A%2F%2Flocalhost%3A9443%2Fcommonauth&" +
            "state=958e9049-8cd2-4580-8745-6679ac8d33f6%2COIDC&nonce=0ed8f1b3-e83f-46c0-8d52-f0d2e7925f98&" +
            "client_id=sample.client-id";

    public static final String tokenResponse =
            "{\"access_token\":\"$token\"," +
                    "\"token_type\":\"bearer\",\"expires_in\":5183760}";

    public static final String userInfoResponse = "{\"first_name\":\"darshan\",\"last_name\":\"dlasname\"," +
            "\"gender\":\"male\",\"email\":\"testmail\\u0040hotmail.com\",\"id\":\"4567890987654\"}";
}
