/*
 * Copyright (c) 2014, WSO2 LLC. (http://www.wso2.com).
 *
 * WSO2 LLC. licenses this file to you under the Apache License,
 * Version 2.0 (the "License"); you may not use this file except
 * in compliance with the License.
 * You may obtain a copy of the License at
 *
 * http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing,
 * software distributed under the License is distributed on an
 * "AS IS" BASIS, WITHOUT WARRANTIES OR CONDITIONS OF ANY
 * KIND, either express or implied.  See the License for the
 * specific language governing permissions and limitations
 * under the License.
 */

package org.wso2.carbon.identity.application.authenticator.facebook;

/**
 * This class holds the constants related to the Facebook authenticator.
 */
public class FacebookAuthenticatorConstants {

    public static final String AUTHENTICATOR_NAME = "FacebookAuthenticator";
    public static final String FACEBOOK_LOGIN_TYPE = "facebook";
    public static final String AUTHENTICATOR_FACEBOOK = "authenticator.facebook";
    public static final String AUTHENTICATOR_FRIENDLY_NAME = "facebook";

    public static final String OAUTH2_GRANT_TYPE_CODE = "code";
    public static final String OAUTH2_PARAM_STATE = "state";
    public static final String OAUTH2_PARAM_ERROR = "error";
    public static final String OAUTH2_PARAM_ERROR_CODE = "error_code";
    public static final String OAUTH2_PARAM_ERROR_DESCRIPTION = "error_description";
    public static final String OAUTH2_PARAM_ERROR_REASON = "error_reason";
    public static final String EMAIL = "email";

    public static final String SCOPE = "Scope";
    public static final String USER_INFO_FIELDS = "UserInfoFields";
    public static final String DEFAULT_USER_IDENTIFIER = "id";

    public static final String CLIENT_ID = "ClientId";
    public static final String CLIENT_SECRET = "ClientSecret";
    public static final String FB_AUTHZ_URL = "AuthnEndpoint";
    public static final String FB_TOKEN_URL = "AuthTokenEndpoint";
    public static final String FB_USER_INFO_URL = "UserInfoEndpoint";
    public static final String FB_CALLBACK_URL = "callBackUrl";

    public static final String FB_ACCESS_TOKEN = "access_token";
    public static final String CLAIM_DIALECT_URI_PARAMETER = "ClaimDialectUri";
    public static final String PREFIE_CLAIM_DIALECT_URI_PARAMETER = "PrefixClaimDialectUri";
    public static final String FORWARD_SLASH = "/";

    public static final String ACCESS_TOKEN_PARAM = "accessToken";
    public static final String ID_TOKEN_PARAM = "idToken";
    public static final String SESSION_DATA_KEY_PARAM = "sessionDataKey";
    public static final String CLIENT_ID_PARAM = "clientId";
    public static final String REDIRECT_URL_SUFFIX = "_redirect_url";
    public static final String STATE_PARAM_SUFFIX = "_state_param";
    public static final String IS_API_BASED = "IS_API_BASED";
    public static final String REDIRECT_URL = "REDIRECT_URL";

    /**
     * Constants related to log management.
     */
    public static class LogConstants {

        public static final String OUTBOUND_AUTH_FACEBOOK_SERVICE = "outbound-auth-facebook";
        public static final String DIAGNOSTIC_LOG_KEY_NAME = "diagnosticLog";

        /**
         * Define action IDs for diagnostic logs.
         */
        public static class ActionIDs {

            public static final String PROCESS_AUTHENTICATION_RESPONSE = "process-outbound-auth-facebook-response";
            public static final String INITIATE_OUTBOUND_AUTH_REQUEST = "initiate-outbound-auth-facebook-request";
        }
    }

    private FacebookAuthenticatorConstants() {
    }
}
