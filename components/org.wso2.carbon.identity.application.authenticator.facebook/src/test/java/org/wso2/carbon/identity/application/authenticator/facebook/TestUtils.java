package org.wso2.carbon.identity.application.authenticator.facebook;

import java.net.URLEncoder;
import java.util.HashMap;
import java.util.Map;

public class TestUtils {

    public static String getTokenRequestUrl() {
        Map<String, String> parameters = new HashMap<>();
        parameters.put(FacebookAuthenticatorConstants.OAUTH2_GRANT_TYPE_CODE, TestConstants.dummyAuthCode);
        parameters.put(TestConstants.CLIENT_SECRET, TestConstants.dummyClientSecret);
        parameters.put(TestConstants.REDIRECT_URI, TestConstants.callbackURL);
        parameters.put(TestConstants.CLIENT_ID, TestConstants.dummyClientId);
        return buildQueryString(TestConstants.facebookTokenEndpoint, parameters);
    }

    public static String buildQueryString(String baseURL, Map<String, String> parameters) {
        StringBuilder stringBuilder = new StringBuilder(baseURL).append(TestConstants.queryParamStarter);
        String url;

        for (Map.Entry<String, String> entry : parameters.entrySet()) {
            stringBuilder.append(URLEncoder.encode(entry.getKey())).append(TestConstants.queryParamValueSeparator).append
                    (URLEncoder.encode(entry.getValue())).append
                    (TestConstants.queryParamSeparator);
        }
        url = stringBuilder.toString();
        return url.substring(0, url.length() - 1);
    }

    public static String buildRedirectURL(String baseURL, String scope, String responseType, String redirectURI, String
            state, String clientID) {

        Map<String, String> map = new HashMap<>();
        map.put("scope", scope);
        map.put("response_type", responseType);
        map.put("redirect_uri", redirectURI);
        map.put("state", state);
        map.put("client_id", clientID);
        return buildQueryString(baseURL, map);
    }
}
