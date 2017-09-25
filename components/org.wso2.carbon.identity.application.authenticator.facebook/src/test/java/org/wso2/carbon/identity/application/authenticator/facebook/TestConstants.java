package org.wso2.carbon.identity.application.authenticator.facebook;

public class TestConstants {

    public static final String facebookTokenEndpoint = "https://graph.facebook.com/oauth/access_token";
    public static final String callbackURL = "https://localhost:9443/commonauth";
    public static final String dummyClientId = "clientIDqwertyuio123456789zxcvbnm";
    public static final String dummyClientSecret = "clientSecretpoiuytrewqlkjhgfdsa09876543";
    public static final String dummyAuthCode = "code67890765432tyuio";
    public static final String REDIRECT_URI = "redirect_uri";
    public static final String queryParamSeparator = "&";
    public static final String queryParamStarter = "?";
    public static final String queryParamValueSeparator = "=";
    public static final String CLIENT_SECRET = "client_secret";
    public static final String CLIENT_ID = "client_id";
    public static final String dummyCommonAuthId = "1234567890";
    public static final String customUserInfoEndpoint = "https://facebook.custom.userinfo.com";
    public static final String customFacebookEndpoint = "https://facebook.custom.com";

    public static final String tokenResponse =
            "{\"access_token\":\"$token\"," +
                    "\"token_type\":\"bearer\",\"expires_in\":5183760}";

    public static final String userInfoResponse = "{\"first_name\":\"darshan\",\"last_name\":\"dlasname\"," +
            "\"gender\":\"male\",\"email\":\"testmail\\u0040hotmail.com\",\"id\":\"4567890987654\"}";
}
