/*
 * Copyright (c) 2014, WSO2 Inc. (http://www.wso2.org) All Rights Reserved.
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

public class FacebookAuthenticatorConstants {

    public static final String AUTHENTICATOR_NAME = "FacebookAuthenticator";
    public static final String FACEBOOK_LOGIN_TYPE = "facebook";

    public static final String OAUTH2_GRANT_TYPE_CODE = "code";
    public static final String OAUTH2_PARAM_STATE = "state";
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

    public static final String CLAIM_DIALECT_URI = "http://wso2.org/facebook/claims";

    static final class FacebookPermissions {

        // Facebook user_profile (Default) permissions
        public static final String ID           = "id";
        public static final String COVER        = "cover";
        public static final String NAME         = "name";
        public static final String FIRST_NAME   = "first_name";
        public static final String LAST_NAME    = "last_name";
        public static final String AGE_RANGE    = "age_range";
        public static final String LINK         = "link";
        public static final String GENDER       = "gender";
        public static final String LOCALE       = "locale";
        public static final String PICTURE      = "picture";
        public static final String TIMEZONE     = "timezone";
        public static final String UPDATED_TIME = "updated_time";
        public static final String VERIFIED     = "verified";

        public static final String USER_FRIENDS                     = "user_friends";
        public static final String EMAIL                            = "email";
        public static final String USER_ABOUT_ME                    = "user_about_me";
        public static final String USER_ACTIONS_BOOKS               = "user_actions.books";
        public static final String USER_ACTIONS_FITNESS             = "user_actions.fitness";
        public static final String USER_ACTIONS_MUSIC               = "user_actions.music";
        public static final String USER_ACTIONS_NEWS                = "user_actions.news";
        public static final String USER_ACTIONS_VIDEO               = "user_actions.video";
        public static final String USER_ACTIONS_APP_NAMESPACE       = "user_actions:";
        public static final String USER_BIRTHDAY                    = "user_birthday";
        public static final String USER_EDUCATION_HISTORY           = "user_education_history";
        public static final String USER_EVENTS                      = "user_events";
        public static final String USER_GAMES_ACTIVITY              = "user_games_activity";
        public static final String USER_HOMETOWN                    = "user_hometown";
        public static final String USER_LIKES                       = "user_likes";
        public static final String USER_LOCATION                    = "user_location";
        public static final String USER_MANAGED_GROUPS              = "user_managed_groups";
        public static final String USER_PHOTOS                      = "user_photos";
        public static final String USER_POSTS                       = "user_posts";
        public static final String USER_RELATIONSHIPS               = "user_relationships";
        public static final String USER_RELATIONSHIP_DETAILS        = "user_relationship_details";
        public static final String USER_RELIGION_POLITICS           = "user_religion_politics";
        public static final String USER_TAGGED_PLACES               = "user_tagged_places";
        public static final String USER_VIDEOS                      = "user_videos";
        public static final String USER_WEBSITE                     = "user_website";
        public static final String USER_WORK_HISTORY                = "user_work_history";
        public static final String READ_CUSTOM_FRIENDLISTS          = "read_custom_friendlists";
        public static final String READ_INSIGHTS                    = "read_insights";
        public static final String READ_AUDIENCE_NETWORK_INSIGHTS   = "read_audience_network_insights";
        public static final String READ_PAGE_MAILBOX                = "read_page_mailboxes";
        public static final String MANAGE_PAGES                     = "manage_pages";
        public static final String PUBLISH_PAGES                    = "publish_pages";
        public static final String PUBLISH_ACTIONS                  = "publish_actions";
        public static final String RSVP_EVENTS                      = "rsvp_event";
        public static final String PAGES_SHOW_LIST                  = "pages_show_list";
        public static final String PAGES_MANAGE_CTA                 = "pages_manage_cta";
        public static final String PAGES_MANAGE_INSTANT_ARTICLES    = "pages_manage_instant_articles";
        public static final String ADS_READ                         = "ads_read";
        public static final String ADS_MANAGEMENT                   = "ads_management";
        public static final String BUSINESS_MANAGEMENT              = "business_management";
        public static final String PAGES_MESSAGING                  = "pages_messaging";
        public static final String PAGES_MESSAGING_SUBSCRIPTIONS    = "pages_messaging_subscriptions";
        public static final String PAGES_MESSAGING_PAYMENTS         = "pages_messaging_payments";
        public static final String PAGES_MESSAGING_PHONE_NUMBER     = "pages_messaging_phone_number";

    }

    private FacebookAuthenticatorConstants() {
    }
}