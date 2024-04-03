package me.zhyd.oauth.request;

import com.alibaba.fastjson.JSON;
import com.alibaba.fastjson.JSONObject;
import com.alipay.api.AlipayApiException;
import com.alipay.api.AlipayClient;
import com.alipay.api.DefaultAlipayClient;
import com.alipay.api.request.AlipaySystemOauthTokenRequest;
import com.alipay.api.request.AlipayUserInfoShareRequest;
import com.alipay.api.response.AlipaySystemOauthTokenResponse;
import com.alipay.api.response.AlipayUserInfoShareResponse;
import com.xkcoding.http.constants.Constants;
import com.xkcoding.http.support.HttpHeader;
import me.zhyd.oauth.cache.AuthCache;
import me.zhyd.oauth.cache.AuthStateCache;
import me.zhyd.oauth.config.AuthConfig;
import me.zhyd.oauth.config.AuthDefaultSource;
import me.zhyd.oauth.config.AuthSource;
import me.zhyd.oauth.enums.AuthResponseStatus;
import me.zhyd.oauth.enums.AuthUserGender;
import me.zhyd.oauth.exception.AuthException;
import me.zhyd.oauth.model.AuthCallback;
import me.zhyd.oauth.model.AuthResponse;
import me.zhyd.oauth.model.AuthToken;
import me.zhyd.oauth.model.AuthUser;
import me.zhyd.oauth.utils.*;

import java.net.InetSocketAddress;
import java.util.HashMap;
import java.util.Map;

import static me.zhyd.oauth.utils.GlobalAuthUtils.generateTwitterSignature;

/**
 * 微信小程序登录
 *
 * @author zhengliangtian
 * @since 1.0.1
 */
public class AuthWeChatMiniProgramMobileRequest extends AuthDefaultRequest {


    public AuthWeChatMiniProgramMobileRequest(AuthConfig config, AuthStateCache authStateCache) {
        super(config, AuthDefaultSource.WECHAT_MINI_PROGRAM_MOBILE, authStateCache);
    }


    @Override
    protected AuthToken getAccessToken(AuthCallback authCallback) {
        return this.getToken(accessTokenUrl(authCallback.getMobile_code()), authCallback.getMobile_code());
    }

    @Override
    protected String accessTokenUrl(String code) {
        return UrlBuilder.fromBaseUrl(source.accessToken())
            .queryParam("appid", config.getClientId())
            .queryParam("secret", config.getClientSecret())
            .queryParam("grant_type", "client_credential")
            .build();
    }

    private String getKey() {
        return "wechat_mini_" + config.getClientId();
    }

    private AuthToken getToken(String accessTokenUrl, String code) {

        AuthStateCache stateCache = super.authStateCache;

        String token = stateCache.get(getKey());
        if (StringUtils.isNotEmpty(token)) {
            return AuthToken.builder().accessToken(token).code(code).build();
        }


        String response = new HttpUtils(config.getHttpConfig()).get(accessTokenUrl).getBody();
        JSONObject accessTokenObject = JSONObject.parseObject(response);

        this.checkResponse(accessTokenObject);

        AuthToken authToken = AuthToken.builder()
            .accessToken(accessTokenObject.getString("access_token"))
            .expireIn(accessTokenObject.getIntValue("expires_in")).code(code)
            .build();
        stateCache.cache(getKey(), authToken.getAccessToken(), authToken.getExpireIn() - 60);
        return authToken;
    }

    private void checkResponse(JSONObject object) {
        if (object.containsKey("errcode") && object.getIntValue("errcode") != 0) {
            throw new AuthException(object.getIntValue("errcode"), object.getString("errmsg"));
        }
    }

    /**
     * {
     * "errcode":0,
     * "errmsg":"ok",
     * "phone_info": {
     * "phoneNumber":"xxxxxx",
     * "purePhoneNumber": "xxxxxx",
     * "countryCode": 86,
     * "watermark": {
     * "timestamp": 1637744274,
     * "appid": "xxxx"
     * }
     * }
     * }
     *
     * @param authToken token
     * @return AuthUser
     */
    @Override
    protected AuthUser getUserInfo(AuthToken authToken) {
        String code = authToken.getCode();
        Map<String, String> oauthParams = buildOauthParams();
        oauthParams.put("code", code);
        HttpHeader httpHeader = new HttpHeader();
        httpHeader.add(Constants.CONTENT_TYPE, "application/json");
        String userUrl = source.userInfo() + authToken.getAccessToken();
        String response = new HttpUtils(config.getHttpConfig()).post(userUrl, JSON.toJSONString(oauthParams), httpHeader).getBody();
        JSONObject object = JSONObject.parseObject(response);
        this.checkResponse(object);
        JSONObject phone_info = object.getJSONObject("phone_info");
        return AuthUser.builder()
            .rawUserInfo(object)
            .phoneNumber(phone_info.getString("phoneNumber")).source(source.toString())
            .countryCode(phone_info.getString("countryCode")).build();
    }

    private Map<String, String> buildOauthParams() {
        Map<String, String> params = new HashMap<>(2);

        return params;
    }
}
