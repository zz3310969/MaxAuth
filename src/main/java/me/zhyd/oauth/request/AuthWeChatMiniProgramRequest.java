package me.zhyd.oauth.request;

import com.alibaba.fastjson.JSONObject;
import com.xkcoding.http.constants.Constants;
import com.xkcoding.http.support.HttpHeader;
import me.zhyd.oauth.cache.AuthStateCache;
import me.zhyd.oauth.config.AuthConfig;
import me.zhyd.oauth.config.AuthDefaultSource;
import me.zhyd.oauth.exception.AuthException;
import me.zhyd.oauth.model.AuthCallback;
import me.zhyd.oauth.model.AuthToken;
import me.zhyd.oauth.model.AuthUser;
import me.zhyd.oauth.utils.HttpUtils;
import me.zhyd.oauth.utils.StringUtils;
import me.zhyd.oauth.utils.UrlBuilder;

import java.util.HashMap;
import java.util.Map;

/**
 * 微信小程序登录
 *
 * @author zhengliangtian
 * @since 1.0.1
 */
public class AuthWeChatMiniProgramRequest extends AuthDefaultRequest {


    public AuthWeChatMiniProgramRequest(AuthConfig config) {
        super(config, AuthDefaultSource.WECHAT_MINI_PROGRAM);
    }


    @Override
    protected AuthToken getAccessToken(AuthCallback authCallback) {
        return AuthToken.builder().code(authCallback.getCode()).build();
    }


    private void checkResponse(JSONObject object) {
        if (object.containsKey("errcode")) {
            throw new AuthException(object.getIntValue("errcode"), object.getString("errmsg"));
        }
    }

    @Override
    protected String userInfoUrl(AuthToken authToken) {
        return UrlBuilder.fromBaseUrl(source.userInfo())
            .queryParam("appid", config.getClientId())
            .queryParam("secret", config.getClientSecret())

            .queryParam("js_code", authToken.getCode())
            .queryParam("grant_type", "authorization_code")
            .build();
    }

    /**
     * 请求参数
     * 属性	类型	必填	说明
     * appid	string	是	小程序 appId
     * secret	string	是	小程序 appSecret
     * js_code	string	是	登录时获取的 code，可通过wx.login获取
     * grant_type	string	是	授权类型，此处只需填写 authorization_code
     *
     * @param authToken token
     * @return AuthUser
     *
     * {
     * "openid":"xxxxxx",
     * "session_key":"xxxxx",
     * "unionid":"xxxxx",
     * "errcode":0,
     * "errmsg":"xxxxx"
     * }
     *
     *
     */
    @Override
    protected AuthUser getUserInfo(AuthToken authToken) {
        String response = new HttpUtils(config.getHttpConfig()).get(userInfoUrl(authToken)).getBody();
        JSONObject object = JSONObject.parseObject(response);
        this.checkResponse(object);
        if (object.containsKey("unionid")) {
            authToken.setUnionId(object.getString("unionid"));
        }
        return AuthUser.builder()
            .rawUserInfo(object).source(source.toString()).unionid(object.getString("unionid"))
            .uuid(object.getString("openid")).build();
    }


}
