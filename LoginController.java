package com.sany.fir.admin.shiro.controller;

import com.google.code.kaptcha.Producer;
import com.sany.fir.admin.common.annotation.SysLog;
import com.sany.fir.admin.common.utils.R;
import com.sany.fir.admin.shiro.service.LoginService;
import com.sany.fir.admin.shiro.service.UserService;
import com.sany.fir.sdk.utils.Constants;
import com.sany.fir.admin.shiro.utils.ShiroUtils;
import com.sany.fir.sdk.user.UserSession;
import com.sany.fir.sdk.utils.HttpContextUtils;
import org.apache.commons.lang.StringUtils;
import org.apache.shiro.SecurityUtils;
import org.apache.shiro.authc.*;
import org.apache.shiro.crypto.hash.Sha256Hash;
import org.apache.shiro.subject.Subject;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.stereotype.Controller;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RequestMethod;
import org.springframework.web.bind.annotation.ResponseBody;
import javax.imageio.ImageIO;
import javax.servlet.ServletException;
import javax.servlet.ServletOutputStream;
import javax.servlet.http.Cookie;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;
import java.awt.image.BufferedImage;
import java.io.IOException;

/**
 * Created by sufeng on 2017/06/26 0026.３３３
 */
@Controller
@RequestMapping("sso")
public class LoginController {
    private static final Logger log = LoggerFactory.getLogger(LoginController.class);

    @Autowired
    private Producer producer;
    @Autowired
    private LoginService loginService;
    @Autowired
    private UserService userService;

    @RequestMapping("captcha.jpg")
    public void captcha(HttpServletResponse response) throws ServletException, IOException {
        response.setHeader("Cache-Control", "no-store, no-cache");
        response.setContentType("image/jpeg");

        //生成文字验证码
        String text = producer.createText();
        //生成图片验证码
        BufferedImage image = producer.createImage(text);
        //保存到shiro session
        ShiroUtils.setSessionAttribute(com.google.code.kaptcha.Constants.KAPTCHA_SESSION_KEY, text);

        ServletOutputStream out = response.getOutputStream();
        ImageIO.write(image, "jpg", out);
    }

    /**
     * 登录
     */
    @ResponseBody
    @RequestMapping(value = "login", method = RequestMethod.POST)
    public R login(String username, String password, String captcha, HttpServletResponse response) throws IOException {
        String kaptcha = ShiroUtils.getKaptcha(com.google.code.kaptcha.Constants.KAPTCHA_SESSION_KEY);
        if (!captcha.equalsIgnoreCase(kaptcha)) {
            return R.error("验证码不正确");
        }

        try {
            Subject subject = ShiroUtils.getSubject();
            //sha256加密
            password = new Sha256Hash(password).toHex();
            UsernamePasswordToken token = new UsernamePasswordToken(username, password);
            subject.login(token);
        } catch (UnknownAccountException e) {
            log.error("UnknownAccountException:",e);
            return R.error(e.getMessage());
        } catch (IncorrectCredentialsException e) {
            log.error("IncorrectCredentialsException:",e);
            return R.error(e.getMessage());
        } catch (LockedAccountException e) {
            log.error("LockedAccountException:",e);
            return R.error(e.getMessage());
        } catch (AuthenticationException e) {
            log.error("AuthenticationException:",e);
            return R.error(e.getMessage());
        }

        return R.ok();
    }

    /**
     * 退出
     */
    @RequestMapping(value = "logout", method = RequestMethod.GET)
    public String logout() {
        ShiroUtils.logout();
        return "redirect:/login.html";
    }

    /**
     * 修改登录用户密码
     */
    @RequestMapping(value = "changePassword", method = RequestMethod.POST)
    @ResponseBody
    public R changePassword(HttpServletResponse response, String password, String newPassword) {
        if (StringUtils.isBlank(password)) return R.error("旧密码不为能空");
        if (StringUtils.isBlank(newPassword)) return R.error("新密码不为能空");
        UserSession userSession = ShiroUtils.getUserSession();
        //更新密码
        int count = loginService.updatePassword(userSession.getUserId(), password, newPassword);
        if (count == 0) {
            return R.error("原密码不正确");
        }
        //退出
        ShiroUtils.logout();
        return R.ok();
    }
}
