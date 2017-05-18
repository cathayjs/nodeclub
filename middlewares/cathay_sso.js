const request = require('request');
var Models = require('../models');
var User = Models.User;
var uuid = require('node-uuid');
var authMiddleWare = require('../middlewares/auth');
var config = require('../config');

const HOST_NAME = 'http://emp.cathay-ins.com.cn:8003';
const URL_REDIRECT_SSO_LOGIN = `${HOST_NAME}/sso/login?callback=http://club.cathay-ins.com.cn:3000`;


function relayCaToken(caToken, callback) {

    request({
        url: `${HOST_NAME}/api/sso/caToken/${caToken}`,
        method: 'PUT',
        json: true
    }, function (err, data, json) {

        console.log('request callback');

        console.log(err, json);

        callback(err, json);

    });

}


// 验证用户是否登录
module.exports = function (req, res, next) {


    let caToken = req.cookies['caToken'];


    // SSO没有登陆
    if (!caToken) {
        res.redirect(URL_REDIRECT_SSO_LOGIN);
        console.log('sso not login')
        return;
    }

    function getName(ssoUser) {

        return ssoUser.nickName || (ssoUser.name + '_' + ssoUser.ID);

    }

    relayCaToken(caToken, function (err, result) {

        // sso是否登陆
        if (result) {

            let userInfo = result.userInfo;

            // 判断用户是否存在
            User.findOne({loginname: getName(userInfo)}, function (err, user) {

                // 不存在，则创建用户
                if (!user) {
                    console.log('用户不存在，开始创建');
                    createUser(userInfo);
                } else {
                    console.log('用户存在', user);
                    // 用户存在，则检查cookie
                    var auth_token = req.signedCookies[config.auth_cookie_name];

                    // session过期，重新生成session, 刷新页面
                    if (!auth_token) {
                        authMiddleWare.gen_session(user, res);
                        res.redirect('/');
                        return;
                    }
                    req.session.user = user;

                    next();
                }

            });
        } else {

            // sso登陆过期
            res.redirect(URL_REDIRECT_SSO_LOGIN);
            console.log('sso timeout');
            return;
        }


    });

    function createUser(ssoUser) {
        var user = new User({
            loginname: getName(ssoUser),
            pass: 'Cathay1234Random',
            email: ssoUser.email,
            active: true,
            accessToken: uuid.v4(),
        });

        user.save(function (err) {

            console.log(err);

            if (err) {
                console.log('创建用户失败', err);
                // 根据 err.err 的错误信息决定如何回应用户，这个地方写得很难看
                if (err.message.indexOf('duplicate key error') !== -1) {
                    if (err.message.indexOf('email') !== -1) {
                        return res.status(500)
                            .send('关联失败，邮箱重复');
                    }
                    if (err.message.indexOf('loginname') !== -1) {
                        return res.status(500)
                            .send('关联失败，账号重复');
                    }
                }
                return next(err);
                // END 根据 err.err 的错误信息决定如何回应用户，这个地方写得很难看
            }

            console.log('创建用户成功');

            authMiddleWare.gen_session(user, res);
            res.redirect('/');

            return;
        });
    }


};


/********

 下午研究改造集成了我们公司的单点登陆，加了一个 middleware，feature:

 * 如果未登陆，自动302跳转SSO LOGIN页面
 * SSO LOGIN登陆成功后，创建caToken, 跳转回来
 * 如果有caToken，但caToken对应的用户在nodeclub中不存在，则自动创建用户，自动创建session，并登陆
 * 如果有caToken，且caToken对应的用户在nodeclub中存在，但nodeclub session不存在，自动创建session，并登陆
 * 如果有caToken，且caToken对应的用户在nodeclub中存在，但nodeclub session存在，直接登陆

 *********/