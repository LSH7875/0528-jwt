require('dotenv').config();
const crypto = require('crypto');

module.exports = (req,res,next) => {
    let {AccessToken} = req.cookies// 클라이언트의 cookie.accesstoken 
    if(AccessToken == undefined){
        res.redirect('/?msg=로그인을 진행해주세요.');
        return 0;
    }

    let [header,payload,sign] = AccessToken.split('.');
    let signature = getSignature(header,payload);

    if (sign == signature) {
        let {userid,exp} = JSON.parse(Buffer.from(payload,'base64').toString()) 
        let nexp = new Date().getTime();
        if(nexp > exp){
            //기간이 만료되었을때 처리영역
            //res.json({result:false,msg:'토큰만료'});
            res.clearCookie('AccessToken');
            res.redirect('/?msg=토큰만료');
        }

        //모든 검증이 완료됨.
        req.userid = userid;
        next();
    } else {
        res.redirect('/?msg=부적절한토큰');
    }
}


function getSignature(header,payload){
    const signature = crypto.createHmac('sha256',Buffer.from(process.env.salt))
                            .update(header+"."+payload)
                            .digest('base64')
                            .replace('==','')
                            .replace('=','')
    
    return signature;
}