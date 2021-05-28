require('dotenv').config();
const crypto = require('crypto'); // npm install crypto



// JWT 토큰생성 header.payload.signatue
function createToken(userid){
    let header = {
        "tpy":"JWT",
        "alg":"HS256"
    }
    let exp = new Date().getTime() + ((60 * 60 * 2) * 1000) // 2021년 5월 28일 28451680 1000
    let payload = {
        userid,
        exp
    }

    const encodingHeader = Buffer.from(JSON.stringify(header))
                                        .toString('base64')
                                        .replace('==','')
                                        .replace('=','')
    
    const encodingPayload = Buffer.from(JSON.stringify(payload))
                                        .toString('base64')
                                        .replace('==','')
                                        .replace('=','')

    const signature = crypto.createHmac('sha256',Buffer.from(process.env.salt))
                            .update(encodingHeader+"."+encodingPayload)
                            .digest('base64')
                            .replace('==','')
                            .replace('=','')
    
    let jwt = `${encodingHeader}.${encodingPayload}.${signature}`
    return jwt;
}

module.exports = createToken;