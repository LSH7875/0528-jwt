const crypto = require('crypto');


function createtoken(){
    let header = {
        "alg": "HS256",
        "typ": "JWT"
    }
    let encodeheader = Buffer.from(JSON.stringify(header)) // string 
                            .toString('base64')
                            .replace('=',''); // 안녕하세요-> 바이너리 데이터바꿈(16진수)

    let payload = {
        "sub": "1234567890", // 각각 속성의 어떤값이 들어가는지 
        "name": "John Doe",
        "user":"web7722",
        "userid":123,
        "iat": 1516239022
    }
    let encodepayload = Buffer.from(JSON.stringify(payload))
                                        .toString('base64')
                                        .replace('==','');
    //1.어떤암호화를 할거냐 (sha256) // 블록체인
    //2.암호화 규칙 스트링으로 적습니다.
    let signature = crypto.createHmac('sha256',Buffer.from('ingoo'))
                    .update(`${encodeheader}.${encodepayload}`) // header.payload
                    .digest('base64')
                    .replace('=','')



    return `${encodeheader}.${encodepayload}.${signature}`;
}

module.exports = createtoken; 