const express = require('express');
const cookieParser = require('cookie-parser'); //npm install cookie-parser
const bodyParser = require('body-parser'); // npm install body-parser
const token = require('./createtoken'); // 외부 js파일 가져오기
const app = express();
const nunjucks = require('nunjucks');
const ctoken = require('./jwt');
const auth = require('./middleware/auth');

app.set('view engine','html');
nunjucks.configure('views',{
    express:app,
})

app.use(bodyParser.json())
app.use(bodyParser.urlencoded({extended:false,}))
app.use(cookieParser());
app.use(express.static('public'));

app.get('/',(req,res)=>{ // main페이지
    let {msg} = req.query;             
    res.render('index')
  
});

app.get('/user/info',auth,(req,res)=>{
    res.send(`Hello ${req.userid}`);
})

app.get('/menu1',(req,res)=>{ //sub 페이지 
    res.send('menu1페이지입니다.');
})

//POST auth/local/login
app.post('/auth/local/login',(req,res)=>{
    let {userid,userpw} = req.body;
    let result = {};
    // DB 접속후 결과 Return 
    if(userid=='root' && userpw=='root'){
        // 로그인 성공
        result = {
            result:true,
            msg:'로그인에 성공하셨습니다.'
        }

        let token = ctoken(userid);
        res.cookie('AccessToken',token,{httpOnly:true,secure:true,})

        //token 내용을 
    } else {
        // 로그인 실패
        result = {
            result:false,
            msg:'아이디와 패스워드를 확인해주세요.'
        }
    }
    res.json(result)
})


app.get('/login',(req,res)=>{
    let {id,pw} = req.query; 

    if(id=='root' && pw=='root'){
        // 토큰 생성
        let ctoken = token();
        res.cookie('token',ctoken,{httpOnly:true,secure:true,});
        res.redirect('/?msg=로그인성공');
    } else {
        // 토큰 실패
        res.redirect('/?msg=로그인실패');
    }

})

app.listen(3000,()=>{
    console.log('server start port 3000!');
});