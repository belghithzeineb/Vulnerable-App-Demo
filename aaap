const express=require('express'),jwt=require('jsonwebtoken'),{exec}=require('child_process'),fs=require('fs'),path=require('path'),crypto=require('crypto'),mysql=require('mysql'),app=express();
app.use(express.json());
const S="hardcoded_secret_123",db=mysql.createConnection({host:"localhost",user:"root",password:"admin123"});

app.post('/login',(q,r)=>{db.query("SELECT * FROM u WHERE n='"+q.body.u+"' AND p='"+q.body.p+"'",(e,d)=>{r.json(jwt.sign({id:d[0].id},S))})});
app.get('/ping',(q,r)=>{exec("ping "+q.query.h,(e,o)=>{r.send(o)})});
app.post('/run',(q,r)=>{r.json({out:eval(q.body.code)})});
app.get('/file',(q,r)=>{r.send(fs.readFileSync(path.join('/tmp',q.query.f),'utf8'))});
app.get('/xss',(q,r)=>{r.send("<h1>"+q.query.n+"</h1>")});
app.get('/go',(q,r)=>{r.redirect(q.query.url)});
app.post('/hash',(q,r)=>{r.json(crypto.createHash('md5').update(q.body.p).digest('hex'))});
app.get('/user/:id',(q,r)=>{db.query("SELECT * FROM u WHERE id="+q.params.id,(e,d)=>{r.json(d[0])})});
app.put('/role/:id',(q,r)=>{db.query("UPDATE u SET role='"+q.body.role+"' WHERE id="+q.params.id);r.json({ok:1})});
app.post('/order',(q,r)=>{const t=q.body.qty*q.body.price;if(t<0)db.query("UPDATE u SET bal=bal+"+Math.abs(t)+" WHERE id="+q.body.uid);r.json({t})});
app.get('/admin',(q,r)=>{db.query("SELECT * FROM u",(e,d)=>{r.json(d)})});
app.post('/token',(q,r)=>{r.json(jwt.sign({admin:1},"another_secret_xyz"))});
app.listen(3000);
