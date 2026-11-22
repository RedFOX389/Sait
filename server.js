// RedWeb backend — Node.js 18+. Registration: nickname + email + password; no email verification.
const express=require('express'),session=require('express-session'),PgSession=require('connect-pg-simple')(session);
const {Pool}=require('pg'),bcrypt=require('bcryptjs'),path=require('path'),rateLimit=require('express-rate-limit'),helmet=require('helmet');
const app=express(),PORT=Number(process.env.PORT||3000),isProduction=process.env.NODE_ENV==='production';
if(!process.env.DATABASE_URL){console.error('Missing DATABASE_URL. Configure PostgreSQL.');process.exit(1)}
if(!process.env.SESSION_SECRET||process.env.SESSION_SECRET.length<32){console.error('SESSION_SECRET must be at least 32 characters.');process.exit(1)}
const pool=new Pool({connectionString:process.env.DATABASE_URL,ssl:process.env.DATABASE_SSL==='false'?false:{rejectUnauthorized:false},max:5,idleTimeoutMillis:30000,connectionTimeoutMillis:10000});
async function initDatabase(){
 await pool.query(`CREATE TABLE IF NOT EXISTS redweb_users(email TEXT PRIMARY KEY,password_hash TEXT NOT NULL,name VARCHAR(24) NOT NULL,avatar TEXT,header_blur INTEGER NOT NULL DEFAULT 12,bio TEXT NOT NULL DEFAULT '',language VARCHAR(8) NOT NULL DEFAULT 'ru',created_at TIMESTAMPTZ NOT NULL DEFAULT NOW())`);
 await pool.query("ALTER TABLE redweb_users ADD COLUMN IF NOT EXISTS bio TEXT NOT NULL DEFAULT ''");
 await pool.query("ALTER TABLE redweb_users ADD COLUMN IF NOT EXISTS language VARCHAR(8) NOT NULL DEFAULT 'ru'");
 await pool.query("ALTER TABLE redweb_users ADD COLUMN IF NOT EXISTS header_blur INTEGER NOT NULL DEFAULT 12");
}
app.set('trust proxy',1);app.use(helmet({contentSecurityPolicy:false}));app.use(express.json({limit:'2mb'}));
app.use(session({store:new PgSession({pool,tableName:'redweb_sessions',createTableIfMissing:true}),secret:process.env.SESSION_SECRET,resave:false,saveUninitialized:false,cookie:{httpOnly:true,sameSite:'lax',secure:isProduction,maxAge:30*24*60*60*1000}}));
app.use('/api/',rateLimit({windowMs:15*60*1000,max:60,standardHeaders:true,legacyHeaders:false}));
const cleanEmail=v=>String(v||'').trim().toLowerCase();
const publicUser=u=>({name:u.name,email:u.email,avatar:u.avatar||null,headerBlur:u.header_blur??12,bio:u.bio||'',language:u.language||'ru'});
function requireAuth(req,res,next){if(!req.session.userEmail)return res.status(401).json({message:'Сначала войди в аккаунт.'});next()}
app.get('/healthz',(_req,res)=>res.json({ok:true}));
app.post('/api/register',async(req,res)=>{
 try{
  const name=String(req.body.name||'').trim(),email=cleanEmail(req.body.email),password=String(req.body.password||'');
  if(name.length<2||name.length>24)return res.status(400).json({message:'Никнейм должен содержать от 2 до 24 символов.'});
  if(!/^[^\s@]+@[^\s@]+\.[^\s@]+$/.test(email))return res.status(400).json({message:'Введи корректный адрес почты.'});
  if(password.length<8)return res.status(400).json({message:'Пароль должен быть не короче 8 символов.'});
  const hash=await bcrypt.hash(password,12);
  const result=await pool.query(`INSERT INTO redweb_users(email,password_hash,name) VALUES($1,$2,$3) ON CONFLICT(email) DO NOTHING RETURNING email,name,avatar,header_blur,bio,language`,[email,hash,name]);
  if(!result.rowCount)return res.status(409).json({message:'Этот email уже зарегистрирован. Попробуй войти.'});
  req.session.userEmail=email;res.json({user:publicUser(result.rows[0])});
 }catch(e){console.error('Registration error:',e);res.status(500).json({message:'Не удалось создать аккаунт. Проверь сервер и базу данных.'})}
});
app.post('/api/login',async(req,res)=>{
 try{
  const email=cleanEmail(req.body.email),password=String(req.body.password||'');
  const result=await pool.query('SELECT email,password_hash,name,avatar,header_blur,bio,language FROM redweb_users WHERE email=$1',[email]),u=result.rows[0];
  if(!u||!(await bcrypt.compare(password,u.password_hash)))return res.status(401).json({message:'Неверная почта или пароль.'});
  req.session.userEmail=email;res.json({user:publicUser(u)});
 }catch(e){console.error('Login error:',e);res.status(500).json({message:'Не удалось выполнить вход. Попробуй позже.'})}
});
app.get('/api/me',requireAuth,async(req,res)=>{
 try{const r=await pool.query('SELECT email,name,avatar,header_blur,bio,language FROM redweb_users WHERE email=$1',[req.session.userEmail]);
  if(!r.rowCount)return req.session.destroy(()=>res.status(401).json({message:'Аккаунт не найден.'}));res.json({user:publicUser(r.rows[0])});
 }catch(e){console.error(e);res.status(500).json({message:'Не удалось загрузить аккаунт.'})}
});
app.put('/api/profile',requireAuth,async(req,res)=>{
 try{
  const name=String(req.body.name||'').trim(),bio=String(req.body.bio||'').trim().slice(0,160),language=req.body.language==='en'?'en':'ru',blur=Number(req.body.headerBlur),avatar=req.body.avatar??null;
  if(name.length<2||name.length>24)return res.status(400).json({message:'Никнейм должен быть длиной от 2 до 24 символов.'});
  if(!Number.isInteger(blur)||blur<0||blur>24)return res.status(400).json({message:'Размытие должно быть от 0 до 24.'});
  if(avatar!==null&&(!/^data:image\/(png|jpeg|webp|gif);base64,/.test(avatar)||avatar.length>1500000))return res.status(400).json({message:'Недопустимая аватарка или слишком большой файл.'});
  const r=await pool.query(`UPDATE redweb_users SET name=$1,avatar=$2,header_blur=$3,bio=$4,language=$5 WHERE email=$6 RETURNING email,name,avatar,header_blur,bio,language`,[name,avatar,blur,bio,language,req.session.userEmail]);
  if(!r.rowCount)return res.status(404).json({message:'Аккаунт не найден.'});res.json({user:publicUser(r.rows[0])});
 }catch(e){console.error(e);res.status(500).json({message:'Не удалось сохранить настройки.'})}
});
app.post('/api/logout',(req,res)=>req.session.destroy(e=>{if(e)return res.status(500).json({message:'Не удалось выйти из аккаунта.'});res.clearCookie('connect.sid');res.json({ok:true})}));
app.use(express.static(__dirname));app.get('/',(_req,res)=>res.sendFile(path.join(__dirname,'RedWeb.html')));
initDatabase().then(()=>app.listen(PORT,()=>console.log(`RedWeb is running on port ${PORT}`))).catch(e=>{console.error('Database initialization failed:',e);process.exit(1)});
