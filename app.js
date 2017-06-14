var expiredTime = 1440;
var registration = require('./registrationObj');
bcrypt = require('bcrypt'),
SALT_WORK_FACTOR = 10;
var config = require('./config');
var express = require('express');
var mongoose = require('mongoose');
var inRange = require('./haversine');
var moment = require('moment');
var jwt = require('jsonwebtoken');
var data = require('./models/message');
var register = require('./models/register');
var User = require ('./models/user');
var bodyParser = require('body-parser');
var morgan = require('morgan');

var port = process.env.PORT || 3000;
var app = express();
var router = express.Router();
//var urlencodedParser = bodyParser.urlencoded({extended:false});
var jsonParser = bodyParser.json();
console.log(moment());
console.log('\n');

mongoose.connect(config.database);
console.log('Hey Ittay, the server is up and ready to serve');
router.use(bodyParser.urlencoded({ extended: false }));
router.use(bodyParser.json());

function createDocForMsg(newMessage,req){
    //create new message doc
    newMessage.Reference = req.body.name;    //the sender
    newMessage.phoneNumber = req.body.pn;
    newMessage.longitude = req.body.long;
    newMessage.latitude = req.body.lat;
    newMessage.range = req.body.range;
    newMessage.msg = req.body.msg;
    newMessage.pending = 1;

}

function createDocForUser(singleUser,req){
     singleUser.phoneNumber = req.body.pn;
    singleUser.email = req.body.email;
    singleUser.state = req.body.state;
    singleUser.city = req.body.city;
    singleUser.username = req.body.username;
    singleUser.password = req.body.password;
}

//encrypt the password
function createHashPassword(singleUser,callback){
    
   // registration.pre('save', function(next) {

    // only hash the password if it has been modified (or is new)
    if (!singleUser.isModified('password')) return next();

    // generate a salt
    bcrypt.genSalt(SALT_WORK_FACTOR, function(err, salt) {
        if (err) return err;

        // hash the password along with the new salt
        bcrypt.hash(singleUser.password, salt, function(err, hash) {
            if (err) return err;

            //save the salt that was used in the encryption
            // override the cleartext password with the hashed one
            callback(singleUser,hash,salt);
        });
    });

}

//comparing between the password that saved in the DB and the log-in password
function checkPass(user,logInPass,response,callback){
            bcrypt.hash(logInPass, user.salt, function(err, hash) {
            if (err) return next(err);
            callback(user.password,hash,response);
        });
}

app.use('/assets' , express.static(__dirname + '/public')); 
app.set('view engine' , 'ejs');

//*admin
router.get('/admin/deleteall',function(req,res){
    data.remove({},function(){});
    register.remove({},function(){});
    User.remove({},function(){}); 
   res.send('deletion succeded!');
});

router.get('/admin/showMsgData',function(req,res){
    data.find({},function(err,allData){
        if (err) throw err;
        res.json(allData);
                 

    });
});

router.get('/admin/showRegData',function(req,res){
        register.find({},function(err,allRegisters){
            if (err) throw err;
            res.json(allRegisters);
        });
});

router.get('/admin/userData',function(req,res){
        User.find({},function(err,allUsers){
            if (err) throw err;
            res.json(allUsers);
        });
});
//register a user into the service
router.post('/registration',jsonParser,function(req,res){
  var singleUser = new register();
  createDocForUser(singleUser,req);
  createHashPassword(singleUser,function(user,password,salt){
    user.salt = salt; 
    user.password = password;
    user.save(function(err){
        if (err) throw err;
    });
  });
  //return the _id of the doc that was created for the user
  res.json({status:true , _id : singleUser._id}); 
  //res.send('Registration succeeded');
  
});


//authentication
router.post('/auth' ,jsonParser, function(req,res){
    register.findOne({email: req.body.email} , function(err,regUser){
        if(err) throw err;
        else if(!regUser){
            //user is not exist
            res.json({success : false , message : 'Authentication failed. email not found.', getName : req.query.email});
        } 
        else {
            checkPass(regUser,req.body.password,res,function(originalHashedPass,logInHashedPass,res){
                if(originalHashedPass != logInHashedPass){
                    //wrong password
                    res.json({success : false , message : 'Authentication failed, wrong password.'}); 
                }   else{
                        var token = jwt.sign(regUser,regUser.email,{expiresIn : expiredTime});
                        // return the token that was created
                        res.json({success : true , 
                                message : 'a new token',
                                token : token});
                    }
            });
        }
    });
});


//middleware - checks if there is a valid token before processing a request
router.use(function(req,res,next){

    var token = req.body.token || req.query.token || req.headers['x-access-token'];
    if (!token)
        res.status(403).json({ success: false, message: 'No token provided.' }); 
    else
        jwt.verify(token,req.query.email,function(err,decoded){
            if(err) {
                res.status(403).json({ success: false, message: 'Failed to authenticate token.' }); 
            
        }
            else{
                req.decoded = decoded;
                next(); 
            } 
        });
});

//*sender api 

//from here on only logged users will be able to use the api 
router.post('/sender/sendMessage',jsonParser , function(req , res){
   var newMessage =new data();

    createDocForMsg(newMessage, req);
    newMessage.save(function(err){
        if (err) throw err;
    });
    //test outcome
    res.json({status:true,newMessage});
    //**add notification that a message is pending */
});

//show all sent messages
router.get('/sender/getAllMsgs',function(req,res){
    data.find({Reference : req.query.username},function(err,doc){
        if(err) throw err;
        res.json(doc);
    });
});

//show all sent messages that didnt open yet **really necessary?
router.get('/sender/getAllPendingMsgs',function(req,res){
    data.find({Reference : req.query.username, pending : 1},function(err,doc){
        if(err) throw err;
        res.json(doc);
    });
});

//delete message that was sent and is still pending
//**should send a notification ?
router.get('/sender/abortPendingMsg',function(req,res){
    data.remove({_id : req.query._id},function(err){
        if(err) throw err;
        res.json({status : true , message : 'the message was deleted'});
    });
});

//*receiver api

//show all received messages
router.get('/receiver/showAllMsgs',function(req,res){
        register.find({_id : req.query._id},function(err,userDoc){
            if(err) throw err;
            data.find({phoneNumber : userDoc[0].phoneNumber}, function(err,msgDoc){
                if(err) throw err;
                res.json({status : true, msgDoc});
            });
        });
    });



//delete all received messages
router.get('/receiver/deleteMessage',function(req,res){
    data.remove({_id : req.query._id}, function(err){
        if (err) throw err;
    });
    res.json({status: true , message: 'deletion succeeded'});
});

/*router.get('/receiver/blackList/addToBlackList',function(req,res){
    register.find({_id : req.query._id},function(err,userInfo){
        if(err) throw err;
        userInfo.blackList.push(req.query.blockThisNumber);
    });
});

router.get('/receiver/blackList/removeFromBlackList',function(req,res){
    register.find({_id : req.query._id},function(err,userInfo){
        if(err) throw err;
        while (list.next()) {
            if(list.current() == req.query.removeThisNumber);
                userInfo.blackList.removeCurrent();
        }
    });
});*/
//checks whether the user is in range  
router.get('/receiver/inRange',function(req,res){
    //find the user by its _id 
   register.find({_id : req.query._id}, function(err,user){
       if(err) throw err;
       //find all the msgs that were'nt open yet
       data.find({phoneNumber : user[0].phoneNumber , pending : 1}, function(err,completeData){
            if(err) throw err;
            //scan those msgs 
            completeData.forEach(function(info){
                //the user is inside the range that was define for the msg
                 if(inRange(req.query.long,req.query.lat,info.long,info.lat, info.range)){
                     //update that the msg was opened and send it
                    data.findOneAndUpdate({_id : info._id}, {$set:{pending:0}},{new : true},
                    function(err,doc){
                        if(err) throw err;
                        res.json({status: true, Reference: doc.Reference , Message : doc.msg, msgId : info._id});
                        //TODO ***send a notification that the message was opened***
                    });   
            }
        });
    });
  });
});


app.use('/', router);

     

app.listen(port);


/*=============================================================================
test using get method

  router.get('/registration',function(req,res){
  var singleUser = new register({
      phoneNumber: 0,
      email:'',
      state:'',
      city:'',
      username:'',
      password:'',
      salt: 0
  });
  createDocForUser(singleUser,req);
  createHashPassword(singleUser,function(user,password,salt){
    user.salt = salt; 
    user.password = password;
    user.save(function(err){
        if (err) throw err;
    });
  });
  //return the _id of the doc that was created for the user
  res.json({status:true , _id : singleUser._id}); 
  //res.send('Registration succeeded');
  
});


/*router.get('/auth' , function(req,res){
    register.findOne({email: req.query.email} , function(err,regUser){
        if(err) throw err;
        else if(!regUser){
            //user is not exist
            res.json({success : false , message : 'Authentication failed. email not found.', getName : req.query.email});
        } 
        else {
            checkPass(regUser,req.query.password,res,function(originalHashedPass,logInHashedPass,res){
                if(originalHashedPass != logInHashedPass){
                    //wrong password
                    res.json({success : false , message : 'Authentication failed, wrong password.'}); 
                }   else{
                        var token = jwt.sign(regUser,regUser.email,{expiresIn : expiredTime});
                        // return the token that was created
                        res.json({success : true , 
                                message : 'a new token',
                                token : token});
                    }
            });
        }
    });
});


router.get('/sender/sendMessage' , function(req , res){
   var newMessage =new data({
    Reference : '',
    phoneNumber: 0,
    longitude: 0,
    latitude: 0,
    range: 0,
    msg:'',
    pending: 0
    });

    createDocForMsg(newMessage, req);
    newMessage.save(function(err){
        if (err) throw err;
    });
    res.json({status:true,newMessage});
});*/

