var mongoose = require('mongoose');
var Schema = mongoose.Schema;
var linkedList = require('linkedlist');
var list = new linkedList();


var registerInformation = new Schema({
    phoneNumber: Number,
    email: String,
    state: String,
    city: String,
    username: String,
   // blackList : list,
    password: Schema.Types.Mixed,
    salt : Schema.Types.Mixed
});
 
module.exports = mongoose.model('register',registerInformation);