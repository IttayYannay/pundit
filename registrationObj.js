var mongoose = require('mongoose');
var Schema = mongoose.Schema;


var registerInformation = new Schema({
    phoneNumber: Number,
    email: String,
    state: String,
    city: String,
    username: String,
    password: Schema.Types.Mixed,
    salt : Schema.Types.Mixed
});
 
module.exports = registerInformation;