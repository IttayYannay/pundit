var mongoose = require('mongoose');
var Schema = mongoose.Schema;

var user = new Schema({
    email : String,
    password : Schema.Types.Mixed,
});

module.exports = mongoose.model('user',user);
