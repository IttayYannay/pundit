var mongoose = require('mongoose');
var Schema = mongoose.Schema;

var messageData = new Schema({
    Reference : String,
    phoneNumber: Number,
    longitude: Number,
    latitude: Number,
    range: Number,
    msg: String,
    pending: Number
});

module.exports = mongoose.model('data',messageData);
