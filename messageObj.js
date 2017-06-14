var mongoose = require('mongoose');
var Schema = mongoose.Schema;

var messageData = new Schema({
    phoneNumber: Number,
    longitude: Number,
    latitude: Number,
    range: Number,
    msg: String,
    pending: Number
});

module.exports = messageData;


//Add Date (moment)