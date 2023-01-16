const mongoose = require("mongoose");

const logSchema = new mongoose.Schema({
    logType: {
        type: String,
        required: true
    },
    timestamp: {
        type: Date,
        required: true
    },
    email: {
        type: String,
        required: true
    },
    success: {
        type: Boolean,
        required: true
    },
    error_message: {
        type: String,
    }
});

module.exports = mongoose.model('Logs', logSchema, 'logs');
