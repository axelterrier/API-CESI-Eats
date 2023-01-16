const mongoose = require('mongoose');
const Schema = mongoose.Schema;

const perfSchema = new Schema({
    route: {
        type: String,
        required: true
    },
    date: {
        type: Date,
        default: Date.now
    },
    time: {
        type: Number,
        required: true
    }
});

module.exports = mongoose.model('Perf', perfSchema,'perf');