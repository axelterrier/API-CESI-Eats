const mongoose = require("mongoose");

const menuSchema = new mongoose.Schema({
    idRestaurant: {
        type: Number
    },
    menu: {
        items: [{
            type: mongoose.Schema.Types.Mixed
        }],
        restaurant_categories: [{
            type: String
        }]
    }
  });
 

module.exports = mongoose.model('Menu', menuSchema,'menu')