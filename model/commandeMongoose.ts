const mongoose = require("mongoose");

const commandeSchema = new mongoose.Schema({
  idCommande: {
    type: Number
  },
  date: {
    type: Date
  },
  client: {
    type: Number
  },
  restaurant: {
    type: Number
  },
  items: [
    {
      name: {
        type: String
      },
      price: {
        type: Number
      },
      qty: {
        type: Number
      },
    }
  ],
  total: {
    type: Number
  },
  deliverer: {
    type: Number
  },
  status: {
    type: String
  }
});


module.exports = mongoose.model('Commande', commandeSchema, 'order')