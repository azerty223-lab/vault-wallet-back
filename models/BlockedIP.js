const mongoose = require("mongoose");

const blockedIPSchema = new mongoose.Schema({
  ip: { type: String, required: true, unique: true, index: true },
  reason: String,
  createdAt: { type: Date, default: Date.now },
  updatedAt: { type: Date, default: Date.now },
});

module.exports = mongoose.model("BlockedIP", blockedIPSchema);
