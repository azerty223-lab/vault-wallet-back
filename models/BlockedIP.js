const mongoose = require("mongoose");

const blockedIPSchema = new mongoose.Schema({
  ip: { type: String, required: true, unique: true, index: true },
  reason: String,
  score: { type: Number, default: 0 },
  createdAt: { type: Date, default: Date.now },
  updatedAt: { type: Date, default: Date.now },
});

module.exports = mongoose.model("BlockedIP", blockedIPSchema);
