const mongoose = require("mongoose");

const visitorSchema = new mongoose.Schema({
  ip: { type: String, required: true },
  userAgent: String,
  path: String,
  isBot: { type: Boolean, default: false },
  country: String,
  tlsVersion: String,
  isMobile: { type: Boolean, default: false },
  createdAt: { type: Date, default: Date.now },
});

module.exports = mongoose.model("Visitor", visitorSchema);
