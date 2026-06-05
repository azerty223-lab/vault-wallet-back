const mongoose = require("mongoose");

const visitorSchema = new mongoose.Schema({
  ip: String,
  userAgent: String,
  path: String,
  isBot: Boolean,
  country: String,
  tlsVersion: String,
  isMobile: Boolean,
  timestamp: { type: Date, default: Date.now },
});

module.exports = mongoose.model("Visitor", visitorSchema);
