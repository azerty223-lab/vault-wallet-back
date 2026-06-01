const TelegramBot = require("node-telegram-bot-api");
require("dotenv").config();

let botInstance = null;
let pollingActive = false;

function initBot() {
  if (!botInstance) {
    const botToken = process.env.TELEGRAM_BOT_TOKEN;
    const chatId = process.env.TELEGRAM_CHAT_ID;
    
    if (!botToken || !chatId) {
      throw new Error("TELEGRAM_BOT_TOKEN or TELEGRAM_CHAT_ID missing");
    }
    
    botInstance = new TelegramBot(botToken, { polling: false });
    botInstance.chatId = chatId;
    
    console.log("✅ Bot instance created (polling disabled)");
  }
  return botInstance;
}

function startPolling() {
  if (pollingActive) {
    console.log("⚠️ Polling already active, skipping...");
    return;
  }
  
  if (!botInstance) {
    console.log("❌ Bot instance not initialized");
    return;
  }
  
  try {
    botInstance.startPolling();
    pollingActive = true;
    console.log("✅ Bot polling started");
    
  } catch (error) {
    console.error("❌ Error starting polling:", error.message);
  }
}

function stopPolling() {
  if (pollingActive && botInstance) {
    try {
      botInstance.stopPolling();
      pollingActive = false;
      console.log("🛑 Bot polling stopped");
    } catch (error) {
      console.error("❌ Error stopping bot polling:", error.message);
    }
  }
}

module.exports = { initBot, startPolling, stopPolling };
