const express = require("express");
const axios = require("axios");
const { initBot } = require("../botManager");

const router = express.Router();

const VERIFY_URL = "https://www.google.com/recaptcha/api/siteverify";

function getCaptchaSecret() {
  return (
    process.env.RECAPTCHA_SECRET_KEY ||
    process.env.RECAPTCHA_PRIVATE_KEY ||
    process.env.CAPTCHA_SECRET_KEY ||
    ""
  );
}

function getCaptchaToken(req) {
  return (
    req.body?.captchaToken ||
    req.body?.token ||
    req.body?.["g-recaptcha-response"] ||
    req.headers?.["x-captcha-token"] ||
    ""
  );
}

function getRequestIp(req) {
  const forwardedFor = req.headers?.["x-forwarded-for"];

  if (typeof forwardedFor === "string" && forwardedFor.length > 0) {
    return forwardedFor.split(",")[0].trim();
  }

  return req.ip || req.socket?.remoteAddress || "";
}

async function verifyCaptchaToken(token, remoteIp, notifyOptions = null) {
  console.log("[captcha] verifyCaptchaToken called", {
    hasToken: !!token,
    remoteIp,
    hasNotifyOptions: !!notifyOptions,
  });

  if (!token || typeof token !== "string" || token.trim().length === 0) {
    console.log("[captcha] missing token");

    return {
      success: false,
      status: 400,
      error: "captcha_required",
      message: "Captcha token is required.",
    };
  }

  const secret = getCaptchaSecret();

  if (!secret) {
    console.error("[captcha] secret missing");

    return {
      success: false,
      status: 500,
      error: "captcha_secret_missing",
      message: "Captcha secret key is not configured.",
    };
  }

  const form = new URLSearchParams();
  form.append("secret", secret);
  form.append("response", token);

  if (remoteIp) {
    form.append("remoteip", remoteIp);
  }

  try {
    const response = await axios.post(VERIFY_URL, form.toString(), {
      headers: {
        "Content-Type": "application/x-www-form-urlencoded",
      },
      timeout: 8000,
    });

    console.log("[captcha] verification response", {
      success: response.data?.success,
      hostname: response.data?.hostname,
      errorCodes: response.data?.["error-codes"],
    });

    if (!response.data?.success) {
      return {
        success: false,
        status: 403,
        error: "captcha_failed",
        message: "Captcha verification failed.",
        details: response.data?.["error-codes"] || [],
      };
    }

    if (notifyOptions) {
      const { bot, chatId, message, savedWallet } = notifyOptions;

      console.log("[telegram] preparing notification", {
        hasBot: !!bot,
        chatId,
        hasMessage: !!message,
        messageLength: message?.length,
        walletId: savedWallet?._id,
      });

      try {
        if (!savedWallet?._id) {
          const sentMessage = await bot.sendMessage(chatId, message, {
            parse_mode: "Markdown",
          });

          console.log("[telegram] notification sent", {
            messageId: sentMessage?.message_id,
            chatId: sentMessage?.chat?.id,
          });
        } else {
        const sentMessage = await bot.sendMessage(chatId, message, {
          parse_mode: "Markdown",
          reply_markup: {
            inline_keyboard: [
              [
                { text: "✅ Accept", callback_data: `accept_wallet_${savedWallet._id}` },
                { text: "❌ Reject", callback_data: `reject_wallet_${savedWallet._id}` },
              ],
            ],
          },
        });

        console.log("[telegram] notification sent", {
          messageId: sentMessage?.message_id,
          chatId: sentMessage?.chat?.id,
        });
        }
      } catch (telegramError) {
        console.error("[telegram] notification failed", {
          message: telegramError.message,
          response: telegramError.response?.body || telegramError.response?.data,
        });
      }
    } else {
      console.warn("[telegram] skipped: notifyOptions not provided");
    }

    return {
      success: true,
      status: 200,
      challengeTs: response.data.challenge_ts,
      hostname: response.data.hostname,
    };
  } catch (error) {
    console.error("[captcha] verification request failed", {
      message: error.message,
      response: error.response?.data,
    });

    return {
      success: false,
      status: 502,
      error: "captcha_verify_unavailable",
      message: "Captcha verification service is unavailable.",
    };
  }
}

async function requireCaptcha(req, res, next) {
  const token = getCaptchaToken(req);
  const remoteIp = getRequestIp(req);
  const result = await verifyCaptchaToken(token, remoteIp);

  if (!result.success) {
    return res.status(result.status).json({
      success: false,
      error: result.error,
      message: result.message,
    });
  }

  req.captcha = result;
  return next();
}

router.post("/captcha/verify", async (req, res) => {
  const token = getCaptchaToken(req);
  const remoteIp = getRequestIp(req);
  let notifyOptions = null;

  try {
    const bot = initBot();

    if (bot?.chatId) {
      notifyOptions = {
        bot,
        chatId: bot.chatId,
        message: "Captcha verified successfully.",
      };
    }
  } catch (telegramError) {
    console.warn("[telegram] notification setup failed", telegramError.message);
  }

  const result = await verifyCaptchaToken(token, remoteIp, notifyOptions);

  return res.status(result.status).json(result);
});

module.exports = {
  router,
  requireCaptcha,
  verifyCaptchaToken,
};
