'use strict';

/* =========================================================
   TELEGRAM NOTIFICATIONS

   Sends the same kind of rich, structured messages shown in the
   AllP2P bot reference screenshots ("Deposit Successful",
   "Order Request Accepted", "PAYMENT RECEIVED", "Order Completed",
   "Order Request Expired", KYC status updates, etc).

   This module is intentionally self-contained and safe to import
   even when Telegram isn't configured yet: with no TELEGRAM_BOT_TOKEN
   set, every send is a no-op that just logs to the console, so local
   development and the rest of the app are unaffected.
========================================================= */

const BOT_TOKEN = process.env.TELEGRAM_BOT_TOKEN || '';
const BOT_USERNAME = process.env.TELEGRAM_BOT_USERNAME || '';
const APP_NAME = process.env.APP_NAME || 'Once P2P';
const APP_URL = process.env.APP_URL || '';

const API_BASE = BOT_TOKEN
  ? `https://api.telegram.org/bot${BOT_TOKEN}`
  : '';

/*
  Telegram's MarkdownV2 requires these characters to be escaped
  anywhere they appear outside of an explicit formatting entity --
  this is exactly why the reference screenshots show stray
  backslashes before punctuation (e.g. "Happy trading\!").
  We escape automatically so template authors never have to think
  about it, and so callers can safely interpolate arbitrary user-
  supplied text (names, ad titles, etc) without breaking the layout
  or leaking Markdown injection.
*/
function escapeMdV2(value) {
  return String(value == null ? '' : value).replace(
    /[_*[\]()~`>#+\-=|{}.!\\]/g,
    '\\$&'
  );
}

// Bold a value after escaping it, for inline emphasis inside a
// larger escaped message (amounts, statuses, names).
function bold(value) {
  return `*${escapeMdV2(value)}*`;
}

function money(amount, currency) {
  const n = Number(amount || 0);
  return `${n.toFixed(2)} ${currency}`;
}

/*
  Builds the message body for a given notification type. Falls back
  to a plain title/body message for any type without a dedicated
  template, so every addNotification() call gets a Telegram message
  even before a specific template is written for it.
*/
function buildMessage(type, title, body, meta = {}) {
  const lines = [];

  // Callers pass a specific `event` in meta (e.g. 'wallet_deposit',
  // 'order_accepted') to pick a rich template below; without one we
  // fall back to the generic notification `type` (e.g. 'wallet',
  // 'p2p_order'), which just hits the default case.
  switch (meta.event || type) {
    case 'kyc_submitted':
      lines.push(
        `👋 Welcome to ${escapeMdV2(APP_NAME)}${
          meta.fullName ? ', ' + escapeMdV2(meta.fullName) : ''
        }\\!`,
        '',
        'Your registration is complete and your KYC documents have been submitted successfully\\.',
        '',
        '⏳ *Account Status: Pending Approval*',
        'Our team is currently reviewing your information\\. This process usually takes a few hours\\.',
        '',
        'You will receive another notification as soon as your account is approved and activated for trading\\.',
        '',
        `Thank you for choosing ${escapeMdV2(APP_NAME)}\\!`
      );
      break;

    case 'kyc_update':
      if (meta.status === 'approved') {
        lines.push(
          `🎉 Congratulations${meta.fullName ? ', ' + escapeMdV2(meta.fullName) : ''}\\!`,
          '',
          `Your ${escapeMdV2(APP_NAME)} account has been *APPROVED* and activated\\!`,
          '',
          '🚀 You can now:',
          '• Deposit USDT to your wallet',
          '• Create Buy and Sell advertisements',
          '• Start trading with other users',
          '',
          '📱 Open the app to get started now\\!',
          '',
          'Happy trading\\!'
        );
      } else {
        lines.push(
          `❌ *KYC Rejected*`,
          '',
          escapeMdV2(body),
          '',
          'Please review your details and submit a new application\\.'
        );
      }
      break;

    case 'wallet_deposit':
      lines.push(
        '🎉 *Deposit Successful\\!*',
        '',
        `Your ${escapeMdV2(meta.currency || 'USDT')} deposit has been processed and credited to your wallet\\.`,
        '',
        '*Deposit Details:*',
        `• Amount: ${escapeMdV2(money(meta.amount, meta.currency || 'USDT'))}`,
        '• Status: ✅ Confirmed',
        ...(meta.balance != null
          ? [
              '',
              '*Current Balance:*',
              `• Available: ${escapeMdV2(money(meta.balance, meta.currency || 'USDT'))}`,
              `• Locked: ${escapeMdV2(money(meta.locked || 0, meta.currency || 'USDT'))}`,
              `• Total: ${escapeMdV2(money((meta.balance || 0) + (meta.locked || 0), meta.currency || 'USDT'))}`
            ]
          : []),
        '',
        'You can now start trading\\!'
      );
      break;

    case 'order_accepted':
      lines.push(
        '✅ *Order Request Accepted*',
        '',
        'The advertiser has accepted your order request\\!',
        '',
        meta.counterparty ? `Advertiser: ${escapeMdV2(meta.counterparty)}` : '',
        `Amount: ${bold(meta.amountUsdt + ' USDT')} \\(${escapeMdV2(money(meta.amountEtb, 'ETB'))}\\)`,
        '',
        '📱 Please proceed to the app to continue with the order\\.'
      );
      break;

    case 'payment_marked_sent':
      lines.push(
        '🔔 *PAYMENT RECEIVED*',
        '',
        'The buyer has marked payment as sent for your order\\.',
        '',
        '📋 *Order Details:*',
        `• Order ID: ${escapeMdV2(meta.orderId)}`,
        `• Amount: ${escapeMdV2(meta.amountUsdt)} USDT \\(${escapeMdV2(money(meta.amountEtb, 'ETB'))}\\)`,
        meta.counterparty ? `• Buyer: ${escapeMdV2(meta.counterparty)}` : '',
        '',
        '⏰ *ACTION REQUIRED:*',
        'Please verify you received the payment in your bank account and release the funds\\.',
        '',
        '👉 Open the app to view the order and release funds\\.'
      );
      break;

    case 'order_completed':
      lines.push(
        '🎉 *Order Completed Successfully\\!*',
        '',
        escapeMdV2(body)
      );
      break;

    case 'order_expired':
      lines.push(
        '⏰ *Order Request Expired*',
        '',
        escapeMdV2(body),
        meta.amountUsdt
          ? `\nAmount: ${escapeMdV2(meta.amountUsdt)} USDT \\(${escapeMdV2(money(meta.amountEtb, 'ETB'))}\\)`
          : '',
        '',
        'Please try creating a new request or choose another offer\\.'
      );
      break;

    default:
      lines.push(bold(title), '', escapeMdV2(body));
  }

  const resolvedType = meta.event || type;

  if (APP_URL && ['order_accepted', 'payment_marked_sent', 'order_completed', 'kyc_update'].includes(resolvedType)) {
    lines.push('', `[Open ${escapeMdV2(APP_NAME)}](${APP_URL})`);
  }

  return lines.filter(l => l !== undefined).join('\n');
}

async function sendTelegramMessage(chatId, text, extra = {}) {
  if (!API_BASE || !chatId) {
    // Not configured yet (or user hasn't linked Telegram) -- log so
    // it's obvious in development what would have been sent.
    console.log(`[telegram:skip] chat=${chatId || 'none'} -- ${API_BASE ? '' : 'TELEGRAM_BOT_TOKEN not set'}`);
    return { ok: false, skipped: true };
  }

  try {
    const res = await fetch(`${API_BASE}/sendMessage`, {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({
        chat_id: chatId,
        text,
        parse_mode: 'MarkdownV2',
        disable_web_page_preview: true,
        ...extra
      })
    });

    const data = await res.json();

    if (!data.ok) {
      console.error('[telegram:error]', data.description || data);
    }

    return data;
  } catch (err) {
    console.error('[telegram:send failed]', err.message);
    return { ok: false, error: err.message };
  }
}

/*
  Sent for a bare "/start" (i.e. the user just opened the bot and hit
  Telegram's own "Start" button) -- greets them and hands them a
  "🚀 Start Trading" button that opens the marketplace right away, no
  KYC/account-linking prerequisite. A `web_app` button (rather than a
  plain `url` one) keeps them inside Telegram, opening the app in the
  built-in webview -- but that only works over https, so this falls
  back to a normal link button if APP_URL isn't https (e.g. still on
  localhost during development).
*/
function welcomeKeyboard() {
  if (!APP_URL) return undefined;

  const button = APP_URL.startsWith('https://')
    ? { text: '🚀 Start Trading', web_app: { url: APP_URL } }
    : { text: '🚀 Start Trading', url: APP_URL };

  return { inline_keyboard: [[button]] };
}

function sendWelcome(chatId) {
  const text = [
    `👋 Welcome to ${escapeMdV2(APP_NAME)}\\!`,
    '',
    'Trade crypto easily with ETB — fast, safe, and direct\\.',
    '',
    'Tap below to open the marketplace\\.'
  ].join('\n');

  const keyboard = welcomeKeyboard();

  return sendTelegramMessage(
    chatId,
    text,
    keyboard ? { reply_markup: keyboard } : {}
  );
}

// Called from addNotification() for every in-app notification. Only
// actually sends if the user has linked a Telegram chat.
function notifyTelegram(user, type, title, body, meta) {
  if (!user || !user.telegramChatId) return;

  const text = buildMessage(type, title, body, meta || {});
  sendTelegramMessage(user.telegramChatId, text).catch(() => {});
}

module.exports = {
  escapeMdV2,
  buildMessage,
  sendTelegramMessage,
  sendWelcome,
  notifyTelegram,
  isConfigured: () => Boolean(API_BASE),
  botUsername: BOT_USERNAME
};
