const nodemailer = require('nodemailer');

let etherealAccount;
let etherealTransporter;

const initEthereal = async () => {
  if (etherealTransporter) return etherealTransporter;
  etherealAccount = await nodemailer.createTestAccount();
  etherealTransporter = nodemailer.createTransport({
    host: etherealAccount.smtp.host,
    port: etherealAccount.smtp.port,
    secure: etherealAccount.smtp.secure,
    auth: {
      user: etherealAccount.user,
      pass: etherealAccount.pass
    }
  });
  return etherealTransporter;
};

// sendEmail supports a MAIL_PROVIDER env; default is ethereal sandbox for dev
const sendEmail = async ({ to, subject, text, html }) => {
  const provider = process.env.MAIL_PROVIDER || 'ethereal';

  if (provider === 'ethereal') {
    const transporter = await initEthereal();
    const info = await transporter.sendMail({
      from: process.env.MAIL_FROM || 'no-reply@example.com',
      to,
      subject,
      text,
      html
    });

    const previewUrl = nodemailer.getTestMessageUrl(info);
    console.log('Ethereal message sent. Preview URL:', previewUrl);
    return { previewUrl, messageId: info.messageId };
  }

  // fallback: just log
  console.log('sendEmail: provider not configured. Logging message.');
  console.log({ to, subject, text, html });
  return { logged: true };
};

module.exports = { sendEmail };
