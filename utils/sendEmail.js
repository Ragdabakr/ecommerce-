const nodemailer = require('nodemailer');

// Nodemailer
const sendEmail = async (options) => {

  // 1) Create transporter ( service that will send email like "gmail","Mailgun", "mialtrap", sendGrid)
  const transporter = nodemailer.createTransport({
   // host: process.env.EMAIL_HOST,
   // port: process.env.EMAIL_PORT, // if secure false port = 587, if true port= 465
    service: 'gmail',
    port: 587,
    secure: false,
    auth: {
      user: 'ragdaaaaadel@gmail.com',
      pass: 'regorego1'
    },
  });


  // 2) Define email options (like from, to, subject, email content)
  const mailOpts = {
    from: 'E-shop App <ragdabakr5@gmail.com>',
    to: options.email,
    subject: options.subject,
    text: options.message,
  };

  // 3) Send email
  await transporter.sendMail(mailOpts);
};

module.exports = sendEmail;
