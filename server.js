require("dotenv").config();
const express = require("express");
const bodyParser = require("body-parser");
const sgMail = require("@sendgrid/mail");
const crypto = require("crypto");
const cors = require('cors');
const app = express();
const client = require('twilio')(process.env.accountSid, process.env.authToken);
const PORT = process.env.PORT || 5000;
// Middleware
app.use(express.json());
const corsOptions = {
    origin: 'https://decarb-98f67d-1bd25872d802028e49e0a37d4.webflow.io', // Allow requests from your frontend
    credentials: true // Allow credentials (cookies) to be sent with requests
};
app.use(cors(corsOptions));
app.use(bodyParser.urlencoded({ extended: true }));

// Store OTPs and last sent times
const otpMap = new Map();
const lastSentTimes = {};

// Generate OTP function
function generateOTP() {
    const digits = '0123456789';
    let OTP = '';
    for (let i = 0; i < 6; i++) {
        OTP += digits[Math.floor(Math.random() * 10)];
    }
    return OTP;
}

// Hash function for storing OTPs securely
function hashOTP(otp) {
    const secret = process.env.secretKey;
    const hash = crypto.createHmac('sha256', secret)
                     .update(otp)
                     .digest('hex');
    return hash;
}
app.get("/",(req,res)=> {
    res.send("opt verification home page!")
})

// Route for sending OTP
app.post("/send-otp", (req, res) => {
    const otp = generateOTP();
    const hashedOTP = hashOTP(otp);
    const phoneNumber = req.body.to;
    otpMap.set(phoneNumber, hashedOTP); // Store hashed OTP in memory
    console.log(phoneNumber);
    client.messages
        .create({
            body: `Your OTP is: ${otp}`,
            to: phoneNumber,
            from: process.env.from,
        })
        .then((message) => {
            console.log(`OTP sent successfully SID: ${message.sid}`);
            res.status(200).json({ success: true, message: "OTP sent successfully." });
        })
        .catch((error) => {
            console.error('Error sending OTP:', error);
            res.status(500).json({ success: false, error: "Failed to send OTP." });
        });
});

// Route for verifying OTP
app.post("/verify-otp", (req, res) => {
    const enteredOTP = req.body.otp;
    const phoneNumber = req.body.to;
    const storedOTP = otpMap.get(phoneNumber); // Retrieve hashed OTP from memory
    if (!storedOTP) {
        return res.status(200).json({ success: false, message: "No OTP found for the given phone number." });
    }
    const hashedEnteredOTP = hashOTP(enteredOTP);
    if (hashedEnteredOTP === storedOTP) {
        otpMap.delete(phoneNumber); // Remove OTP from memory after successful verification
        res.status(200).json({ success: true, message: "OTP verified successfully." });
    } else {
        res.status(400).json({ success: false, message: "Invalid OTP. Please try again." });
    }
});

// Route for resending OTP
const resendInterval = 15 * 1000; // Resend interval idn milliseconds

app.post("/resend-otp", (req, res) => {
    const phoneNumber = req.body.to;
    const currentTime = Date.now();
    const lastSentTime = lastSentTimes[phoneNumber] || 0;
    const timeDifference = currentTime - lastSentTime;
    
    // Check if OTP was recently sent within the last 30 seconds
    if (timeDifference < resendInterval) {
        const timeRemaining = Math.ceil((resendInterval - timeDifference) / 1000);
        return res.status(429).json({ success: false, message: `You can resend OTP after ${timeRemaining} seconds!` });
    }

    // Generate OTP
    const otp = generateOTP();
    const hashedOTP = hashOTP(otp);
    otpMap.set(phoneNumber, hashedOTP); // Store hashed OTP in memory

    // Resend OTP
    client.messages
        .create({
            body: `Your OTP is: ${otp}`,
            to: phoneNumber,
            from: process.env.from,
        })
        .then((message) => {
            console.log(`OTP resent successfully SID: ${message.sid}`);
            // Update the last sent time
            lastSentTimes[phoneNumber] = currentTime;
            res.status(200).json({ success: true, message: "OTP resent successfully." });
        })
        .catch((error) => {
            console.error('Error resending OTP:', error);
            res.status(400).json({ success: false, error: "Failed to resend OTP." });
        });
});

app.post("/email-otp", (req, res) => {
    const { email } = req.body;

    // Check if OTP was recently sent within the last 30 seconds
    const currentTime = Date.now();
    const lastSentTime = lastSentTimes[email] || 0;
    const timeDifference = currentTime - lastSentTime;
    if (timeDifference < 30 * 1000) { // 30 seconds in milliseconds
        const timeRemaining = Math.ceil((30 * 1000 - timeDifference) / 1000); // Convert remaining time to seconds
        return res.status(429).json({ success: false, message: `You can resend OTP after ${timeRemaining} seconds.` });
    }

    const otp = generateOTP(); // Generate OTP
    const hashedOTP = hashOTP(otp); // Hash OTP
    
    const msg = {
        to: email,
        from: process.env.SENDGRID_SENDER_EMAIL,
        subject: 'Your OTP',
        text: `Your OTP is: ${otp}`
    };
    
    sgMail.setApiKey(process.env.SENDGRID_API_KEY);
    sgMail.send(msg)
        .then(() => {
            console.log("Email sent successfully.");
            otpMap.set(email, hashedOTP); // Store hashed OTP in memory
            lastSentTimes[email] = currentTime; // Update the last sent time
            res.status(200).json({ success: true, message: "OTP sent successfully." });
        })
        .catch((error) => {
            console.error('Error sending email:', error);
            res.status(500).json({ success: false, error: "Failed to send OTP." });
        });
});

// Error handling middleware
app.use((err, req, res, next) => {
    console.error(err.stack);
    res.status(500).send('Something broke!');
});

app.listen(PORT, () => {
    console.log(`Server running at ${PORT}`);
});