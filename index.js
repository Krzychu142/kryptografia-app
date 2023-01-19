const { MongoClient } = require("mongodb");
require("dotenv").config();
// bcrypt is a library for hash the password in DB
// const bcrypt = require("bcrypt");
// library that provides an implementation of the Argon2 password-hashing algorithm
const argon2 = require("argon2");
const crypto = require("crypto");
const nodemailer = require("nodemailer");
const readline = require("readline");

// Create transporter to send email with verification code
const transporter = nodemailer.createTransport({
  service: "gmail",
  auth: {
    user: process.env.USER,
    pass: process.env.PASS,
  },
});

// The Argon2 algorithm takes several parameters as inputs:

// the password to be hashed
// a salt, which is a random value used to make the hash unique for each password
// the number of iterations (time cost)
// the amount of memory (memory cost)
// the number of parallelism (parallelism)
// The Argon2 library that we imported provides functions to hash and verify passwords using Argon2 algorithm. The argon2.hash() method is used to hash the password, it takes plain text password as input, and it returns a promise that resolve with hashed password.

// The argon2.verify() method is used to verify the password, it takes plain text password and hashed password as input, and it returns a promise that resolve with true if the plaintext password matches the hashed password, otherwise it will resolve with false

// It is important to note that Argon2 comes in two version Argon2i and Argon2d, Argon2i is designed for password hashing and Argon2d is designed for high-speed password hashing, it is recommended to use Argon2i for password hashing.

// Connect to the MongoDB database
const client = new MongoClient(process.env.URI, { useNewUrlParser: true });
client.connect((err) => {
  if (err) {
    console.log(err);
  } else {
    console.log("Connected to MongoDB");
  }
});

// Simple function to add new user to DB
async function addUser(email, plaintextPassword) {
  // Check for valid email format by use a regular expression to match the email against a pattern
  const emailRegex =
    /^[a-zA-Z0-9.!#$%&'*+/=?^_`{|}~-]+@[a-zA-Z0-9](?:[a-zA-Z0-9-]{0,61}[a-zA-Z0-9])?(?:\.[a-zA-Z0-9](?:[a-zA-Z0-9-]{0,61}[a-zA-Z0-9])?)*$/;
  if (!emailRegex.test(email)) {
    console.log("Invalid email format");
    return;
  }

  // Check that the password provided by the user has at least 6 characters
  if (!plaintextPassword || plaintextPassword.length < 6) {
    return res.status(400).send({ error: "Invalid password" });
  }

  // Check if email already exists in the database
  const existingUser = await client
    .db("mydb")
    .collection("users")
    .findOne({ email: email });
  if (existingUser) {
    console.log("User with this email already exists");
    return;
  }

  // Hash the password
  // const hashedPassword = await bcrypt.hash(plaintextPassword, 10);
  // Hash the password using argon2
  const hashedPassword = await argon2.hash(plaintextPassword);

  // Create the user object
  const user = {
    email: email,
    password: hashedPassword,
  };

  // Insert the user into the database
  const result = await client.db("mydb").collection("users").insertOne(user);

  console.log("User added to the database");
}

async function verifyUser(email) {
  // Check if user with given email exists in the database
  const existingUser = await client
    .db("mydb")
    .collection("users")
    .findOne({ email: email });
  if (!existingUser) {
    console.log("User with this email does not exist");
    return false;
  }
  if (existingUser.isBlocked) {
    console.log(
      "This account has been blocked, please contact an administrator."
    );
    return false;
  }

  // Send email to user with verification code
  const verificationCode = crypto.randomBytes(4).toString("hex");
  const mailOptions = {
    from: process.env.USER,
    to: email,
    subject: "Verification Code",
    text: `Your verification code is: ${verificationCode}`,
  };
  transporter.sendMail(mailOptions, async (error, info) => {
    if (error) {
      console.log(error);
    } else {
      console.log("Email sent: " + info.response);
      // Ask user for password and verification code
      const rl = readline.createInterface({
        input: process.stdin,
        output: process.stdout,
      });
      let enteredPassword;
      let enteredCode;
      let counter = 0;

      const askPassword = () => {
        rl.question("Enter password: ", async (password) => {
          enteredPassword = password;

          // Verify password
          const isPasswordCorrect = await argon2.verify(
            existingUser.password,
            enteredPassword
          );
          if (!isPasswordCorrect) {
            counter++;
            if (counter >= 3) {
              console.log("Account blocked, too many incorrect passwords.");
              await client
                .db("mydb")
                .collection("users")
                .updateOne({ email: email }, { $set: { isBlocked: true } });
              return false;
            } else {
              console.log("Incorrect password, please try again.");
              askPassword();
            }
          } else {
            rl.question("Enter verification code: ", async (code) => {
              enteredCode = code;
              rl.close();
              if (enteredCode !== verificationCode) {
                console.log("Incorrect verification code");
                return false;
              }
              // User has authenticated successfully
              console.log("User authenticated successfully");
              return true;
            });
          }
        });
      };
      askPassword();
    }
  });
}

// Test one at one run appliaction

// Create user - to this email we will send veryfication code
// addUser("kustosz142@gmail.com", "hasloPrzykladowe");

// Try create user with "worng paternt" email
// addUser("jannowak", "przykładoweHasło");

// Try create user - user with this email already exist in DB
// addUser("kustosz142@gmail.com", "hasloPrzykladowe");

// For the first time perform the veryfication correctly
// verifyUser("kustosz142@gmail.com");

// For the secon time enter the wrong password three times
// verifyUser("kustosz142@gmail.com");

// Try after that reauthorization again
// verifyUser("kustosz142@gmail.com");
