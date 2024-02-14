const express = require("express");
const bodyParser = require("body-parser");
const { MongoClient } = require("mongodb");
const bcrypt = require("bcrypt");
const uri = "mongodb://localhost:27017";
const { check, validationResult } = require("express-validator");
const session = require("express-session"); // Add this require

const app = express();

app.use(bodyParser.json());
app.use(
	session({
	  secret: "your-secret-key",
	  resave: false,
	  saveUninitialized: false,
	})
  );
app.post(
  "/register",
  [
    check("username")
      .isLength({ min: 5 })
      .withMessage("Username must be at least 5 characters long")
      .trim()
      .escape(), // Sanitize input by trimming whitespace and escaping characters
    check("password")
      .isLength({ min: 8 })
      .withMessage("Password must be at least 8 characters long"),
  ],
  async (req, res) => {
    const client = new MongoClient(uri);
    const errors = validationResult(req); // Check for errors

    if (!errors.isEmpty()) {
      return res.status(400).json({});
    }
    try {
      await client.connect();
      const database = client.db("users");
      const collection = database.collection("users");

      const hashedPassword = await bcrypt.hash(req.body.password, 10);

      const newUser = {
        username: req.body.username,
        password: hashedPassword,
      };

      const result = await collection.insertOne(newUser);
      res.send({ message: "User registered" });
    } catch (error) {
      console.error(error);
      res.status(500).send({ message: "Error registering user" });
    } finally {
      await client.close();
    }
  }
);

app.post(
  "/login",
  [
    check("username").exists().withMessage("Username is required"),
    check("password").exists().withMessage("Password is required"),
  ],
  async (req, res) => {
    const client = new MongoClient(uri);
    const errors = validationResult(req);

    if (!errors.isEmpty()) {
      return res.status(400).json({ errors: errors.array() });
    }

    try {
      await client.connect();
      const database = client.db("users");
      const collection = database.collection("users");

      // Find the user by username
      const user = await collection.findOne({ username: req.body.username });

      if (!user) {
        return res
          .status(401)
          .send({ message: "Invalid username or password" });
      }

      // Compare passwords using bcrypt
      const passwordMatch = await bcrypt.compare(
        req.body.password,
        user.password
      );

      if (!passwordMatch) {
        return res
          .status(401)
          .send({ message: "Invalid username or password" });
      }

      // Successful login - Handle session creation (Example using express-session)

      req.session.userId = user._id; // Store user ID in the session

      res.send({ message: "Login successful" });
    } catch (error) {
      console.error(error);
      res.status(500).send({ message: "Error logging in" });
    } finally {
      await client.close();
    }
  }
);

app.listen(3000, () => {
  console.log("Server is running on port 3000");
});
