const express = require("express");
const bodyParser = require("body-parser");
const { MongoClient } = require("mongodb");
const bcrypt = require("bcrypt");
const uri = "mongodb://localhost:27017";
const { check, validationResult } = require("express-validator");

const app = express();

app.use(bodyParser.json());

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

app.listen(3000, () => {
  console.log("Server is running on port 3000");
});
