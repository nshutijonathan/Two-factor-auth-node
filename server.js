const express = require("express");
const speakeasy = require("speakeasy");
const uuid = require("uuid");
const { JsonDB } = require("node-json-db");
const { Config } = require("node-json-db/dist/lib/JsonDBConfig");
const app = express();
app.use(express.json());
const db = new JsonDB(new Config("myDatabase", true, false, "/"));
app.get("/api", (req, res) => {
  return res.status(200).send({
    message: "Welcome",
  });
});
app.post("/api/register", (req, res) => {
  const id = uuid.v4();

  try {
    const path = `/user/${id}`;
    const temp_secret = speakeasy.generateSecret();
    db.push(path, { id, temp_secret });
    res.json({ id, secret: temp_secret.base32 });
  } catch (error) {
    console.log("error", error);
    return res.status(500).send({
      message: "Error generating the secret",
    });
  }
});
app.post("/api/verify", (req, res) => {
  const { token, userId } = req.body;
  try {
    const path = `/user/${userId}`;
    const user = db.getData(path);
    const { base32: secret } = user.temp_secret;
    const verified = speakeasy.totp.verify({
      secret,
      encoding: "base32",
      token,
    });
    if (verified) {
      db.push(path, { id: userId, secret: user.temp_secret });
      res.json({ verified: true });
    } else {
      res.json({ verified: false });
    }
  } catch (error) {
    console.log("error", error);
    return res.status(500).send({
      message: "Error  finding the user",
    });
  }
});
app.post("/api/validate", (req, res) => {
  const { token, userId } = req.body;
  try {
    const path = `/user/${userId}`;
    const user = db.getData(path);
    const { base32: secret } = user.secret;
    const tokenValidates = speakeasy.totp.verify({
      secret,
      encoding: "base32",
      token,
      window: 1,
    });
    if (tokenValidates) {
      res.json({ tokenValidates: true });
    } else {
      res.json({ tokenValidates: false });
    }
  } catch (error) {
    console.log("error", error);
    return res.status(500).send({
      message: "Error  finding the user",
    });
  }
});
const PORT = process.env.PORT || 5000;
app.listen(PORT, () => console.log(`app started on port ${PORT}`));
