import express from 'express';
import bodyParser from 'body-parser';
import bcrypt from "bcrypt";

const app = express();
const port = 4007;
app.use(express.static('public'));
app.use(bodyParser.urlencoded({ extended: true }));
app.set('view engine', 'ejs');

let users = []; // Array to store user data

app.get('/', (req, res) => {
  res.render("signin.ejs");
});

app.post('/user', async (req, res) => {
  const data = {
    name: req.body.email,
    password: req.body.password
  };

  const existUser = users.find(user => user.name === data.name);

  if (existUser) {
    res.render("signin.ejs", { error: "User Already Existed!" });
  } else {
    bcrypt.hash(data.password, 10, (err, hash) => {
      if (err) {
        res.send("Password Cannot be hashed");
      } else if (hash) {
        data.password = hash;
        users.push(data);
        console.log(users);
        res.render("login.ejs");
      }
    });
  }
});

app.get('/login', (req, res) => {
  res.render("login.ejs");
});

app.post('/check', async (req, res) => {
  const username = req.body.name.toLowerCase();
  const password = req.body.password.toLowerCase();

  try {
    const check = users.find(user => user.name.toLowerCase() === username);

    if (!check) {
      res.render("login.ejs", { error: "User not found" });
    } else {
      const isPassword = await bcrypt.compare(password, check.password);
      console.log(isPassword);

      if (!isPassword) {
        res.render("login.ejs", { error: "Incorrect Password" });
      } else {
        res.send("Successfully Connected");
      }
    }
  } catch {
    res.send("Wrong Details");
  }
});

app.listen(port, () => {
  console.log(`Your Server Running on port ${port}`);
});

