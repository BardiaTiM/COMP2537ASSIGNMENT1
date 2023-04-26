require('dotenv').config();

const express = require('express');
const session = require('express-session');
const MongoStore = require('connect-mongo');
const bcrypt = require('bcrypt');
const Joi = require('joi');
const app = express();
const expireTime = 3600000; // 1 hour

const port = process.env.PORT || 3030;

/* secret information section */
const mongodb_host = process.env.MONGODB_HOST;
const mongodb_user = process.env.MONGODB_USER;
const mongodb_password = process.env.MONGODB_PASSWORD;
const mongodb_database = process.env.MONGODB_DATABASE;
const mongodb_session_secret = process.env.MONGODB_SESSION_SECRET;


var {database} = require('./databaseConnection.js');

const userCollection = database.db(mongodb_database).collection('users');

app.use(express.urlencoded({extended: false}));

var mongoStore = MongoStore.create({
	mongoUrl: `mongodb+srv://${mongodb_user}:${mongodb_password}@${mongodb_host}/sessions`,
	crypto: {
		secret: mongodb_session_secret
	}
})

app.use(session({
    secret: mongodb_session_secret,
    store: mongoStore,
    saveUninitialized: false,
    resave: true
}));

app.get('/nosql-injection', async (req,res) => {
	var email = req.query.email;

	if (!email) {
		res.send(`<h3>no user provided - try /nosql-injection?user=name</h3> <h3>or /nosql-injection?user[$ne]=name</h3>`);
		return;
	}
	console.log("email: "+email);

	const schema = Joi.string().max(20).required();
	const validationResult = schema.validate(email);

	//If we didn't use Joi to validate and check for a valid URL parameter below
	// we could run our userCollection.find and it would be possible to attack.
	// A URL parameter of user[$ne]=name would get executed as a MongoDB command
	// and may result in revealing information about all users or a successful
	// login without knowing the correct password.
	if (validationResult.error != null) {  
	   console.log(validationResult.error);
	   res.send("<h1 style='color:darkred;'>A NoSQL injection attack was detected!!</h1>");
	   return;
	}	

	const result = await userCollection.find({username: username}).project({username: 1, password: 1, _id: 1}).toArray();

	console.log(result);

    res.send(`<h1>Hello ${username}</h1>`);
});

//HOME
app.get('/', (req, res) => {
    const email = req.session.email;
    const name = req.session.name;
    if (typeof email === "string" && email !== "") {
      var html = `
        Hello, ${name}! <br\>
        <button onclick="window.location.href='/members'">Go to Members Area</button><br>
        <button onclick="window.location.href='/logout2'">Logout</button>
      `;
      res.send(html);
    } else {
      var html = `
        <button onclick="window.location.href='/signup'">Sign Up</button><br>
        <button onclick="window.location.href='/login'">Log In</button>
      `;
      res.send(html);
    }
  });
  

//SIGN UP
app.get('/signup', (req, res) => {
    var html = `
      Sign Up:
      <br/>
      <br/>
      <form action='/submitUser' method='post'>
        <input name='name' type='text' placeholder='name'><br>
        <input name='email' type='text' placeholder='email'><br>
        <input name='password' type='password' placeholder='password'><br>
        <br/>
        <button type='submit'>Submit</button>
      </form>
    `;
    res.send(html);
  });


  app.post('/submitUser', async (req,res) => {
    var name = req.body.name;
    var email = req.body.email;
    var password = req.body.password;
    var saltRounds = 12;

    if (!name) {
        res.send("name is required. <a href='/signup'>Try again</a>");
        return;
    }
    if (!email) {
        res.send("email is required. <a href='/signup'>Try again</a>");
        return;
    }
    if (!password) {
        res.send("Password is required. <a href='/signup'>Try again</a>");
        return;
    }

    const schema = Joi.object(
        {
            name: Joi.string().max(20).required(),
            email: Joi.string().email().required(),
            password: Joi.string().max(20).required()
        });
        
    const validationResult = schema.validate({name, email, password});
    if (validationResult.error != null) {
        console.log(validationResult.error);
        res.redirect("/signup");
        return;
    }

    // Check if an account with the provided email already exists
    const existingUser = await userCollection.findOne({ email: email });
    if (existingUser) {
        res.send("An account with this email already exists. <a href='/signup'>Try again</a>");
        return;
    }

    var hashedPassword = await bcrypt.hash(password, saltRounds);
        
    await userCollection.insertOne({name: name, email: email, password: hashedPassword});
    console.log("Inserted user");

    res.redirect('/members');
});


//LOG IN 
app.get('/login', (req,res) => {
    var html = `
    log in
    <form action='/loggingin' method='post'>
    <input name='email' type='text' placeholder='email'><br>
    <input name='password' type='password' placeholder='password'><br>
    <button>Submit</button>
    </form>
    `;
    res.send(html);
});

app.post('/loggingin', async (req,res) => {
    var email = req.body.email;
    var password = req.body.password;

	const schema = Joi.string().max(20).required();
	const validationResult = schema.validate(email);
	if (validationResult.error != null) {
	   console.log(validationResult.error);
	   res.redirect("/login");
	   return;
	}

	const result = await userCollection.find({email: email}).project({email: 1, password: 1, name: 1}).toArray();

	console.log(result);
	if (result.length != 1) {
		console.log("user not found");
		res.redirect("/login");
		return;
	}
	if (await bcrypt.compare(password, result[0].password)) {
		console.log("correct password");
		req.session.authenticated = true;
		req.session.email = email;
        req.session.name = result[0].name;
		req.session.cookie.maxAge = expireTime;

		res.redirect('/members');
		return;
	}
	else {
		console.log("incorrect password");
		res.redirect("/login");
		return; 
	}
});


//MEMBERS
app.get('/members', (req, res) => {
    // Get the user's name and profile picture from the session
    const name = req.session.name;
    const email = req.session.email;
    const pictureUrl = req.session.pictureUrl;

    // Check if the user is logged in
    if (!email) {
      // Redirect to the login page if not logged in
      res.redirect('/login');
    } else {
      // Render the members page with the user's name and profile picture
      const html = `
        <h1>Hello, ${name}!</h1>
        <img src="${pictureUrl}" alt="Profile Picture">
        <br><br>
        <form action="/logout" method="post">
          <button type="submit">Sign Out</button>
        </form>
      `;
      res.send(html);
    }
  });

  app.post('/logout', (req, res) => {
    // Destroy the session
    req.session.destroy((err) => {
      if (err) {
        console.log(err);
      } else {
        // Redirect to the login page after successfully logging out
        res.redirect('/login');
      }
    });
  });

  //logout2
    app.get('/logout2', (req,res) => { 
        req.session.destroy((err) => {
            if (err) {
                console.log(err);
            } else {
                res.redirect('/');
            }
        });
    });
  


app.get('/cat/:id', (req,res) => {

    var cat = req.params.id;

    if (cat == 1) {
        res.send("Fluffy: <img src='/fluffy.gif' style='width:250px;'>");
    }
    else if (cat == 2) {
        res.send("Socks: <img src='/socks.gif' style='width:250px;'>");
    }
    else {
        res.send("Invalid cat id: "+cat);
    }
});


app.use(express.static(__dirname + "/public"));

app.get("*", (req,res) => {
	res.status(404);
	res.send("Page not found - 404");
})

app.listen(port, () => {
	console.log("Node application listening on port "+port);
}); 

