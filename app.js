const express = require('express'); 
const { Pool } = require('pg'); 
const bodyParser = require('body-parser'); 
const bcrypt = require('bcrypt'); 
const app = express(); 
const port = 3000; 

const pool = new Pool({ 
   user: 'postgres', 
   host: 'localhost', 
   database: 'postgres', 
   password: '1908', 
   port: 5432, }); 

app.use(bodyParser.urlencoded({ extended: true })); 
app.use(bodyParser.json()); 

//-----Sign Up------
app.get('/', (req, res) => { res.sendFile(__dirname + '/index.html'); });

app.post('/api/auth/signup', async (req, res) => { 
   const { username, email, password, role } = req.body; // Hash the password 

const hashedPassword = await bcrypt.hash(password, 10); // Insert user into the database 

try {
   // Check if the username or email already exists
   const userCheck = await pool.query('SELECT * FROM users WHERE username = $1 OR email = $2', [username, email]);

    if (userCheck.rows.length > 0) {
      return res.status(400).json({ message: 'Username or email already exists' });
    }

    // Insert user into the database
    const result = await pool.query(
      'INSERT INTO users (username, email, password, role) VALUES ($1, $2, $3, $4) RETURNING *',
      [username, email, hashedPassword, role]
    );
    res.redirect('/signIn');
}catch (error) {
   console.error(error);
   res.status(500).send('Error registering user');
 }
}); 

//-----Sign In------
app.get('/signIn', (req, res) => { res.sendFile(__dirname + '/signIn.html'); }); 

app.post('/api/auth/signin', async (req, res) => { const { username, password } = req.body; // Hash the password 

try {
   const result = await pool.query('SELECT * FROM users WHERE username = $1', [username]);

   if (result.rows.length === 1) {
     const user = result.rows[0];
     const passwordMatch = await bcrypt.compare(password, user.password);

     if (passwordMatch) {
       if (user.role === 'admin') {
         res.redirect('/admin');
       } else if (user.role === 'moderator') {
         res.redirect('/moderator');
       } else {
         res.redirect('/user');
       }
     } else {
       res.status(401).json({ message: 'Invalid password' });
     }
   } else {
     res.status(404).json({ message: 'User not found' });
   }
 } catch (error) {
   console.error(error);
   res.status(500).send('Error during login');
 }
});

//-----Roles-------

app.get('/admin', (req, res) => { res.sendFile(__dirname + '/admin_page.html'); });

app.get('/moderator', (req, res) => { res.sendFile(__dirname + '/moderator_page.html'); });

app.get('/user', (req, res) => { res.sendFile(__dirname + '/user_page.html'); });


//----Log Out------
app.get('/logOut', (req, res) => { res.sendFile(__dirname + '/signIn'); });


app.listen(port, () => { console.log(`Server is running on http://localhost:${port}`);
}); 