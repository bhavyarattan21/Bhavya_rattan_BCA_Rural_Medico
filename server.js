// server.js
const express = require('express');
const mysql = require('mysql2/promise');
const bcrypt = require('bcrypt');
const bodyParser = require('body-parser');
const cors = require('cors');

const app = express();
app.use(cors());
app.use(bodyParser.json());
app.use(bodyParser.urlencoded({ extended: true }));

// 1) MySQL connection pool
const pool = mysql.createPool({
  host: 'localhost',
  user: 'root',
  password: '',       // your XAMPP MySQL password
  database: 'rural_medico',
  waitForConnections: true,
  connectionLimit: 10
});

// Helper to run queries
async function query(sql, params) {
  const [rows] = await pool.execute(sql, params);
  return rows;
}

// 2) Registration endpoint
// REGISTER
app.post('/register', async (req, res) => {
  const requiredFields = ['full_name', 'phone_number', 'email', 'password', 'state'];
  const missingFields = requiredFields.filter(field => !req.body[field]);

  if (missingFields.length > 0) {
    return res.status(400).json({
      message: `Missing fields: ${missingFields.join(', ')}`
    });
  }

  try {
    const hash = await bcrypt.hash(req.body.password, 10);
    await query(
      `INSERT INTO users
  (full_name, phone_number, email, password_hash, state)
  VALUES (?, ?, ?, ?, ?)`,
      [req.body.full_name, req.body.phone_number, req.body.email, hash, req.body.state]
    );
    res.json({ message: 'Registration successful' });
  } catch (error) {
    if (error.code === 'ER_DUP_ENTRY') {
      return res.status(409).json({ message: 'Email already exists' });
    }
    console.error('Registration error:', error);
    res.status(500).json({ message: 'Server error during registration' });
  }
});

// LOGIN
app.post('/login', async (req, res) => {
  if (!req.body.email || !req.body.password) {
    return res.status(400).json({ message: 'Email and password required' });
  }

  try {
    const [users] = await pool.execute(
      'SELECT * FROM users WHERE email = ?',
      [req.body.email]
    );

    if (users.length === 0) {
      return res.status(401).json({ message: 'Invalid credentials' });
    }

    const user = users[0];
    const validPassword = await bcrypt.compare(req.body.password, user.password_hash);

    if (!validPassword) {
      return res.status(401).json({ message: 'Invalid credentials' });
    }

    res.json({
      message: 'Login successful',
      user: {
        id: user.id,
        name: user.full_name,
        email: user.email
      }
    });
  } catch (error) {
    console.error('Login error:', error);
    res.status(500).json({ message: 'Server error during login' });
  }
});

// 4) Appointment booking endpoint
app.post('/appointments', async (req, res) => {
  const requiredFields = [
    'user_id', 'full_name', 'email', 'phone_number',
    'address', 'age', 'gender', 'problem', 'date', 'time'
  ];

  const missingFields = requiredFields.filter(field => !req.body[field]);

  if (missingFields.length > 0) {
    return res.status(400).json({
      message: `Missing required fields: ${missingFields.join(', ')}`
    });
  }

  // Validate age is a number
  if (isNaN(req.body.age) || req.body.age < 0) {
    return res.status(400).json({ message: 'Invalid age' });
  }

  try {
    await query(
      `INSERT INTO appointments
  (user_id, full_name, email, phone_number, address, age, gender, problem, preferred_doctor, appointment_date, appointment_time)
  VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)`,
      [
        req.body.user_id,
        req.body.full_name,
        req.body.email,
        req.body.phone_number,
        req.body.address,
        parseInt(req.body.age),
        req.body.gender,
        req.body.problem,
        req.body.preferred_doctor || null, // Handle optional field
        req.body.date,
        req.body.time
      ]
    );
    res.json({ message: 'Appointment booked successfully' });
  } catch (error) {
    console.error('Appointment error:', error);
    res.status(500).json({ message: 'Server error during appointment booking' });
  }
});

// Server start
const PORT = process.env.PORT || 3000;
app.listen(PORT, () => {
  console.log(`Server running on port ${PORT}`);
});