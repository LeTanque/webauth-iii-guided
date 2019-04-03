const router = require('express').Router();
const bcrypt = require('bcryptjs');
const jwt = require('jsonwebtoken');

const secret = require('../api/secrets').jwtSecret; // <<<<<<<<<<<<
const Users = require('../users/users-model.js');

// for endpoints beginning with /api/auth
router.post('/register', (req, res) => {
  let user = req.body;
  const hash = bcrypt.hashSync(user.password, 10); // 2 ^ n
  user.password = hash;
  console.log(req.body)

  Users.add(user)
    .then(saved => {
      res.status(201).json(saved);
    })
    .catch(error => {
      res.status(500).json(error);
    });
});

router.post('/login', (req, res) => {
  let { username, password } = req.body;

  Users.findBy({ username })
    .first()
    .then(user => {
      if (user && bcrypt.compareSync(password, user.password)) {
        const token = generateToken(user);

        res.status(200).json({
          message: `Welcome ${user.username}!`,
          token,
        });
      } else {
        res.status(401).json({ message: 'Invalid Credentials' });
      }
    })
    .catch(error => {
      res.status(500).json(error);
    });
});

function generateToken(user) {
  const payload = {
    subject: user.id,
    username: user.username,
    roles: ["student", "ta", "staff"], // pretend they come from database user.roles
    // This is testing full access
    // To have them come from user.roles, change the migration to build the db differently; including the user.roles column
    // Then have the roles flag set as student by default, only.
    // Then have some mechanism for staff to modify the user.roles array for users, giving or taking away permissions.
    // Possibly a button that only appears in the staff backend settings. Possibly the GET of students with a button on each one for each
    // // roles value. That button would connect to a endpoint that modifies the db cell value for the roles array.
    // Then when user log out/in, their new token will contain the correct roles identifier, giving them the correct access.
  };
  // removed the const secret from this line <<<<<<<<<<<<<<<<<<<<<<<
  const options = {
    expiresIn: '1d',
  };

  return jwt.sign(payload, secret, options); // returns valid token
}

module.exports = router;
