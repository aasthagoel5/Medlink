const User = require('./auth.model');
const { hashPassword, comparePassword, generateToken } = require('./auth.service');

const signup = async (req , res) => {
  try {
    const {name, email, password } = req.body

    if (!name || !email || !password){
      return res.status(400).json({ message: 'Name, email, and password are required' });
    }

    const existingUser = await User.findOne({email});
    if (existingUser){
      return res.status(409).json({message : 'An acoount with this email already exists'});
    }

    const hashedPassword = await hashPassword(password);
    const user = await User.create({ name, email, password: hashedPassword });
    
    const token = generateToken(user._id);

    res.status(201).json({
      token,
      user: { id: user._id, name: user.name, email: user.email },
    });
  } catch (err) {
    res.status(500).json({ message: 'Signup failed', error: err.message });
  }
};

const login = async (req, res ) => {
  try {
    const {email, password} = req.body;

    const user = await User.findOne({ email });
    if (!user){
      return res.status(401).json({message : 'Invalid email or password'});
    }

    const isMatch = await comparePassword(password, user.password);
    if(!isMatch){
      return res.status(401).json({message : 'Invalid email or password'});
    }

    const token  = generateToken(user._id);

    res.status(200).json({
      token,
      user: { id: user._id, name: user.name, email: user.email },
    });
    } catch (err) {
      res.status(500).json({message : 'Login failed', error: err.message});
    }
};

module.exports = {signup, login};
