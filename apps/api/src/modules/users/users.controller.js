const User = require('../auth/auth.model');

const getMe = async (req, res) => {
  try {
    const user = await User.findById(req.userId).select('-password'); // Exclude password
    res.status(200).json(user);
  } catch (err) {
    res.status(500).json({ message: 'Failed to fetch profile', error: err.message });
  }
};

const updateMe = async (req, res) => {
  try {
    const { bloodGroup, allergies, chronicConditions, dateOfBirth, emergencyContacts } = req.body;
    const user = await User.findByIdAndUpdate(req.userId, { bloodGroup, allergies, chronicConditions, dateOfBirth, emergencyContacts }, { new: true }).select('-password');
    res.status(200).json(user);
  } catch (err) {
    res.status(500).json({ message: 'Failed to update profile', error: err.message });
  }
};


module.exports = { getMe, updateMe };

