const ShareLink = require('./sharing.model');
const Record  = require('../records/records.model');

// EXPIRY_OPTIONS maps a friendly string to milliseconds
const EXPIRY_OPTIONS = {
  '1h': 60 * 60 * 1000,
  '1d': 24 * 60 * 60 * 1000,
  '7d': 7 * 24 * 60 * 60 * 1000,
};

const createShareLink = async (req, res) => {
  try{
    const {recordId,  expiry} = req.body  //expiry '1h' | '1d' | '7d'

    const record = await Record.findOne({_id: recordId, owner: req.userId});
    if(!record){
      return res.status(400).json({message: 'Record not found'});
    }

    const durationMs = EXPIRY_OPTIONS[expiry] || EXPIRY_OPTIONS['1d']; // default to 1 day
    const expiresAt = new Date(Date.now() + durationMs);

    const shareLink = await ShareLink.create({
      record: record._id,
      owner: req.userId,
      expiresAt,
    });

    res.status(201).json({
      shareUrl:`${ process.env.FRONTEND_URL}/shared/${shareLink.token}`,
      expiresAt: shareLink.expiresAt,
    });
  }catch(err){
    res.status(500).json({message: 'Failed to create share link', error: err.message});
  }
};

const getActiveLink = async (req, res ) => {
  try{
    const links = await ShareLink.find({
      owner: req.userId,
      expiresAt: { $gt: new Date()}    //only still-valid links
    }).populate('record', 'type doctorName recordDate');

    res.status(200).json(links);
  }catch(err){
    res.status(500).json({message: 'Failed to fetch share link', error: err.message})
  }
};

const revokeLink = async (req, res) => {
  try {
    const link = await ShareLink.findOneAndDelete({ _id: req.params.id, owner: req.userId });
    if (!link) {
      return res.status(404).json({ message: 'Share link not found' });
    }
    res.status(200).json({ message: 'Share link revoked' });
  } catch (err) {
    res.status(500).json({ message: 'Failed to revoke link', error: err.message });
  }
};

// PUBLIC — no auth required, this is what a doctor hits
const resolveSharedRecord = async (req, res ) => {
  try{
    const link = await ShareLink.findOne({ token: req.params.token }).populate('record');

    if(!link){
      return res.status(404).json({message: 'Invalid share link' });    
    }

    if (link.expiresAt < new Date()){
      return res.status(410).json({message:'This link has expired'});
    }

    res.status(200).json({
      record: link.record,
      expiresAt: link.expiresAt
    });
  }catch (err){
    res.status(500).json({message: 'Failed to resolve shared link', error: err.message});
  }
};

module.exports = {createShareLink, getActiveLink, revokeLink, resolveSharedRecord}


