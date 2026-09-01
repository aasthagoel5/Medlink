const multer = require('multer');
const { CloudinaryStorage } = require('multer-storage-cloudinary');
const cloudinary = require('../../config/cloudinary');


const storage = new CloudinaryStorage({
  cloudinary,
  params:{
    folder: 'medlink-records',
    allowed_formats: ['jpg', 'jpeg', 'pdf', 'png']
  },
});

const upload = multer({ storage, limits: { fileSize: 10 * 1024 * 1024 } }); // 10MB cap

module.exports = upload;