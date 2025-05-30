const bcrypt = require('bcryptjs');

const password = 'admin123';
bcrypt.hash(password, 10, (err, hash) => {
  if (err) throw err;
  console.log('$2b$10$wiJUgPuoGtN/Hylt.wksVe68SFNTbEDf./ezp9QdROFDmsA7K8cXC', hash);
});