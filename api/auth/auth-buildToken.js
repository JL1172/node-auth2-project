const UserData = require("../users/users-model");
const jwt = require("jsonwebtoken")
const {JWT_SECRET} = require("../secrets")

module.exports = {buildToken}
async function buildToken(user,userToCompare) {
    const roleName = await UserData.findById(userToCompare.user_id);
    const nameOfRole = roleName.role_name;
   
    const payload = {
      subject : userToCompare.user_id,
      username : user.username,
      role_name : nameOfRole.trim(),
    }
    const options = {
      expiresIn : "1d"
    }
    return jwt.sign(payload,JWT_SECRET,options)
  }