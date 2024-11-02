const crypto = require("crypto");
const fs = require("fs");

// Function to generate password hash with a unique salt and store it
function hashPassword(userID, password, users) {
    const salt = crypto.randomBytes(16).toString("hex"); // Generate a random salt

    crypto.pbkdf2(password, salt, 5000, 15, "sha512", function(err, derivedKey){
        if (err) throw err;
        
        const userObj = {
            userID: userID,
            salt: salt,
            hash: derivedKey.toString("hex")
        };

        storeInDB(userObj);
    });

    // Function to store user data in a file
    function storeInDB(userObj) {
        // Read existing users from file
        console.log("Creating new User");
        users.push(userObj); // Add the new user
        fs.writeFile("./userAuthentication/passwords.json", JSON.stringify(users, null, 2), "utf8", function(err){
            if(err){
                console.log("Error writing to file:", err);
            } 
            else{
                console.log("Success User Created");
            }
        });
    }
}

// Function to verify password during login
function verifyPassword(userID, password, callback) {
    fs.readFile("./userAuthentication/passwords.json", "utf8", (err, data) => {
        if(err){
            console.log("Error reading file:", err);
            callback(false);
            return;
        }

        let users = [];
        try{
            users = JSON.parse(data); // Parse stored user data
        } 
        catch(e) {
            console.log("Error parsing JSON:", e);
            callback(false);
            return;
        }

        const userObj = users.find(function(obj){
            return obj.userID === userID;
        });

        if(!userObj) {
            console.log("User not found");
            callback(false);
            return;
        }

        // Generate hash with the same salt and compare
        crypto.pbkdf2(password, userObj.salt, 5000, 15, "sha512", (err, derivedKey) => {
            if (err) throw err;
            const isMatch = userObj.hash === derivedKey.toString("hex");
            callback(isMatch);
        });
    });
}

// Example usage
const userId = "Jishu";
const password = "Pass123";

// Register user
function createUser(userID, password){
    fs.readFile("./userAuthentication/passwords.json", "utf8", function(err, data){
        let users = [];
        if (!err) {
            try{
                users = JSON.parse(data); // Parse existing data if available
            } 
            catch(e){
                console.log("Error parsing JSON, starting fresh.");
            }
        }

        const isNotAvailable = users.find(function(obj){
            return obj.userID === userID;
        });
        if(isNotAvailable) {
            console.log("This Id has already been taken. Please try Another");
            return;
        }

        // else create user
        hashPassword(userId, password, users);
    });
}
createUser(userId, password);

// Simulate login
function verifyUser(){
    setTimeout(() => {
        verifyPassword(userId, password, (isAuthenticated) => {
            if (isAuthenticated) {
                console.log("\nUser Authenticated Successfully");
            } 
            else {
                console.log("\nUser NOT Authenticated, Please Enter Correct Password");
            }
        });
    }, 1000); // Delay to ensure file write has completed
}
verifyUser();