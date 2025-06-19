const mongoose = require("mongoose");
require("dotenv").config();
const { createClient } = require("@supabase/supabase-js");

const userSchema = new mongoose.Schema({
  email: { type: String, required: true, unique: true },
  password: { type: String, required: true },
  role: { type: String, enum: ["user", "admin"], default: "user" },
});

module.exports = mongoose.model("User", userSchema);

const supabaseUrl = process.env.SUPABASE_URL;
const supabaseKey = process.env.SUPABASE_ANON_KEY;
const supabase = createClient(supabaseUrl, supabaseKey);

console.log("SUPABASE_URL:", supabaseUrl);
console.log("SUPABASE_ANON_KEY:", supabaseKey ? "OK" : "MISSING");
