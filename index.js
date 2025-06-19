require("dotenv").config();
const express = require("express");
const cors = require("cors");
const app = express();
const PORT = process.env.PORT || 3001;
const { createClient } = require("@supabase/supabase-js");
const jwt = require("jsonwebtoken");
const bcrypt = require("bcryptjs");
const axios = require("axios");

const supabaseUrl = process.env.SUPABASE_URL;
const supabaseKey = process.env.SUPABASE_ANON_KEY;
const supabase = createClient(supabaseUrl, supabaseKey);
const JWT_SECRET = process.env.JWT_SECRET || "secretkey123";
const AI_SERVICE_URL =
  process.env.AI_SERVICE_URL || "https://ai-budgeting-ai.domcloud.dev";
app.use(express.json());
app.use(cors());

// Register
app.post("/api/register", async (req, res) => {
  const { email, password } = req.body;
  try {
    const { data: existing } = await supabase
      .from("users")
      .select("*")
      .eq("email", email);
    if (existing && existing.length > 0)
      return res.status(400).json({ message: "Email already registered" });
    const hash = await bcrypt.hash(password, 10);
    const { error } = await supabase
      .from("users")
      .insert([{ email, password: hash, role: "user" }]);
    if (error) return res.status(400).json({ message: error.message });
    res.status(201).json({ message: "User registered" });
  } catch (err) {
    res.status(500).json({ message: "Server error" });
  }
});

// Login
app.post("/api/login", async (req, res) => {
  const { email, password } = req.body;
  try {
    const { data: users } = await supabase
      .from("users")
      .select("*")
      .eq("email", email);
    const user = users && users[0];
    if (!user) return res.status(400).json({ message: "Invalid credentials" });
    const valid = await bcrypt.compare(password, user.password);
    if (!valid) return res.status(400).json({ message: "Invalid credentials" });
    const token = jwt.sign({ userId: user.id, role: user.role }, JWT_SECRET, {
      expiresIn: "1d",
    });
    res.json({ token });
  } catch (err) {
    res.status(500).json({ message: "Server error" });
  }
});

function auth(req, res, next) {
  const authHeader = req.headers.authorization;
  if (!authHeader) return res.status(401).json({ message: "No token" });
  const token = authHeader.split(" ")[1];
  try {
    const decoded = jwt.verify(token, JWT_SECRET);
    req.user = decoded;
    next();
  } catch {
    res.status(401).json({ message: "Invalid token" });
  }
}

// CREATE transaksi (integrasi AI classify)
app.post("/api/transactions", auth, async (req, res) => {
  try {
    let { amount, category, source, date, note, description } = req.body;
    if (!category && description) {
      const aiRes = await axios.post(`${AI_SERVICE_URL}/classify`, {
        description,
      });
      category = aiRes.data.category;
    }
    const { error } = await supabase.from("transactions").insert([
      {
        user_id: req.user.userId,
        amount,
        category: category || "Other",
        source,
        date,
        note,
      },
    ]);
    if (error) return res.status(400).json({ message: error.message });
    res.status(201).json({ message: "Transaction created" });
  } catch (err) {
    res.status(500).json({ message: "Server error", error: err.message });
  }
});

// READ (list) transaksi user (filter kategori/tanggal opsional)
app.get("/api/transactions", auth, async (req, res) => {
  try {
    const { category, start, end } = req.query;
    let query = supabase
      .from("transactions")
      .select("*")
      .eq("user_id", req.user.userId);
    if (category) query = query.eq("category", category);
    if (start) query = query.gte("date", start);
    if (end) query = query.lte("date", end);
    const { data, error } = await query.order("date", { ascending: false });
    if (error) return res.status(400).json({ message: error.message });
    res.json(data);
  } catch (err) {
    res.status(500).json({ message: "Server error" });
  }
});

// UPDATE transaksi
app.put("/api/transactions/:id", auth, async (req, res) => {
  try {
    const { id } = req.params;
    const { amount, category, source, date, note } = req.body;
    const { data, error } = await supabase
      .from("transactions")
      .update({ amount, category, source, date, note })
      .eq("id", id)
      .eq("user_id", req.user.userId)
      .select();
    if (error) return res.status(400).json({ message: error.message });
    if (!data || data.length === 0)
      return res.status(404).json({ message: "Not found" });
    res.json(data[0]);
  } catch (err) {
    res.status(500).json({ message: "Server error" });
  }
});

// DELETE transaksi
app.delete("/api/transactions/:id", auth, async (req, res) => {
  try {
    const { id } = req.params;
    const { data, error } = await supabase
      .from("transactions")
      .delete()
      .eq("id", id)
      .eq("user_id", req.user.userId)
      .select();
    if (error) return res.status(400).json({ message: error.message });
    if (!data || data.length === 0)
      return res.status(404).json({ message: "Not found" });
    res.json({ message: "Deleted" });
  } catch (err) {
    res.status(500).json({ message: "Server error" });
  }
});

// GET semua budget setting user
app.get("/api/budgets", auth, async (req, res) => {
  try {
    const { data, error } = await supabase
      .from("budget_settings")
      .select("*")
      .eq("user_id", req.user.userId);
    if (error) return res.status(400).json({ message: error.message });
    res.json(data);
  } catch (err) {
    res.status(500).json({ message: "Server error" });
  }
});

// SET/UPDATE budget setting per kategori
app.post("/api/budgets", auth, async (req, res) => {
  try {
    const { category, limit } = req.body;
    if (!category || !limit)
      return res.status(400).json({ message: "Category and limit required" });
    // Upsert: delete existing, then insert (karena supabase-js belum support upsert multi-key)
    await supabase
      .from("budget_settings")
      .delete()
      .eq("user_id", req.user.userId)
      .eq("category", category);
    const { data, error } = await supabase
      .from("budget_settings")
      .insert([{ user_id: req.user.userId, category, budget_limit: limit }])
      .select();
    if (error) return res.status(400).json({ message: error.message });
    res.json(data[0]);
  } catch (err) {
    res.status(500).json({ message: "Server error" });
  }
});

// ALERT: cek jika pengeluaran kategori bulan ini melebihi limit
app.get("/api/budgets/alert", auth, async (req, res) => {
  try {
    const { data: budgets, error: err1 } = await supabase
      .from("budget_settings")
      .select("*")
      .eq("user_id", req.user.userId);
    const now = new Date();
    const start = new Date(now.getFullYear(), now.getMonth(), 1)
      .toISOString()
      .slice(0, 10);
    const end = new Date(now.getFullYear(), now.getMonth() + 1, 0)
      .toISOString()
      .slice(0, 10);
    const { data: txs, error: err2 } = await supabase
      .from("transactions")
      .select("*")
      .eq("user_id", req.user.userId)
      .gte("date", start)
      .lte("date", end);
    if (err1 || err2)
      return res.status(400).json({ message: (err1 || err2).message });
    const alert = budgets.map((b) => {
      const spent = txs
        .filter((t) => t.category === b.category)
        .reduce((a, t) => a + t.amount, 0);
      return {
        category: b.category,
        limit: b.budget_limit,
        spent,
        alert: spent >= b.budget_limit,
        warning: spent >= b.budget_limit * 0.8 && spent < b.budget_limit,
      };
    });
    res.json(alert);
  } catch (err) {
    res.status(500).json({ message: "Server error" });
  }
});

// Helper: deteksi expense
const isExpense = (t) => t.category && t.category.toLowerCase() !== "income";

// AI Insight Advanced Endpoint
app.get("/api/insight", auth, async (req, res) => {
  try {
    const now = new Date();
    const start = new Date(now.getFullYear(), now.getMonth(), 1)
      .toISOString()
      .slice(0, 10);
    const prevStart = new Date(now.getFullYear(), now.getMonth() - 1, 1)
      .toISOString()
      .slice(0, 10);
    const prevEnd = new Date(now.getFullYear(), now.getMonth(), 0)
      .toISOString()
      .slice(0, 10);
    const weekAgo = new Date(now.getTime() - 7 * 24 * 60 * 60 * 1000)
      .toISOString()
      .slice(0, 10);
    // Ambil transaksi bulan ini, bulan lalu, dan 7 hari terakhir
    const { data: txsNow } = await supabase
      .from("transactions")
      .select("*")
      .eq("user_id", req.user.userId)
      .gte("date", start);
    const { data: txsPrev } = await supabase
      .from("transactions")
      .select("*")
      .eq("user_id", req.user.userId)
      .gte("date", prevStart)
      .lte("date", prevEnd);
    const { data: txsWeek } = await supabase
      .from("transactions")
      .select("*")
      .eq("user_id", req.user.userId)
      .gte("date", weekAgo);
    // Helper: hitung total per kategori
    const sumByCat = (txs) => {
      const sum = {};
      txs?.forEach((t) => {
        if (!sum[t.category]) sum[t.category] = 0;
        sum[t.category] += t.amount;
      });
      return sum;
    };
    const nowSum = sumByCat(txsNow);
    const prevSum = sumByCat(txsPrev);
    // 1. Insight: Kategori dengan kenaikan terbesar
    let maxCat = null,
      maxInc = 0;
    for (const cat in nowSum) {
      const inc = nowSum[cat] - (prevSum[cat] || 0);
      if (inc > maxInc) {
        maxInc = inc;
        maxCat = cat;
      }
    }
    // 2. Insight: Kategori dengan penurunan terbesar
    let minCat = null,
      minDec = 0;
    for (const cat in prevSum) {
      const dec = (prevSum[cat] || 0) - (nowSum[cat] || 0);
      if (dec > minDec) {
        minDec = dec;
        minCat = cat;
      }
    }
    // 3. Prediksi pengeluaran bulan ini (berdasarkan rata-rata harian bulan ini)
    const daysPassed = Math.max(
      1,
      Math.floor((now - new Date(start)) / (1000 * 60 * 60 * 24))
    );
    const totalNow = txsNow?.reduce((a, t) => a + t.amount, 0) || 0;
    const avgPerDay = totalNow / daysPassed;
    const daysInMonth = new Date(
      now.getFullYear(),
      now.getMonth() + 1,
      0
    ).getDate();
    const predicted = Math.round(avgPerDay * daysInMonth);
    // 4. Deteksi pengeluaran besar mendadak (transaksi > 2x rata-rata mingguan, hanya expense)
    const weekTotal =
      txsWeek?.filter(isExpense).reduce((a, t) => a + t.amount, 0) || 0;
    const weekAvg =
      weekTotal / Math.max(1, txsWeek?.filter(isExpense).length || 1);
    const sudden = txsNow?.filter(
      (t) => isExpense(t) && t.amount > 2 * weekAvg
    );
    // Kumpulkan insight
    const insights = [];
    if (maxCat && maxInc > 0) {
      insights.push({
        type: "increase",
        category: maxCat,
        message: `Pengeluaran kategori ${maxCat} naik sebesar ${maxInc.toLocaleString(
          "id-ID"
        )} bulan ini dibanding bulan lalu.`,
      });
    }
    if (minCat && minDec > 0) {
      insights.push({
        type: "decrease",
        category: minCat,
        message: `Pengeluaran kategori ${minCat} turun sebesar ${minDec.toLocaleString(
          "id-ID"
        )} bulan ini dibanding bulan lalu.`,
      });
    }
    insights.push({
      type: "prediction",
      message: `Prediksi total pengeluaran bulan ini: Rp${predicted.toLocaleString(
        "id-ID"
      )}.`,
    });
    if (sudden && sudden.length > 0) {
      sudden.forEach((t) => {
        insights.push({
          type: "sudden",
          category: t.category,
          message: `Terdeteksi pengeluaran besar di kategori ${
            t.category
          }: Rp${t.amount.toLocaleString("id-ID")} pada ${t.date}.`,
        });
      });
    }
    if (insights.length === 0) {
      insights.push({
        type: "info",
        message: "Tidak ada insight signifikan bulan ini.",
      });
    }
    res.json(insights);
  } catch (err) {
    res
      .status(500)
      .json({ message: "Gagal mengambil insight", error: err.message });
  }
});

// Get user profile (email)
app.get("/api/profile", auth, async (req, res) => {
  try {
    const { data: users, error } = await supabase
      .from("users")
      .select("email")
      .eq("id", req.user.userId)
      .single();
    if (error) return res.status(400).json({ message: error.message });
    res.json(users);
  } catch (err) {
    res
      .status(500)
      .json({ message: "Gagal mengambil profil user", error: err.message });
  }
});

// GET goal user
app.get("/api/goals", auth, async (req, res) => {
  try {
    const { data, error } = await supabase
      .from("goals")
      .select("goal")
      .eq("user_id", req.user.userId)
      .single();
    if (error && error.code !== "PGRST116")
      // ignore 'no rows' error
      return res.status(400).json({ message: error.message });
    res.json({ goal: data ? data.goal : "" });
  } catch (err) {
    res.status(500).json({ message: "Server error" });
  }
});

// SET/UPDATE goal user
app.post("/api/goals", auth, async (req, res) => {
  try {
    const { goal } = req.body;
    if (!goal) return res.status(400).json({ message: "Goal required" });
    // Upsert: hapus dulu, lalu insert (karena supabase-js belum support upsert multi-key)
    await supabase.from("goals").delete().eq("user_id", req.user.userId);
    const { data, error } = await supabase
      .from("goals")
      .insert([{ user_id: req.user.userId, goal }])
      .select();
    if (error) return res.status(400).json({ message: error.message });
    res.json(data[0]);
  } catch (err) {
    res.status(500).json({ message: "Server error" });
  }
});

// Gemini AI Budget Analysis
// Simpan API key Gemini di .env, misal: GEMINI_API_KEY=xxx
const GEMINI_API_KEY = process.env.GEMINI_API_KEY;
const GEMINI_API_URL =
  "https://generativelanguage.googleapis.com/v1beta/models/gemini-2.0-flash:generateContent";

app.post("/api/ai-budget-analysis", auth, async (req, res) => {
  try {
    if (!GEMINI_API_KEY)
      return res.status(500).json({ message: "Gemini API key not set" });
    const { transactions } = req.body;
    if (
      !transactions ||
      !Array.isArray(transactions) ||
      transactions.length === 0
    ) {
      return res.status(400).json({ message: "No transactions provided" });
    }
    // Format prompt
    const prompt = `Analisa data transaksi berikut dan berikan insight budgeting dalam bahasa Indonesia. Tampilkan hasil dalam format markdown yang rapi dan terstruktur (gunakan judul, bullet, tabel jika perlu, dan penjelasan singkat).\n\nData transaksi:\n${JSON.stringify(
      transactions,
      null,
      2
    )}`;
    const response = await fetch(`${GEMINI_API_URL}?key=${GEMINI_API_KEY}`, {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify({
        contents: [{ parts: [{ text: prompt }] }],
      }),
    });
    if (!response.ok) {
      const err = await response.text();
      return res.status(500).json({ message: "Gemini API error", error: err });
    }
    const result = await response.json();
    // Ambil insight dari response Gemini
    const insight =
      result.candidates?.[0]?.content?.parts?.[0]?.text || "Tidak ada insight.";
    res.json({ insight });
  } catch (err) {
    res.status(500).json({ message: "Server error", error: err.message });
  }
});

app.get("/", (req, res) => {
  res.send("Backend is running with Supabase JS Client!");
});

module.exports = app;

if (require.main === module) {
  app.listen(PORT, () => {
    console.log(`Server running on http://localhost:${PORT}`);
  });
}
