const path = require("path");
require("dotenv").config({ path: path.resolve(__dirname, ".env") });
const express = require("express");
const cors = require("cors");
const morgan = require("morgan");
const app = express();
const PORT = process.env.PORT || 3001;
const { createClient } = require("@supabase/supabase-js");
const jwt = require("jsonwebtoken");
const bcrypt = require("bcryptjs");
const axios = require("axios");

const supabaseUrl = process.env.SUPABASE_URL;
const supabaseKey = process.env.SUPABASE_ANON_KEY;
const supabase = createClient(supabaseUrl, supabaseKey);
const JWT_SECRET = process.env.JWT_SECRET || "aabbccddee1122334455667788991122";
const AI_SERVICE_URL = process.env.AI_SERVICE_URL || "http://localhost:5000";

// Middleware
app.use(morgan("dev"));
app.use(express.json());
app.use(
  cors({
    origin: "*", // Izinkan semua origin (bisa diganti dengan URL frontend Anda)
    methods: ["GET", "POST", "PUT", "DELETE"], // Izinkan metode DELETE
    allowedHeaders: ["Content-Type", "Authorization"], // Izinkan header Authorization
  })
);

// Middleware Error Handling Terpusat
const errorHandler = (err, req, res, next) => {
  console.error("==================== ERROR ====================");
  console.error("Timestamp:", new Date().toISOString());
  console.error("Route:", `${req.method} ${req.originalUrl}`);
  console.error("Body:", JSON.stringify(req.body, null, 2));
  console.error("Error Message:", err.message);
  console.error("Error Stack:", err.stack);
  console.error("==============================================");

  // Jangan kirim stack trace ke client di production
  const status = err.statusCode || 500;
  const message = err.message || "Internal Server Error";
  res.status(status).json({
    message,
    // Hanya sertakan stack di environment development
    ...(process.env.NODE_ENV === "development" && { stack: err.stack }),
  });
};

// Register
app.post("/api/register", async (req, res, next) => {
  const {
    email,
    password,
    nama,
    umur,
    tempat_tinggal,
    status_pernikahan,
    tipe_tempat_tinggal,
    biaya_tanggungan,
    punya_kendaraan,
    nomor_wa,
    gaji_per_bulan,
  } = req.body;

  try {
    // 1. Buat user baru di Supabase Auth
    const { data: authData, error: authError } = await supabase.auth.signUp({
      email,
      password,
    });

    if (authError) {
      throw new Error(authError.message);
    }
    if (!authData.user) {
      throw new Error("Registration failed: user not created.");
    }

    const userId = authData.user.id;

    // 2. Update data di tabel 'profiles' yang sudah otomatis dibuat oleh trigger
    const { error: profileError } = await supabase
      .from("profiles")
      .update({
        nama,
        umur,
        tempat_tinggal,
        status_pernikahan,
        tipe_tempat_tinggal,
        biaya_tanggungan,
        punya_kendaraan,
        nomor_wa,
        gaji_per_bulan,
        updated_at: new Date(),
      })
      .eq("id", userId);

    if (profileError) {
      // Jika update profil gagal, coba hapus user yang sudah terlanjur dibuat
      await supabase.auth.admin.deleteUser(userId);
      throw new Error(`Failed to update profile: ${profileError.message}`);
    }

    res.status(201).json({ message: "User registered successfully" });
  } catch (err) {
    next(err); // Kirim error ke middleware terpusat
  }
});

// Login
app.post("/api/login", async (req, res, next) => {
  const { email, password } = req.body;
  try {
    const { data, error } = await supabase.auth.signInWithPassword({
      email,
      password,
    });

    if (error) {
      const err = new Error(error.message || "Invalid credentials");
      err.statusCode = 400;
      return next(err);
    }

    if (!data.session) {
      const err = new Error("Login failed, no session returned.");
      err.statusCode = 401;
      return next(err);
    }

    res.json({ token: data.session.access_token });
  } catch (err) {
    next(err); // Kirim error ke middleware terpusat
  }
});

// Middleware Otentikasi
async function auth(req, res, next) {
  const authHeader = req.headers.authorization;
  if (!authHeader || !authHeader.startsWith("Bearer ")) {
    const err = new Error("No token provided or invalid format.");
    err.statusCode = 401;
    return next(err);
  }

  const token = authHeader.split(" ")[1];
  try {
    const {
      data: { user },
      error,
    } = await supabase.auth.getUser(token);

    if (error || !user) {
      const err = new Error("Invalid or expired token.");
      err.statusCode = 401;
      return next(err);
    }

    // Attach the full user object for more flexibility
    // and add userId for backward compatibility with existing code.
    req.user = user;
    req.user.userId = user.id;
    next();
  } catch (err) {
    next(err);
  }
}

// == RUTE TERPROTEKSI (Memerlukan Otentikasi) ==
const apiRouter = express.Router();
apiRouter.use(auth);

// CREATE transaksi (integrasi AI classify)
apiRouter.post("/transactions", async (req, res, next) => {
  try {
    let { amount, category, source, date, note, description, expense_type } =
      req.body;
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
        source: source || "",
        date,
        note: description,
        expense_type, // Tambahkan di sini
      },
    ]);
    if (error) throw error;
    res.status(201).json({ message: "Transaction created" });
  } catch (err) {
    next(err);
  }
});

// READ (list) transaksi user (filter kategori/tanggal opsional)
apiRouter.get("/transactions", async (req, res, next) => {
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
    if (error) throw error;
    res.json(data);
  } catch (err) {
    next(err);
  }
});

// UPDATE transaksi
apiRouter.put("/transactions/:id", async (req, res, next) => {
  try {
    const { id } = req.params;
    const { amount, category, source, date, note, expense_type } = req.body;
    const { data, error } = await supabase
      .from("transactions")
      .update({ amount, category, source, date, note, expense_type }) // Tambahkan di sini
      .eq("id", id)
      .eq("user_id", req.user.userId)
      .select();
    if (error) throw error;
    if (!data || data.length === 0)
      return res.status(404).json({ message: "Not found" });
    res.json(data[0]);
  } catch (err) {
    next(err);
  }
});

// DELETE transaksi
apiRouter.delete("/transactions/:id", async (req, res, next) => {
  try {
    const { id } = req.params;
    const { data, error } = await supabase
      .from("transactions")
      .delete()
      .eq("id", id)
      .eq("user_id", req.user.userId)
      .select();
    if (error) throw error;
    if (!data || data.length === 0)
      return res.status(404).json({ message: "Not found" });
    res.json({ message: "Deleted" });
  } catch (err) {
    next(err);
  }
});

// DELETE SEMUA transaksi user
apiRouter.delete("/transactions/all", async (req, res, next) => {
  try {
    console.log("[Handler] Entered /api/transactions/all logic.");
    // Langkah 1: Dapatkan semua ID transaksi milik user
    const { data: transactions, error: selectError } = await supabase
      .from("transactions")
      .select("id")
      .eq("user_id", req.user.userId);

    if (selectError) throw selectError;

    if (!transactions || transactions.length === 0) {
      return res.json({ message: "No transactions to delete." });
    }

    const transactionIds = transactions.map((tx) => tx.id);

    // Langkah 2: Hapus transaksi berdasarkan ID yang didapat
    const { error: deleteError } = await supabase
      .from("transactions")
      .delete()
      .in("id", transactionIds);

    if (deleteError) throw deleteError;

    res.json({ message: "All transactions deleted" });
  } catch (err) {
    next(err);
  }
});

// GET semua budget setting user
apiRouter.get("/budgets", async (req, res, next) => {
  try {
    const { data, error } = await supabase
      .from("budget_settings")
      .select("*")
      .eq("user_id", req.user.userId);
    if (error) throw error;
    res.json(data);
  } catch (err) {
    next(err);
  }
});

// SET/UPDATE budget setting per kategori
apiRouter.post("/budgets", async (req, res, next) => {
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
    if (error) throw error;
    res.json(data[0]);
  } catch (err) {
    next(err);
  }
});

// ALERT: cek jika pengeluaran kategori bulan ini melebihi limit
apiRouter.get("/budgets/alert", async (req, res, next) => {
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
    if (err1 || err2) throw err1 || err2;
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
    next(err);
  }
});

// Helper: deteksi expense
const isExpense = (t) => t.category && t.category.toLowerCase() !== "income";

// AI Insight Advanced Endpoint
apiRouter.get("/insight", async (req, res, next) => {
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
    next(err);
  }
});

// Get user profile (email)
apiRouter.get("/profile", async (req, res, next) => {
  try {
    // The auth middleware now attaches the full user object.
    // We can get the email directly from it.
    if (!req.user || !req.user.email) {
      const err = new Error("User email not found in authentication token.");
      err.statusCode = 404;
      return next(err);
    }
    res.json({ email: req.user.email });
  } catch (err) {
    next(err);
  }
});

// GET goal user
apiRouter.get("/goals", async (req, res, next) => {
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
    next(err);
  }
});

// SET/UPDATE goal user
apiRouter.post("/goals", async (req, res, next) => {
  try {
    const { goal } = req.body;
    if (!goal) return res.status(400).json({ message: "Goal required" });
    // Upsert: hapus dulu, lalu insert (karena supabase-js belum support upsert multi-key)
    await supabase.from("goals").delete().eq("user_id", req.user.userId);
    const { data, error } = await supabase
      .from("goals")
      .insert([{ user_id: req.user.userId, goal }])
      .select();
    if (error) throw error;
    res.json(data[0]);
  } catch (err) {
    next(err);
  }
});

// CRUD for Payment Sources
apiRouter
  .route("/payment-sources")
  .get(async (req, res, next) => {
    try {
      const { data, error } = await supabase
        .from("payment_sources")
        .select("*")
        .eq("user_id", req.user.userId)
        .order("created_at", { ascending: true });
      if (error) throw error;
      res.json(data);
    } catch (err) {
      next(err);
    }
  })
  .post(async (req, res, next) => {
    try {
      const { name, type } = req.body;
      if (!name) {
        return res.status(400).json({ message: "Name is required" });
      }
      const { data, error } = await supabase
        .from("payment_sources")
        .insert([{ user_id: req.user.userId, name, type }])
        .select()
        .single();
      if (error) throw error;
      res.status(201).json(data);
    } catch (err) {
      next(err);
    }
  });

apiRouter
  .route("/payment-sources/:id")
  .put(async (req, res, next) => {
    try {
      const { id } = req.params;
      const { name, type } = req.body;
      if (!name) {
        return res.status(400).json({ message: "Name is required" });
      }
      const { data, error } = await supabase
        .from("payment_sources")
        .update({ name, type })
        .eq("id", id)
        .eq("user_id", req.user.userId)
        .select()
        .single();
      if (error) throw error;
      if (!data) return res.status(404).json({ message: "Not found" });
      res.json(data);
    } catch (err) {
      next(err);
    }
  })
  .delete(async (req, res, next) => {
    try {
      const { id } = req.params;
      const { data, error } = await supabase
        .from("payment_sources")
        .delete()
        .eq("id", id)
        .eq("user_id", req.user.userId)
        .select()
        .single();
      if (error) throw error;
      if (!data) return res.status(404).json({ message: "Not found" });
      res.status(204).send(); // No Content
    } catch (err) {
      next(err);
    }
  });

// Get/Update User Profile Details
apiRouter
  .route("/profile-details")
  .get(async (req, res, next) => {
    try {
      const { data, error } = await supabase
        .from("profiles")
        .select("*")
        .eq("id", req.user.userId)
        .single();

      if (error) throw error;

      // Gabungkan dengan email dari auth user
      const profileData = { ...data, email: req.user.email };
      res.json(profileData);
    } catch (err) {
      next(err);
    }
  })
  .put(async (req, res, next) => {
    const { userId } = req.user;
    const {
      nama,
      umur,
      tempat_tinggal,
      status_pernikahan,
      tipe_tempat_tinggal,
      biaya_tanggungan,
      punya_kendaraan,
      nomor_wa,
      gaji_per_bulan,
    } = req.body;

    try {
      const { data, error } = await supabase
        .from("profiles")
        .update({
          nama,
          umur,
          tempat_tinggal,
          status_pernikahan,
          tipe_tempat_tinggal,
          biaya_tanggungan,
          punya_kendaraan,
          nomor_wa,
          gaji_per_bulan,
          updated_at: new Date(),
        })
        .eq("id", userId)
        .select()
        .single();

      if (error) throw error;

      res.json(data);
    } catch (err) {
      next(err);
    }
  });

// Gemini AI Budget Analysis
// Simpan API key Gemini di .env, misal: GEMINI_API_KEY=xxx
const GEMINI_API_KEY = process.env.GEMINI_API_KEY;
const GEMINI_API_URL =
  "https://generativelanguage.googleapis.com/v1beta/models/gemini-2.0-flash:generateContent";

apiRouter.post("/ai-budget-analysis", async (req, res, next) => {
  try {
    if (!GEMINI_API_KEY) {
      const err = new Error("Gemini API key not set");
      err.statusCode = 500;
      throw err;
    }
    const { transactions } = req.body;
    if (
      !transactions ||
      !Array.isArray(transactions) ||
      transactions.length === 0
    ) {
      const err = new Error("No transactions provided");
      err.statusCode = 400;
      throw err;
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
      const errorText = await response.text();
      const err = new Error(`Gemini API error: ${errorText}`);
      err.statusCode = 500;
      throw err;
    }
    const result = await response.json();
    // Ambil insight dari response Gemini
    const insight =
      result.candidates?.[0]?.content?.parts?.[0]?.text || "Tidak ada insight.";
    res.json({ insight });
  } catch (err) {
    next(err);
  }
});

// AI Budget Plan Generator
apiRouter.post("/generate-budget", async (req, res, next) => {
  const { prompt } = req.body;
  const userId = req.user.userId;

  if (!prompt) {
    const err = new Error("Prompt is required");
    err.statusCode = 400;
    return next(err);
  }

  try {
    // 1. Ambil profil user untuk konteks tambahan
    const { data: profile, error: profileError } = await supabase
      .from("profiles")
      .select("*")
      .eq("id", userId)
      .single();

    if (profileError || !profile) {
      const err = new Error("Could not find user profile to create budget.");
      err.statusCode = 404;
      return next(err);
    }

    // 2. Format prompt yang lebih kaya untuk AI
    const detailedPrompt = `
      User Profile:
      - Gaji per bulan: ${new Intl.NumberFormat("id-ID", {
        style: "currency",
        currency: "IDR",
      }).format(profile.gaji_per_bulan)}
      - Status: ${profile.status_pernikahan}
      - Biaya Tanggungan: ${profile.biaya_tanggungan}
      - Tempat Tinggal: ${profile.tipe_tempat_tinggal}
      - Punya Kendaraan: ${profile.punya_kendaraan ? "Ya" : "Tidak"}

      User Request: "${prompt}"

      Based on the user profile and request above, please provide a monthly budget allocation plan.
      The output MUST be a valid JSON array of objects. Each object must have three keys:
      1. "kategori" (string): The budget category.
      2. "jumlah" (number): The allocated amount.
      3. "tipe" (string): The expense type, which must be either 'tetap' for fixed expenses or 'variabel' for variable expenses.

      Do not include any explanation or introductory text outside of the JSON array.
    `;

    // 3. Panggil AI Service (Flask)
    const aiResponse = await axios.post(`${AI_SERVICE_URL}/generate-plan`, {
      prompt: detailedPrompt,
    });

    // Pastikan respons dari AI adalah array
    if (!Array.isArray(aiResponse.data)) {
      throw new Error("Invalid response format from AI service.");
    }

    const budgetPlan = aiResponse.data;

    // 4. (Opsional, tapi direkomendasikan) Simpan hasil ke database
    const now = new Date();
    const budgetRecords = budgetPlan.map((item) => ({
      user_id: userId,
      kategori: item.kategori,
      jumlah: item.jumlah,
      bulan: now.getMonth() + 1, // Bulan (1-12)
      tahun: now.getFullYear(),
    }));

    const { error: insertError } = await supabase
      .from("generated_budgets")
      .insert(budgetRecords);

    if (insertError) {
      // Tidak melempar error fatal jika hanya gagal menyimpan, tapi catat di log
      console.error("Failed to save generated budget:", insertError.message);
    }

    // 5. Kirim hasil kembali ke frontend
    res.json(budgetPlan);
  } catch (err) {
    // Tangani error dari axios atau lainnya
    if (axios.isAxiosError(err)) {
      console.error("AI Service Error:", err.response?.data);
      const newErr = new Error("Failed to get response from AI service.");
      newErr.statusCode = err.response?.status || 500;
      return next(newErr);
    }
    next(err);
  }
});

// Save Generated Budget Plan
apiRouter.post("/save-budget-plan", async (req, res, next) => {
  try {
    const { plan } = req.body;
    const { userId } = req.user;

    // Defensive check: Pastikan userId ada
    if (!userId) {
      const err = new Error("Authentication error: User ID is missing.");
      err.statusCode = 401; // Unauthorized
      return next(err);
    }

    if (!plan || !Array.isArray(plan)) {
      const err = new Error("Invalid budget plan data.");
      err.statusCode = 400;
      return next(err);
    }

    // 1. Hapus semua pengaturan budget yang ada untuk user ini agar tidak tumpang tindih
    const { error: deleteError } = await supabase
      .from("budget_settings")
      .delete()
      .eq("user_id", userId);

    if (deleteError) {
      throw new Error(`Failed to clear old budget: ${deleteError.message}`);
    }

    // 2. Format data baru dan sisipkan
    const dataToInsert = plan.map((item) => ({
      user_id: userId,
      category: item.kategori,
      budget_limit: item.jumlah,
      expense_type: item.tipe,
    }));

    const { error: insertError } = await supabase
      .from("budget_settings")
      .insert(dataToInsert);

    if (insertError) {
      throw new Error(`Failed to save budget plan: ${insertError.message}`);
    }

    res.status(200).json({ message: "Budget plan saved successfully." });
  } catch (err) {
    next(err);
  }
});

// DELETE SEMUA DATA USER (TRANSACTIONS, BUDGETS, GOALS)
apiRouter.delete("/user-data/all", async (req, res, next) => {
  try {
    const userId = req.user.userId;

    // 1. Hapus semua transaksi
    const { error: txError } = await supabase
      .from("transactions")
      .delete()
      .eq("user_id", userId);

    if (txError) {
      throw new Error(`Failed to delete transactions: ${txError.message}`);
    }

    // 2. Hapus semua pengaturan budget
    const { error: budgetError } = await supabase
      .from("budget_settings")
      .delete()
      .eq("user_id", userId);

    if (budgetError) {
      throw new Error(
        `Failed to delete budget settings: ${budgetError.message}`
      );
    }

    // 3. Hapus semua goals
    const { error: goalError } = await supabase
      .from("goals")
      .delete()
      .eq("user_id", userId);

    if (goalError) {
      throw new Error(`Failed to delete goals: ${goalError.message}`);
    }

    res.json({ message: "All user data has been successfully deleted." });
  } catch (err) {
    next(err);
  }
});

// Gunakan router untuk semua rute API yang terproteksi
app.use("/api", apiRouter);

// Handler untuk rute tidak ditemukan (404)
app.use((req, res, next) => {
  const error = new Error(`Not Found - ${req.originalUrl}`);
  error.statusCode = 404;
  next(error);
});

// Terapkan middleware error handling sebagai middleware terakhir
app.use(errorHandler);

app.get("/", (req, res) => {
  res.send("Backend is running with Supabase JS Client!");
});

module.exports = app;

if (require.main === module) {
  app.listen(PORT, () => {
    console.log(`Server running on http://localhost:${PORT}`);
  });
}
