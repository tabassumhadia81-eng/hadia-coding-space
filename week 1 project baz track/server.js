const express = require("express");
const path = require("path");
const Database = require("better-sqlite3");
const bcrypt = require("bcryptjs");
const jwt = require("jsonwebtoken");

const app = express();
const PORT = 3000;
app.use(express.static(path.join(__dirname, "..")));


const JWT_SECRET = "biztrack-development-secret";

const db = new Database("biztrack.db");

db.pragma("foreign_keys = ON");

db.exec(`
CREATE TABLE IF NOT EXISTS users (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    name TEXT NOT NULL,
    email TEXT NOT NULL UNIQUE,
    password TEXT NOT NULL
);

CREATE TABLE IF NOT EXISTS products (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    name TEXT NOT NULL,
    category TEXT NOT NULL,
    price REAL NOT NULL,
    stock INTEGER NOT NULL DEFAULT 0
);

CREATE TABLE IF NOT EXISTS customers (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    name TEXT NOT NULL,
    email TEXT NOT NULL,
    phone TEXT NOT NULL,
    address TEXT
);

CREATE TABLE IF NOT EXISTS sales (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    invoice TEXT NOT NULL UNIQUE,
    customer_id INTEGER NOT NULL,
    product_id INTEGER NOT NULL,
    qty INTEGER NOT NULL,
    total REAL NOT NULL,
    date TEXT NOT NULL,
    FOREIGN KEY(customer_id) REFERENCES customers(id),
    FOREIGN KEY(product_id) REFERENCES products(id)
);

CREATE TABLE IF NOT EXISTS expenses (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    title TEXT NOT NULL,
    category TEXT NOT NULL,
    amount REAL NOT NULL,
    date TEXT NOT NULL
);
`);

app.use(express.json());

function auth(req, res, next) {

    const header = req.headers.authorization || "";

    const token = header.startsWith("Bearer ")
        ? header.slice(7)
        : null;

    if (!token) {
        return res.status(401).json({
            message: "Login required"
        });
    }

    try {

        req.user = jwt.verify(token, JWT_SECRET);

        next();

    } catch {

        res.status(401).json({
            message: "Invalid or expired token"
        });

    }
}


/* =========================
   SIGN UP
========================= */

app.post("/api/auth/signup", async (req, res) => {

    const { name, email, password } = req.body;

    if (!name || !email || !password) {

        return res.status(400).json({
            message: "All fields are required"
        });

    }

    if (password.length < 6) {

        return res.status(400).json({
            message: "Password must be at least 6 characters"
        });

    }

    try {

        const hashedPassword = await bcrypt.hash(password, 10);

        const result = db.prepare(`
            INSERT INTO users (name, email, password)
            VALUES (?, ?, ?)
        `).run(
            name.trim(),
            email.toLowerCase().trim(),
            hashedPassword
        );

        const user = {
            id: result.lastInsertRowid,
            name: name.trim(),
            email: email.toLowerCase().trim()
        };

        const token = jwt.sign(
            user,
            JWT_SECRET,
            { expiresIn: "2h" }
        );

        res.json({
            message: "Account created successfully",
            token,
            user
        });

    } catch (error) {

        if (String(error).includes("UNIQUE")) {

            return res.status(409).json({
                message: "Email already registered"
            });

        }

        res.status(500).json({
            message: "Server error"
        });

    }

});


/* =========================
   LOGIN
========================= */

app.post("/api/auth/login", async (req, res) => {

    const email = (req.body.email || "")
        .toLowerCase()
        .trim();

    const password = req.body.password || "";

    const user = db.prepare(`
        SELECT * FROM users
        WHERE email = ?
    `).get(email);

    if (!user) {

        return res.status(401).json({
            message: "Invalid email or password"
        });

    }

    const passwordCorrect =
        await bcrypt.compare(password, user.password);

    if (!passwordCorrect) {

        return res.status(401).json({
            message: "Invalid email or password"
        });

    }

    const safeUser = {
        id: user.id,
        name: user.name,
        email: user.email
    };

    const token = jwt.sign(
        safeUser,
        JWT_SECRET,
        { expiresIn: "2h" }
    );

    res.json({
        message: "Login successful",
        token,
        user: safeUser
    });

});


/* =========================
   CURRENT USER
========================= */

app.get("/api/me", auth, (req, res) => {

    res.json({
        user: req.user
    });

});


/* =========================
   PRODUCTS
========================= */

app.get("/api/products", auth, (req, res) => {

    const products = db.prepare(`
        SELECT * FROM products
        ORDER BY id DESC
    `).all();

    res.json(products);

});


app.post("/api/products", auth, (req, res) => {

    const {
        name,
        category,
        price,
        stock
    } = req.body;

    if (
        !name ||
        !category ||
        Number(price) < 0 ||
        Number(stock) < 0
    ) {

        return res.status(400).json({
            message: "Invalid product data"
        });

    }

    const result = db.prepare(`
        INSERT INTO products
        (name, category, price, stock)
        VALUES (?, ?, ?, ?)
    `).run(
        name,
        category,
        Number(price),
        Number(stock)
    );

    res.json({
        message: "Product added",
        id: result.lastInsertRowid
    });

});


app.put("/api/products/:id", auth, (req, res) => {

    const {
        name,
        category,
        price,
        stock
    } = req.body;

    const result = db.prepare(`
        UPDATE products
        SET name = ?,
            category = ?,
            price = ?,
            stock = ?
        WHERE id = ?
    `).run(
        name,
        category,
        Number(price),
        Number(stock),
        req.params.id
    );

    if (!result.changes) {

        return res.status(404).json({
            message: "Product not found"
        });

    }

    res.json({
        message: "Product updated"
    });

});


app.delete("/api/products/:id", auth, (req, res) => {

    const result = db.prepare(`
        DELETE FROM products
        WHERE id = ?
    `).run(req.params.id);

    if (!result.changes) {

        return res.status(404).json({
            message: "Product not found"
        });

    }

    res.json({
        message: "Product deleted"
    });

});


/* =========================
   CUSTOMERS
========================= */

app.get("/api/customers", auth, (req, res) => {

    const customers = db.prepare(`
        SELECT * FROM customers
        ORDER BY id DESC
    `).all();

    res.json(customers);

});


app.post("/api/customers", auth, (req, res) => {

    const {
        name,
        email,
        phone,
        address
    } = req.body;

    if (!name || !email || !phone) {

        return res.status(400).json({
            message: "Name, email and phone are required"
        });

    }

    const result = db.prepare(`
        INSERT INTO customers
        (name, email, phone, address)
        VALUES (?, ?, ?, ?)
    `).run(
        name,
        email,
        phone,
        address || ""
    );

    res.json({
        message: "Customer added",
        id: result.lastInsertRowid
    });

});


/* =========================
   SALES
========================= */

app.get("/api/sales", auth, (req, res) => {

    const sales = db.prepare(`
        SELECT
            sales.*,
            customers.name AS customerName,
            products.name AS productName
        FROM sales
        JOIN customers
            ON customers.id = sales.customer_id
        JOIN products
            ON products.id = sales.product_id
        ORDER BY sales.id DESC
    `).all();

    res.json(sales);

});


app.post("/api/sales", auth, (req, res) => {

    const customerId = Number(req.body.customerId);
    const productId = Number(req.body.productId);
    const qty = Number(req.body.qty);

    const customer = db.prepare(`
        SELECT * FROM customers
        WHERE id = ?
    `).get(customerId);

    const product = db.prepare(`
        SELECT * FROM products
        WHERE id = ?
    `).get(productId);

    if (!customer || !product || qty < 1) {

        return res.status(400).json({
            message: "Invalid sale data"
        });

    }

    if (product.stock < qty) {

        return res.status(400).json({
            message: "Not enough stock"
        });

    }

    const total = product.price * qty;

    const invoice =
        "INV-" +
        Date.now().toString().slice(-8);

    const date =
        new Date().toISOString().slice(0, 10);

    const transaction = db.transaction(() => {

        db.prepare(`
            UPDATE products
            SET stock = stock - ?
            WHERE id = ?
        `).run(qty, productId);

        db.prepare(`
            INSERT INTO sales
            (
                invoice,
                customer_id,
                product_id,
                qty,
                total,
                date
            )
            VALUES (?, ?, ?, ?, ?, ?)
        `).run(
            invoice,
            customerId,
            productId,
            qty,
            total,
            date
        );

    });

    transaction();

    res.json({
        message: "Sale created",
        invoice
    });

});


/* =========================
   EXPENSES
========================= */

app.get("/api/expenses", auth, (req, res) => {

    const expenses = db.prepare(`
        SELECT * FROM expenses
        ORDER BY id DESC
    `).all();

    res.json(expenses);

});


app.post("/api/expenses", auth, (req, res) => {

    const {
        title,
        category,
        amount,
        date
    } = req.body;

    if (
        !title ||
        !category ||
        Number(amount) <= 0
    ) {

        return res.status(400).json({
            message: "Invalid expense data"
        });

    }

    const result = db.prepare(`
        INSERT INTO expenses
        (title, category, amount, date)
        VALUES (?, ?, ?, ?)
    `).run(
        title,
        category,
        Number(amount),
        date || new Date().toISOString().slice(0, 10)
    );

    res.json({
        message: "Expense added",
        id: result.lastInsertRowid
    });

});


/* =========================
   REPORTS
========================= */

app.get("/api/reports", auth, (req, res) => {

    const sales = db.prepare(`
        SELECT COALESCE(SUM(total), 0) AS total
        FROM sales
    `).get().total;

    const expenses = db.prepare(`
        SELECT COALESCE(SUM(amount), 0) AS total
        FROM expenses
    `).get().total;

    const products = db.prepare(`
        SELECT COUNT(*) AS total
        FROM products
    `).get().total;

    const customers = db.prepare(`
        SELECT COUNT(*) AS total
        FROM customers
    `).get().total;

    const lowStock = db.prepare(`
        SELECT COUNT(*) AS total
        FROM products
        WHERE stock <= 10
    `).get().total;

    res.json({
        sales,
        expenses,
        profit: sales - expenses,
        products,
        customers,
        lowStock
    });

});


/* =========================
   START SERVER
========================= */

app.listen(PORT, () => {

    console.log(
        `BizTrack server running at http://localhost:${PORT}`
    );

});