import jwt from "jsonwebtoken";

export function isAuthenticated(req, res, next) {
    const token = req.headers["x-auth-token"]
    console.log('tokencheck', token);
    if (!token) {
        return res.status(400).json({ message: "Invalid Authorization" })
    }
    jwt.verify(token, process.env.SECURE_KEY);
    next();
}