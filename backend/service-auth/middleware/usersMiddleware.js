// Middleware

const jwt = require('jsonwebtoken');

const verifyToken = (req, res, next) => {
    const accessToken = req.cookies.access_cookie;

    if (!accessToken) {
        return res.status(401).json({ success: false, error: 'access token is required' });
    }

    try {
        const decoded = jwt.verify(accessToken, process.env.JWT_SECRET);
        req.userId = decoded.userId;
        next();
    } catch (error) {
        console.log("Ошибка во время проверки токена")
        return res.status(401).json({ success: false, error: 'invalid or expired access token' });
    }
};

module.exports = { verifyToken };