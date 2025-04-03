const express = require('express');
const jwt = require('jsonwebtoken');
const bcrypt = require('bcryptjs');
const { Pool } = require('pg');
const { verifyToken } = require('../middleware/usersMiddleware.js');

const router = express.Router();

// Creating pool for database
const pool = new Pool({
    user: process.env.DB_USER,
    host: process.env.DB_HOST,
    database: process.env.DB_NAME,
    password: process.env.DB_PASSWORD,
    port: process.env.DB_PORT,
});

// Маршрут по умолчанию
router.get('/', (req, res) => {
    res.send('Welcome to User Service');
});

// Генерация токенов
const generateTokens = (userId) => {
    const accessToken = jwt.sign(
        { userId: userId },
        process.env.JWT_SECRET,
        { expiresIn: '1m' }
    );

    const refreshToken = jwt.sign(
        { userId: userId },
        process.env.JWT_REFRESH_SECRET,
        { expiresIn: '1h' }
    );

    return { accessToken, refreshToken };
};

// Маршрут для проверки валидности токена
router.get('/validatetoken', verifyToken, (req, res) => {
    res.status(200).json({
        success: true,
        message: 'Token is valid',
        userId: req.userId
    });
});

// Маршрут для обновления access токена
router.post('/refresh', (req, res) => {
    const refreshToken = req.cookies.refresh_cookie;

    if (!refreshToken) {
        return res.status(400).json({ success: false, message: 'Refresh token is required' });
    }

    try {
        const decoded = jwt.verify(refreshToken, process.env.JWT_REFRESH_SECRET);
        const newAccessToken = generateTokens(decoded.userId).accessToken;

        res.cookie('access_cookie', newAccessToken, {
            httpOnly: true, // Куки недоступны через JavaScript
            secure: process.env.NODE_ENV === 'production', // Только HTTPS в production
            secure: false,
            maxAge: 1 * 60 * 1000, // 1m (время жизни accessToken)
            sameSite: 'strict', // Защита от CSRF
        });

        res.status(200).json({ success: true, message: 'Access token refreshed' });
    }
    catch (error) {
        return res.status(401).json({ success: false, message: 'Invalid or expired refresh token' });
    }
});

// Регистрация пользователя
router.post('/register', async (req, res) => {
    const { login, password, name } = req.body;

    if (!login || !password || !name) {
        return res.status(400).json({ message: 'login, password and name are required' });
    }

    try {
        const user = await pool.query('SELECT * FROM users WHERE login = $1', [login]);

        if (user.rows[0]) {
            return res.status(401).json({ message: 'Пользователь уже зарегистрирован.' });
        }

        // Хеширование пароля
        const hashedPassword = await bcrypt.hash(password, 10);

        // Сохранение пользователя в базе данных
        const result = await pool.query(
            'INSERT INTO users (login, password, name) VALUES ($1, $2, $3) RETURNING id',
            [login, hashedPassword, name]
        );

        const newUser = result.rows[0];

        // Создание JWT
        const { accessToken, refreshToken } = generateTokens(newUser.id);

        // Установка токенов в куки
        res.cookie('access_cookie', accessToken, {
            httpOnly: true, // Куки недоступны через JavaScript
            secure: process.env.NODE_ENV === 'production', // Только HTTPS в production
            secure: false,
            maxAge: 1 * 60 * 1000, // 1m (время жизни accessToken)
            sameSite: 'strict', // Защита от CSRF
        });

        res.cookie('refresh_cookie', refreshToken, {
            httpOnly: true,
            secure: process.env.NODE_ENV === 'production',
            secure: false,
            maxAge: 60 * 60 * 1000, // 1h (время жизни refreshToken)
            sameSite: 'strict',
        });

        res.status(201).json({
            success: true,
            message: "successful register",
            userId: newUser.id
        });
    } catch (error) {
        // if (error.code === '23505') {
        //     res.status(400).json({ message: 'login already exists' });
        // } 
        console.error('Ошибка при регистрации пользователя', error);
        res.status(500).json({ message: 'Ошибка сервера.' });
    }
});

// Вход пользователя
router.post('/login', async (req, res) => {
    const { login, password } = req.body;

    if (!login || !password) {
        return res.status(400).json({ success: false, message: 'login and password are required' });
    }

    try {
        // Поиск пользователя в базе данных
        const result = await pool.query('SELECT * FROM users WHERE login = $1', [login]);
        const user = result.rows[0];

        if (!user) {
            return res.status(401).json({ success: false, message: 'Пользователь не найден.' });
        }

        // Проверка пароля
        const isPasswordValid = await bcrypt.compare(password, user.password);
        if (!isPasswordValid) {
            return res.status(401).json({ success: false, message: 'Неверный пароль.' });
        }

        // Генерация токенов
        const { accessToken, refreshToken } = generateTokens(user.id);

        // Установка токенов в куки
        res.cookie('access_cookie', accessToken, {
            httpOnly: true, // Куки недоступны через JavaScript
            secure: process.env.NODE_ENV === 'production', // Только HTTPS в production
            secure: false,
            maxAge: 1 * 60 * 1000, // 1m (время жизни accessToken)
            sameSite: 'strict', // Защита от CSRF
        });

        res.cookie('refresh_cookie', refreshToken, {
            httpOnly: true,
            secure: process.env.NODE_ENV === 'production',
            secure: false,
            maxAge: 60 * 60 * 1000, // 1h (время жизни refreshToken)
            sameSite: 'strict',
        });

        res.status(200).json({
            success: true,
            message: "successful logging in",
            userId: user.id
        });
    } catch (error) {
        console.error("Ошибка при авторизации пользователя", error);
        res.status(500).json({ success: false, message: 'Ошибка сервера.' });
    }
});

// Получение информации о пользователе
router.get('/data/:id', async (req, res) => {
    const userId = req.params.id;

    if (!userId) {
        return res.status(400).json({ message: 'user ID is required' });
    }

    if (isNaN(userId)) {
        return res.status(400).json({ message: 'user ID must be a number' });
    }

    try {
        // Поиск пользователя в базе данных
        const result = await pool.query('SELECT id, login, password, name FROM users WHERE id = $1', [userId]);

        if (result.rows.length === 0) {
            // Если пользователь не найден
            return res.status(404).json({ message: 'user not found' });
        }

        const user = result.rows[0];

        res.status(200).json(user);

    } catch (error) {
        console.error('Ошибка при получении данных пользователя:', error);
        res.status(500).json({ message: 'Ошибка сервера.' });
    }
});

router.get('/all', async (req, res) => {
    try {
        // Запрос к базе данных для получения всех пользователей
        const result = await pool.query('SELECT * FROM users');

        // Возврат списка пользователей
        res.status(200).json({
            count: result.rows.length,
            users: result.rows
        });
    } catch (error) {
        console.error('Ошибка при получении списка пользователей:', error);
        res.status(500).json({ message: 'Ошибка сервера.' });
    }
})

// 
router.get('/exists/:id', async (req, res) => {
    const userId = req.params.id;

    try {
        const user = await pool.query('SELECT id FROM users WHERE id = $1', [userId]);
        if (user.rows.length === 0) {
            return res.json({ exists: false });
        } else {
            res.json({ exists: true });
        }
    } catch (error) {
        console.error(error);
        res.status(500).json({ message: 'internal server error' });
    }
});

router.post('/signout', async (req, res) => {
    try {
        // Удаляем куки access_cookie и refresh_cookie
        res.clearCookie('access_cookie', {
            httpOnly: true,
            secure: process.env.NODE_ENV === 'production',
            secure: false,
            sameSite: 'strict',
        });

        res.clearCookie('refresh_cookie', {
            httpOnly: true,
            secure: process.env.NODE_ENV === 'production',
            secure: false,
            sameSite: 'strict',
        });

        // Отправляем успешный ответ
        res.status(200).json({ success: true, message: 'Вы успешно вышли из системы' });

    }
    catch (error) {
        console.error('Ошибка при выходе:', error);
        res.status(500).json({ message: 'Ошибка при выходе из системы' });
    }
});

module.exports = router;