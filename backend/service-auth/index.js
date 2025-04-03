require('dotenv').config();
const express = require('express');
const usersRoutes = require('./routes/usersRoutes');
const cors = require('cors');
const bodyParser = require('body-parser');
const cookieParser = require('cookie-parser');

const app = express();
app.use(bodyParser.json());
app.use(cookieParser());
app.use(cors(
    {
        // Заменить этот домен на адрес frontend
        origin: 'http://192.168.0.15:4000', // Разрешить запросы с frontned
        methods: ['GET', 'POST', 'PUT', 'DELETE'], // Разрешенные HTTP-методы
        credentials: true, // Разрешить отправку учётных данных
    }
));

// Подключение маршрутов
app.use('/api/users', usersRoutes);

// Запуск сервера
const PORT = process.env.PORT;
const BASE_URL = process.env.BASE_URL;
const server = app.listen(PORT, BASE_URL, () => {
    console.log(`User Service running on url ${BASE_URL}:${PORT}/api/users`);
});

// Функция для закрытия сервера
const closeServer = () => {
    server.close(() => {
        console.log('User Service closed.');
        process.exit(0); // Завершение процесса Node.js
    });
};

// Закрытие сервера при нажатии Ctrl+C (для тестирования)
process.on('SIGINT', () => {
    closeServer();
});