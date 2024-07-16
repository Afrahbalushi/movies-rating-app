const express = require('express');
const bodyParser = require('body-parser');
const axios = require('axios');
const { Sequelize, DataTypes } = require('sequelize');
const passport = require('passport');
const passportJWT = require('passport-jwt');
const jwt = require('jsonwebtoken');
const bcrypt = require('bcrypt');
const moment = require('moment');

const app = express();
app.use(bodyParser.json());
app.use(bodyParser.urlencoded({ extended: true }));

const sequelize = new Sequelize('moviesDB', 'sa', 'root', {
    host: 'localhost',
    dialect: 'mssql'
});

const User = sequelize.define('User', {
    username: {
        type: DataTypes.STRING,
        unique: true,
        allowNull: false
    },
    password: {
        type: DataTypes.STRING,
        allowNull: false
    }
}, { timestamps: true });

User.beforeCreate(async (user) => {
    const salt = await bcrypt.genSalt(10);
    user.password = await bcrypt.hash(user.password, salt);
});

const Movie = sequelize.define('Movie', {
    name: {
        type: DataTypes.STRING,
        allowNull: false
    },
    description: {
        type: DataTypes.TEXT,
        allowNull: false
    },
    release_date: {
        type: DataTypes.DATE,
        allowNull: true
    },
    main_cast: {
        type: DataTypes.STRING(1000),
        allowNull: true
    },
    director: {
        type: DataTypes.STRING,
        allowNull: true
    },
    budget: {
        type: DataTypes.FLOAT,
        allowNull: true
    }
});

const initializeDatabase = async () => {
    await sequelize.sync({ alter: true });
};

const jwtOptions = {
    jwtFromRequest: passportJWT.ExtractJwt.fromAuthHeaderAsBearerToken(),
    secretOrKey: 'afrah'
};

passport.use(new passportJWT.Strategy(jwtOptions, async (jwt_payload, done) => {
    try {
        const user = await User.findByPk(jwt_payload.id);
        return done(null, user ? user : false);
    } catch (error) {
        return done(error, false);
    }
}));

app.use(passport.initialize());

app.post('/register', async (req, res) => {
    const { username, password } = req.body;
    if (!username || !password) return res.status(400).json({ error: 'Username and password are required' });
    try {
        await User.create({ username, password });
        res.json({ message: 'User registered successfully!' });
    } catch (error) {
        res.status(400).json({ error: 'Username already exists!' });
    }
});

app.post('/login', async (req, res) => {
    const { username, password } = req.body;
    if (!username || !password) return res.status(400).json({ error: 'Username and password are required' });
    try {
        const user = await User.findOne({ where: { username } });
        if (!user || !await bcrypt.compare(password, user.password)) return res.status(401).json({ error: 'Invalid username or password' });
        const token = jwt.sign({ id: user.id }, jwtOptions.secretOrKey, { expiresIn: '1h' });
        res.json({ message: 'Login successful!', token });
    } catch (error) {
        res.status(500).json({ error: 'Internal server error' });
    }
});

async function fetchMovieDetails(movieId, retries = 3) {
    const url = `https://cinema.stag.rihal.tech/api/movie/${movieId}`;
    for (let attempt = 1; attempt <= retries; attempt++) {
        try {
            return (await axios.get(url, { timeout: 5000 })).data;
        } catch (error) {
            if (attempt === retries) throw error;
            await new Promise(resolve => setTimeout(resolve, 1000));
        }
    }
}

const parseDate = (dateString) => {
    const formats = [
        'YYYY-MM-DD',
        'MM/DD/YYYY',
        'DD-MM-YYYY',
        'MMMM D, YYYY',
        'YYYY/MM/DD'
    ];
    const date = moment(dateString, formats, true);
    return date.isValid() ? date.toDate() : null;
};

async function loadMovies() {
    try {
        const movies = require('./movies.json');
        const movieRecords = await Promise.all(movies.map(async (movie) => {
            try {
                const details = await fetchMovieDetails(movie.id);
                return {
                    name: movie.name,
                    description: movie.description,
                    release_date: parseDate(details.release_date),
                    main_cast: Array.isArray(details.main_cast) ? details.main_cast.join(', ') : details.main_cast,
                    director: details.director,
                    budget: details.budget
                };
            } catch {
                return null;
            }
        }));
        await Movie.bulkCreate(movieRecords.filter(record => record));
        console.log('Movies loaded successfully');
    } catch (error) {
        console.error('Error loading movies:', error.message);
    }
}

initializeDatabase().then(loadMovies);

app.use('/movies', passport.authenticate('jwt', { session: false }));

app.get('/movies', async (req, res) => {
    try {
        res.json(await Movie.findAll());
    } catch (error) {
        res.status(500).json({ error: 'Internal server error' });
    }
});

const port = process.env.PORT || 3000;
app.listen(port, () => console.log(`Server running on port ${port}`));
