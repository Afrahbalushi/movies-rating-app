const express = require('express');
const bodyParser = require('body-parser');
const axios = require('axios');
const { Sequelize, DataTypes } = require('sequelize');
const passport = require('passport');
const passportJWT = require('passport-jwt');
const jwt = require('jsonwebtoken');
const bcrypt = require('bcrypt');
const moment = require('moment');
const { Op } = require('sequelize');
const numeral = require('numeral');


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

const Rating = sequelize.define('Rating', {
    score: {
        type: DataTypes.INTEGER,
        allowNull: false,
        validate: {
            min: 1,
            max: 10
        }
    }
});

User.hasMany(Rating);
Rating.belongsTo(User);
Movie.hasMany(Rating);
Rating.belongsTo(Movie);

const initializeDatabase = async () => {
    try {
        const usersExist = await User.sync();
        const moviesExist = await Movie.sync();
        const ratingsExist = await Rating.sync();

        if (usersExist && moviesExist && ratingsExist) {
            console.log('Database tables already exist.');
            return;
        }

        await sequelize.sync({ alter: true });
        console.log('Database synchronized successfully.');
    } catch (error) {
        console.error('Error initializing database:', error.message);
        
    }
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
        
        const existingMoviesCount = await Movie.count();
        
        if (existingMoviesCount > 0) {
            console.log('Movies already loaded. Skipping insertion.');
            return;
        }

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
        
        const validMovieRecords = movieRecords.filter(record => record);

        if (validMovieRecords.length > 0) {
            await Movie.bulkCreate(validMovieRecords);
            console.log('Movies loaded successfully');
        } else {
            console.log('No valid movies to load.');
        }
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

app.post('/movies/:id/rate', passport.authenticate('jwt', { session: false }), async (req, res) => {
    const movieId = req.params.id;
    const { score } = req.body;

    if (!score || score < 1 || score > 10) {
        return res.status(400).json({ error: 'Score must be between 1 and 10' });
    }

    try {
        const movie = await Movie.findByPk(movieId);
        if (!movie) {
            return res.status(404).json({ error: 'Movie not found' });
        }

        const user = req.user;
        const existingRating = await Rating.findOne({ where: { UserId: user.id, MovieId: movie.id } });

        if (existingRating) {
            existingRating.score = score;
            await existingRating.save();
        } else {
            await Rating.create({ score, UserId: user.id, MovieId: movie.id });
        }

        res.json({ message: 'Rating submitted successfully' });
    } catch (error) {
        res.status(500).json({ error: 'Internal server error' });
    }
});

app.get('/movies/:id/ratings', async (req, res) => {
    const movieId = req.params.id;

    try {
        const movie = await Movie.findByPk(movieId, {
            include: {
                model: Rating,
                include: [
                    {
                        model: User,
                        attributes: ['username']
                    },
                    {
                        model: Movie,
                        attributes: ['name']
                    }
                ]
            }
        });

        if (!movie) {
            return res.status(404).json({ error: 'Movie not found' });
        }

        res.json(movie.Ratings.map(rating => ({
            id: rating.id,
            score: rating.score,
            createdAt: rating.createdAt,
            updatedAt: rating.updatedAt,
            UserId: rating.UserId,
            MovieId: rating.MovieId,
            User: rating.User,
            Movie: { name: movie.name }
        })));
    } catch (error) {
        res.status(500).json({ error: 'Internal server error' });
    }
});



const truncateDescription = (description, maxLength) => {
    if (!description) return '';

    if (description.length > maxLength) {
        let truncatedText = description.substring(0, maxLength);
        truncatedText = truncatedText.substr(0, Math.min(truncatedText.length, truncatedText.lastIndexOf(' ')));

        return truncatedText.trim() + '...';
    }

    return description;
};

app.get('/movies/list', async (req, res) => {
    try {
        const movies = await Movie.findAll({
            attributes: [
                'id',
                'name',
                'description',
                [sequelize.fn('AVG', sequelize.col('Ratings.score')), 'averageRating']
            ],
            include: [{
                model: Rating,
                attributes: []
            }],
            group: ['Movie.id', 'name', 'description']
        });

        const formattedMovies = movies.map(movie => {
            const averageRating = parseFloat(movie.dataValues.averageRating || 0);
            const description = truncateDescription(movie.description, 100);

            return {
                id: movie.id,
                name: movie.name,
                description: description,
                averageRating: averageRating
            };
        });

        res.json(formattedMovies);
    } catch (error) {
        console.error('Error fetching movie list:', error);
        res.status(500).json({ error: 'Internal server error' });
    }
});



app.get('/movies/search', async (req, res) => {
    const { query } = req.query;

    if (!query) {
        return res.status(400).json({ error: 'Query parameter is required' });
    }

    try {
        const movies = await Movie.findAll({
            where: {
                [Op.or]: [
                    { name: { [Op.like]: `%${query}%` } },
                    { description: { [Op.like]: `%${query}%` } }
                ]
            },
            attributes: ['id', 'name', 'description']
        });

        res.json(movies);
    } catch (error) {
        console.error('Error searching for movies:', error);
        res.status(500).json({ error: 'Internal server error' });
    }
});


app.get('/movies/top-rated', passport.authenticate('jwt', { session: false }), async (req, res) => {
    try {
        const userId = req.user.id;

        const topRatedMovies = await Rating.findAll({
            where: { UserId: userId },
            attributes: ['MovieId', [sequelize.col('Movie.name'), 'name'], 'score'],
            include: [{
                model: Movie,
                attributes: []
            }],
            order: [['score', 'DESC']],
            limit: 5
        });

        const formattedMovies = topRatedMovies.map(rating => ({
            id: rating.MovieId,
            name: rating.getDataValue('name'),
            rating: rating.score
        }));

        res.json(formattedMovies);
    } catch (error) {
        console.error('Error fetching top-rated movies:', error);
        res.status(500).json({ error: 'Internal server error' });
    }
});




const port = process.env.PORT || 3000;
app.listen(port, () => console.log(`Server running on port ${port}`));
