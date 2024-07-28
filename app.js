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
const multer = require('multer');
const path = require('path');
const fs = require('fs');



const uploadDir = path.join(__dirname, 'uploads');
if (!fs.existsSync(uploadDir)) {
    fs.mkdirSync(uploadDir);
}

const storage = multer.diskStorage({
    destination: function (req, file, cb) {
        cb(null, uploadDir);
    },
    filename: function (req, file, cb) {
        cb(null, Date.now() + path.extname(file.originalname));
    }
});

const upload = multer({ storage: storage });



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



const Memory = sequelize.define('Memory', {
    title: {
        type: DataTypes.STRING,
        allowNull: false
    },
    date: {
        type: DataTypes.DATE,
        allowNull: false
    },
    photos: {
        type: DataTypes.STRING,
        allowNull: true 
    },
    story: {
        type: DataTypes.TEXT,
        allowNull: false
    }
});

User.hasMany(Memory);
Memory.belongsTo(User);
Movie.hasMany(Memory);
Memory.belongsTo(Movie);


const initializeDatabase = async () => {
    try {
        await User.sync();
        await Movie.sync();
        await Rating.sync();
        await Memory.sync();
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



const downloadImage = async (url, filePath) => {
    const writer = fs.createWriteStream(filePath);
    const response = await axios({
        url,
        method: 'GET',
        responseType: 'stream'
    });
    response.data.pipe(writer);
    return new Promise((resolve, reject) => {
        writer.on('finish', resolve);
        writer.on('error', reject);
    });
};


app.post('/movies/:id/memories', passport.authenticate('jwt', { session: false }), async (req, res) => {
    const movieId = req.params.id;
    const { title, date, story, photoUrl } = req.body;

    if (!title || !date || !story || !photoUrl) {
        return res.status(400).json({ error: 'Title, date, story, and photoUrl are required' });
    }

    const url = new URL(photoUrl);
    let ext = path.extname(url.pathname).toLowerCase();

    
    if (!['.jpg', '.jpeg', '.png'].includes(ext)) {
        ext = '.jpg';
    }

    const fileName = Date.now() + ext;
    const filePath = path.join(__dirname, 'uploads', fileName);

    try {
        
        await downloadImage(photoUrl, filePath);

        const movie = await Movie.findByPk(movieId);
        if (!movie) {
            return res.status(404).json({ error: 'Movie not found' });
        }

        const memory = await Memory.create({
            title,
            date: new Date(date),
            photos: fileName, 
            story,
            UserId: req.user.id,
            MovieId: movie.id
        });

        res.json({ message: 'Memory added successfully!', memory });
    } catch (error) {
        console.error('Error creating memory:', error);
        res.status(500).json({ error: 'Internal server error' });
    }
});



app.get('/memories', passport.authenticate('jwt', { session: false }), async (req, res) => {
    try {
        const userId = req.user.id;

        const memories = await Memory.findAll({
            where: { UserId: userId },
            include: {
                model: Movie,
                attributes: ['id', 'name']
            },
            attributes: ['id', 'title', 'MovieId']
        });

        const response = memories.map(memory => ({
            id: memory.id,
            movieId: memory.MovieId,
            movieName: memory.Movie.name,
            title: memory.title
        }));

        res.json(response);
    } catch (error) {
        console.error('Error fetching memories:', error);
        res.status(500).json({ error: 'Internal server error' });
    }
});


app.put('/memories/:id', passport.authenticate('jwt', { session: false }), async (req, res) => {
    const memoryId = req.params.id;
    const { title, story } = req.body;

    if (!title && !story) {
        return res.status(400).json({ error: 'At least one of title or story must be provided to update' });
    }

    try {
        const memory = await Memory.findOne({ where: { id: memoryId, UserId: req.user.id } });
        if (!memory) {
            return res.status(404).json({ error: 'Memory not found or you do not have permission to update it' });
        }

        if (title) memory.title = title;
        if (story) memory.story = story;

        await memory.save();

        res.json({ message: 'Memory updated successfully', memory });
    } catch (error) {
        console.error('Error updating memory:', error);
        res.status(500).json({ error: 'Internal server error' });
    }
});



app.post('/memories/:id/photos', passport.authenticate('jwt', { session: false }), upload.array('photos', 10), async (req, res) => {
    const memoryId = req.params.id;

    try {
        const memory = await Memory.findOne({ where: { id: memoryId, UserId: req.user.id } });
        if (!memory) {
            return res.status(404).json({ error: 'Memory not found or you do not have permission to update it' });
        }

       
        const newPhotos = req.files.map(file => file.filename);
        const existingPhotos = memory.photos ? memory.photos.split(',') : [];
        const updatedPhotos = existingPhotos.concat(newPhotos).join(',');

        memory.photos = updatedPhotos;
        await memory.save();

        res.json({ message: 'Photos added successfully', memory });
    } catch (error) {
        console.error('Error adding photos to memory:', error);
        res.status(500).json({ error: 'Internal server error' });
    }
});


app.delete('/memories/:id/photos', passport.authenticate('jwt', { session: false }), async (req, res) => {
    const memoryId = req.params.id;
    const { photosToDelete } = req.body;

    if (!photosToDelete || !Array.isArray(photosToDelete)) {
        return res.status(400).json({ error: 'photosToDelete must be provided as an array of filenames' });
    }

    try {
        const memory = await Memory.findOne({ where: { id: memoryId, UserId: req.user.id } });
        if (!memory) {
            return res.status(404).json({ error: 'Memory not found or you do not have permission to update it' });
        }

        const existingPhotos = memory.photos ? memory.photos.split(',') : [];
        const updatedPhotos = existingPhotos.filter(photo => !photosToDelete.includes(photo));

        memory.photos = updatedPhotos.join(',');

        
        photosToDelete.forEach(photo => {
            const filePath = path.join(uploadDir, photo);
            if (fs.existsSync(filePath)) {
                fs.unlinkSync(filePath);
            }
        });

        await memory.save();

        res.json({ message: 'Photos deleted successfully', memory });
    } catch (error) {
        console.error('Error deleting photos from memory:', error);
        res.status(500).json({ error: 'Internal server error' });
    }
});



app.delete('/memories/:id', passport.authenticate('jwt', { session: false }), async (req, res) => {
    const memoryId = req.params.id;

    try {
        const memory = await Memory.findOne({ where: { id: memoryId, UserId: req.user.id } });

        if (!memory) {
            return res.status(404).json({ error: 'Memory not found or you do not have permission to delete it' });
        }

        if (memory.photos) {
            const photos = memory.photos.split(',');
            photos.forEach(photo => {
                const filePath = path.join(uploadDir, photo);
                if (fs.existsSync(filePath)) {
                    fs.unlinkSync(filePath);
                }
            });
        }

        await memory.destroy();
        res.json({ message: 'Memory deleted successfully' });
    } catch (error) {
        console.error('Error deleting memory:', error);
        res.status(500).json({ error: 'Internal server error' });
    }
});


const stopWords = new Set([
    'i', 'me', 'my', 'myself', 'we', 'our', 'ours', 'ourselves', 'you', 'your', 'yours', 'yourself', 'yourselves',
    'he', 'him', 'his', 'himself', 'she', 'her', 'hers', 'herself', 'it', 'its', 'itself', 'they', 'them', 'their',
    'theirs', 'themselves', 'what', 'which', 'who', 'whom', 'this', 'that', 'these', 'those', 'am', 'is', 'are', 'was',
    'were', 'be', 'been', 'being', 'have', 'has', 'had', 'having', 'do', 'does', 'did', 'doing', 'a', 'an', 'the', 'and',
    'but', 'if', 'or', 'because', 'as', 'until', 'while', 'of', 'at', 'by', 'for', 'with', 'about', 'against', 'between',
    'into', 'through', 'during', 'before', 'after', 'above', 'below', 'to', 'from', 'up', 'down', 'in', 'out', 'on', 'off',
    'over', 'under', 'again', 'further', 'then', 'once', 'here', 'there', 'when', 'where', 'why', 'how', 'all', 'any',
    'both', 'each', 'few', 'more', 'most', 'other', 'some', 'such', 'no', 'nor', 'not', 'only', 'own', 'same', 'so',
    'than', 'too', 'very', 's', 't', 'can', 'will', 'just', 'don', 'should', 'now'
]);

app.get('/top-words', passport.authenticate('jwt', { session: false }), async (req, res) => {
    try {
        const memories = await Memory.findAll({ attributes: ['story'] });
        const wordCounts = {};

        memories.forEach(memory => {
            const words = memory.story.toLowerCase().split(/\W+/);
            words.forEach(word => {
                if (!stopWords.has(word) && word.length > 0) {
                    wordCounts[word] = (wordCounts[word] || 0) + 1;
                }
            });
        });

        const sortedWords = Object.entries(wordCounts).sort((a, b) => b[1] - a[1]);
        const topWords = sortedWords.slice(0, 5).map(entry => ({ word: entry[0], count: entry[1] }));

        res.json(topWords);
    } catch (error) {
        console.error('Error fetching top words:', error);
        res.status(500).json({ error: 'Internal server error' });
    }
});



const port = process.env.PORT || 3000;
app.listen(port, () => console.log(`Server running on port ${port}`));