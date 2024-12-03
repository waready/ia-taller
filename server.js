require('dotenv').config();
const express = require('express');
const bcrypt = require('bcrypt');
const jwt = require('jsonwebtoken');
const OpenAI = require('openai');
const sqlite3 = require('sqlite3').verbose();
const xlsx = require('xlsx');
const multer = require('multer');
const fs = require('fs');

// Configuración de OpenAI
const client = new OpenAI({
  apiKey: process.env.OPENAI_API_KEY,
});

// Configuración de Express
const app = express();
app.use(express.json());
const upload = multer({ dest: 'uploads/' });

// Configuración de la base de datos SQLite
const db = new sqlite3.Database('./database.sqlite', (err) => {
  if (err) {
    console.error('Error al conectar con la base de datos:', err.message);
  } else {
    console.log('Base de datos SQLite creada en archivo "database.sqlite"');
  }
});

// Crear tabla de usuarios
db.serialize(() => {
  db.run(`
    CREATE TABLE IF NOT EXISTS users (
      id INTEGER PRIMARY KEY AUTOINCREMENT,
      username TEXT NOT NULL UNIQUE,
      password TEXT NOT NULL,
      tokens INTEGER DEFAULT 10
    )
  `);
});

// Middleware para autenticación
const authenticate = (req, res, next) => {
    let token = req.headers['authorization'];
    if (!token) return res.status(401).json({ message: 'Token requerido' });
  
    // Elimina el prefijo 'Bearer' si está presente
    if (token.startsWith('Bearer ')) {
      token = token.slice(7, token.length).trim();
    }
  
    try {
      const decoded = jwt.verify(token, process.env.JWT_SECRET);
      req.user = decoded; // Asigna los datos del token decodificado a la solicitud
      next();
    } catch (err) {
      console.error('Error al verificar el token:', err.message);
      res.status(403).json({ message: 'Token inválido' });
    }
  };
  

// Middleware para verificar tokens disponibles
const checkTokens = (req, res, next) => {
  db.get('SELECT * FROM users WHERE id = ?', [req.user.id], (err, user) => {
    if (err || !user) return res.status(404).json({ message: 'Usuario no encontrado' });

    if (user.tokens <= 0) {
      return res.status(403).json({ message: 'No tienes tokens disponibles' });
    }

    req.user.tokens = user.tokens;
    next();
  });
};

// Reducir tokens
const reduceTokens = (req) => {
  db.run('UPDATE users SET tokens = tokens - 1 WHERE id = ?', [req.user.id]);
};

// Ruta de registro
app.post('/register', async (req, res) => {
  const { username, password } = req.body;
  if (!username || !password)
    return res.status(400).json({ message: 'Usuario y contraseña requeridos' });

  try {
    const hashedPassword = await bcrypt.hash(password, 10);
    db.run(
      'INSERT INTO users (username, password, tokens) VALUES (?, ?, 10)',
      [username, hashedPassword],
      (err) => {
        if (err) return res.status(400).json({ message: 'Usuario ya existe' });
        res.json({ message: 'Usuario registrado con éxito' });
      }
    );
  } catch (err) {
    res.status(500).json({ message: 'Error del servidor' });
  }
});

// Ruta de login
app.post('/login', (req, res) => {
  const { username, password } = req.body;
  db.get('SELECT * FROM users WHERE username = ?', [username], async (err, user) => {
    if (err || !user)
      return res.status(404).json({ message: 'Usuario no encontrado' });

    const validPassword = await bcrypt.compare(password, user.password);
    if (!validPassword)
      return res.status(403).json({ message: 'Contraseña incorrecta' });

    const token = jwt.sign({ id: user.id, username: user.username }, process.env.JWT_SECRET, {
      expiresIn: '2h',
    });

    res.json({ token });
  });
});

// **Funciones protegidas**
app.post('/audio-to-text', authenticate, checkTokens, upload.single('audio'), async (req, res) => {
  const audioPath = req.file.path;

  try {
    const response = await client.audio.transcriptions.create({
      file: fs.createReadStream(audioPath),
      model: 'whisper-1',
    });

    reduceTokens(req);
    res.json({ transcription: response.text, tokensLeft: req.user.tokens - 1 });
  } catch (error) {
    res.status(500).json({ message: 'Error al transcribir audio', error: error.message });
  } finally {
    fs.unlinkSync(audioPath); // Eliminar archivo temporal
  }
});

app.post('/image-generation', authenticate, checkTokens, async (req, res) => {
  const { prompt } = req.body;

  try {
    const response = await client.images.generate({
      prompt,
      n: 1,
      size: '1024x1024',
    });

    reduceTokens(req);
    res.json({ imageUrl: response.data[0].url, tokensLeft: req.user.tokens - 1 });
  } catch (error) {
    res.status(500).json({ message: 'Error al generar imagen', error: error.message });
  }
});

app.post('/image-variation', authenticate, checkTokens, upload.single('image'), async (req, res) => {
  const imagePath = req.file.path;

  try {
    const response = await client.images.variations.create({
      image: fs.createReadStream(imagePath),
      n: 1,
      size: '1024x1024',
    });

    reduceTokens(req);
    res.json({ variationUrl: response.data[0].url, tokensLeft: req.user.tokens - 1 });
  } catch (error) {
    res.status(500).json({ message: 'Error al crear variación de imagen', error: error.message });
  } finally {
    fs.unlinkSync(imagePath); // Eliminar archivo temporal
  }
});

app.post('/translate', authenticate, checkTokens, async (req, res) => {
  const { text, targetLanguage } = req.body;

  if (!text || !targetLanguage) {
    return res.status(400).json({ message: 'Texto y lenguaje objetivo requeridos' });
  }

  try {
    const response = await client.chat.completions.create({
      messages: [{ role: 'user', content: `Traduce esto al ${targetLanguage}: ${text}` }],
      model: 'gpt-4',
    });

    reduceTokens(req);
    res.json({ translation: response.choices[0].message.content, tokensLeft: req.user.tokens - 1 });
  } catch (error) {
    res.status(500).json({ message: 'Error al traducir texto', error: error.message });
  }
});

// Función para importar usuarios desde un archivo Excel
function importUsersFromExcel(filePath) {
    try {
      const workbook = xlsx.readFile(filePath); // Cargar el archivo Excel
      const sheetName = workbook.SheetNames[0]; // Obtener el primer nombre de hoja
      const data = xlsx.utils.sheet_to_json(workbook.Sheets[sheetName]); // Convertir a JSON
  
      // Insertar usuarios en la base de datos
      db.serialize(async () => {
        const stmt = db.prepare('INSERT INTO users (username, password, tokens) VALUES (?, ?, ?)');
        for (const user of data) {
          try {
            const hashedPassword = await bcrypt.hash(user.password, 10); // Cifrar la contraseña
            stmt.run(user.username, hashedPassword, user.tokens, (err) => {
              if (err) {
                console.error(`Error al insertar usuario ${user.username}:`, err.message);
              } else {
                console.log(`Usuario ${user.username} importado con éxito`);
              }
            });
          } catch (hashError) {
            console.error(`Error al cifrar contraseña para ${user.username}:`, hashError.message);
          }
        }
        stmt.finalize();
      });
  
      console.log('Importación completada');
    } catch (error) {
      console.error('Error al importar usuarios desde Excel:', error.message);
    }
}
  
  // Ruta de ejemplo para ejecutar la importación
  const filePath = './users_sample.xlsx'; // Cambia esta ruta si es necesario
  importUsersFromExcel(filePath);

// Iniciar servidor
const PORT = process.env.PORT || 3000;
app.listen(PORT, () => console.log(`Servidor corriendo en el puerto ${PORT}`));
