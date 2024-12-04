require('dotenv').config();
const express = require('express');
const bcrypt = require('bcrypt');
const jwt = require('jsonwebtoken');
const OpenAI = require('openai');
const sqlite3 = require('sqlite3').verbose();
const xlsx = require('xlsx');
const multer = require('multer');
const fs = require('fs');
const axios = require('axios');
const path = require('path'); // Importa el módulo path
const sharp = require('sharp');

// Configuración de OpenAI
const client = new OpenAI({
  apiKey: process.env.OPENAI_API_KEY,
});

// Configuración de Express
const app = express();
app.use(express.json());
const upload = multer({ dest: 'uploads/' });
app.use('/generated', express.static(path.join(__dirname, 'generated')));

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
  let audioPath = req.file.path;

  try {
    // Renombrar el archivo con la extensión adecuada
    const renamedPath = `${audioPath}.mp3`;
    fs.renameSync(audioPath, renamedPath);
    audioPath = renamedPath;

    console.log('Archivo renombrado:', audioPath);

    const response = await client.audio.transcriptions.create({
      file: fs.createReadStream(audioPath),
      model: 'whisper-1',
    });

    reduceTokens(req);
    res.json({ transcription: response.text, tokensLeft: req.user.tokens - 1 });
  } catch (error) {
    console.error('Error en OpenAI:', error.message);
    res.status(500).json({ message: 'Error al transcribir audio', error: error.message });
  } finally {
    if (fs.existsSync(audioPath)) {
      fs.unlinkSync(audioPath); // Eliminar archivo temporal si existe
    }
  }
});

// Función para convertir un flujo a un buffer
const streamToBuffer = async (stream) => {
  const chunks = [];
  for await (const chunk of stream) {
    chunks.push(chunk);
  }
  return Buffer.concat(chunks);
};

app.post('/text-to-audio', authenticate, checkTokens, async (req, res) => {
  const { text, voice } = req.body;

  if (!text) {
    return res.status(400).json({ message: 'Texto requerido' });
  }

  // Definir las voces disponibles
  const voices = {
    nova: 'nova',
    alloy: 'alloy',
    echo: 'echo',
    fable: 'fable',
    onyx: 'onyx',
    shimmer: 'shimmer',
  };

  // Seleccionar la voz o usar una predeterminada
  const selectedVoice = voices[voice] ?? 'nova';

  try {
    console.log('Texto recibido:', text);
    console.log('Voz seleccionada:', selectedVoice);

    // Crear la carpeta personalizada para el usuario
    const folderPath = path.resolve(__dirname, `generated/audios/${req.user.username}`);
    const speechFile = path.resolve(`${folderPath}/${new Date().getTime()}.mp3`);
    fs.mkdirSync(folderPath, { recursive: true });

    // Enviar la solicitud al modelo de OpenAI
    console.log('Enviando solicitud a OpenAI...');
    const response = await client.audio.speech.create({
      model: 'tts-1', // Modelo de texto a voz
      voice: selectedVoice,
      input: text,
      response_format: 'mp3',
    });

    console.log('Estado de la respuesta:', response.status);
    console.log('Encabezados de la respuesta:', response.headers);

    // Procesar el cuerpo de la respuesta
    if (response.body) {
      const responseBuffer = await streamToBuffer(response.body);
      fs.writeFileSync(speechFile, responseBuffer);
      console.log('Archivo de audio generado desde el flujo:', speechFile);
    } else {
      throw new Error('No se generó audio en la respuesta del modelo.');
    }

    // Reducir tokens y enviar la respuesta
    reduceTokens(req);
    res.json({
      audioUrl: `/generated/audios/${req.user.username}/${path.basename(speechFile)}`,
      tokensLeft: req.user.tokens - 1,
    });
  } catch (error) {
    console.error('Error al generar audio:', error.message);
    res.status(500).json({ message: 'Error al generar audio', error: error.message });
  }
});


// Helper para descargar imágenes como PNG
const downloadImageAsPng = async (url) => {
  const folderPath = path.resolve(__dirname, 'generated/images/');
  fs.mkdirSync(folderPath, { recursive: true });

  const fileName = `${new Date().getTime()}.png`;
  const filePath = path.resolve(folderPath, fileName);

  const response = await axios.get(url, { responseType: 'arraybuffer' });
  fs.writeFileSync(filePath, response.data);

  return filePath;
};

// Helper para convertir imágenes a PNG con formato RGBA
const convertToPngWithRGBA = async (filePath) => {
  const outputPath = `${filePath}.png`;
  await sharp(filePath)
    .ensureAlpha() // Asegurar el canal Alpha (convertir a RGBA)
    .toFormat('png')
    .toFile(outputPath);

  // Elimina el archivo original
  if (fs.existsSync(filePath)) {
    fs.unlink(filePath, (err) => {
      if (err) {
        console.error(`Error al eliminar el archivo ${filePath}:`, err.message);
      }
    });
  }
  return outputPath;
};

// Ruta para generar o editar imágenes
app.post('/image-generation', authenticate, checkTokens, upload.fields([
  { name: 'originalImage', maxCount: 1 },
  { name: 'maskImage', maxCount: 1 },
]), async (req, res) => {
  const { prompt } = req.body;
  let originalImage = req.files?.originalImage?.[0]?.path;
  let maskImage = req.files?.maskImage?.[0]?.path;

  try {
    if (!prompt) {
      return res.status(400).json({ message: 'El campo "prompt" es obligatorio.' });
    }

    // Convertir las imágenes a PNG con formato RGBA
    if (originalImage) {
      originalImage = await convertToPngWithRGBA(originalImage);
    }
    if (maskImage) {
      maskImage = await convertToPngWithRGBA(maskImage);
    }

    // Generación o edición de imagen
    const response = !originalImage || !maskImage
      ? await client.images.generate({
          prompt,
          model: 'dall-e-3',
          n: 1,
          size: '1024x1024',
          quality: 'standard',
          response_format: 'url',
        })
      : await client.images.edit({
          model: 'dall-e-2',
          prompt,
          image: fs.createReadStream(originalImage),
          mask: fs.createReadStream(maskImage),
          n: 1,
          size: '1024x1024',
          response_format: 'url',
        });

    // Guardar la imagen generada o editada
    const filePath = await downloadImageAsPng(response.data[0].url);
    const fileName = path.basename(filePath);

    reduceTokens(req);
    res.json({
      imageUrl: `/generated/images/${fileName}`,
      tokensLeft: req.user.tokens - 1,
    });
  } catch (error) {
    console.error('Error al generar/editar imagen:', error.message);
    res.status(500).json({ message: 'Error al generar imagen', error: error.message });
  } finally {
    // Limpieza de archivos temporales
    if (originalImage && fs.existsSync(originalImage)) {
      fs.unlink(originalImage, (err) => {
        if (err) {
          console.error(`Error al eliminar el archivo ${originalImage}:`, err.message);
        }
      });
    }
    if (maskImage && fs.existsSync(maskImage)) {
      fs.unlink(maskImage, (err) => {
        if (err) {
          console.error(`Error al eliminar el archivo ${maskImage}:`, err.message);
        }
      });
    }
  }
});

app.post('/image-variation', authenticate, checkTokens, upload.single('baseImage'), async (req, res) => {
  const baseImage = req.file?.path;

  if (!baseImage) {
    return res.status(400).json({ message: 'Se requiere una imagen base.' });
  }

  try {
    // Convertir la imagen base a PNG con formato RGBA
    const pngImagePath = await convertToPngWithRGBA(baseImage);

    // Enviar solicitud a OpenAI para crear una variación
    const response = await client.images.createVariation({
      model: 'dall-e-2',
      image: fs.createReadStream(pngImagePath),
      n: 1,
      size: '1024x1024',
      response_format: 'url',
    });

    // Descargar la imagen generada
    const filePath = await downloadImageAsPng(response.data[0].url);
    const fileName = path.basename(filePath);

    // Reducir tokens disponibles y devolver la respuesta
    reduceTokens(req);
    res.json({
      imageUrl: `/generated/images/${fileName}`,
      openAIUrl: response.data[0].url,
      tokensLeft: req.user.tokens - 1,
    });
  } catch (error) {
    console.error('Error al crear variación de imagen:', error.message);
    res.status(500).json({ message: 'Error al crear variación de imagen', error: error.message });
  } finally {
    // Limpieza de archivos temporales
    if (fs.existsSync(baseImage)) {
      fs.unlink(baseImage, (err) => {
        if (err) console.error(`Error al eliminar el archivo ${baseImage}:`, err.message);
      });
    }
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

// Ruta para importar usuarios desde un archivo Excel
app.post('/import-users', upload.single('file'), (req, res) => {
  const filePath = req.file.path; // Ruta del archivo subido

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
    res.json({ message: 'Usuarios importados con éxito' });
  } catch (error) {
    console.error('Error al importar usuarios desde Excel:', error.message);
    res.status(500).json({ message: 'Error al importar usuarios desde Excel', error: error.message });
  } finally {
    // Eliminar el archivo temporal subido
    fs.unlinkSync(filePath);
  }
});
  

// Iniciar servidor
const PORT = process.env.PORT || 3000;
app.listen(PORT, () => console.log(`Servidor corriendo en el puerto ${PORT}`));
