// server.js
const jwt = require('jsonwebtoken');
const bcrypt = require('bcrypt');
const express = require('express');
const mysql = require('mysql2');
const cors = require('cors'); // <-- 1. IMPORTA CORS
require('dotenv').config(); // Carga las variables del archivo .env
const JWT_SECRET = process.env.JWT_SECRET || 'este-es-un-secreto-muy-secreto'; // Añade esta línea
const crypto = require('crypto'); // Módulo incorporado de Node.js
const nodemailer = require('nodemailer');


//Clodarinary
const cloudinary = require('cloudinary').v2; // Importa Cloudinary v2
const multer = require('multer');
const path = require('path');
require('dotenv').config(); // Asegúrate que dotenv se cargue antes de configurar cloudinary


// --- Configuración de Cloudinary ---
cloudinary.config({ 
    cloud_name: process.env.CLOUDINARY_CLOUD_NAME, 
    api_key: process.env.CLOUDINARY_API_KEY, 
    api_secret: process.env.CLOUDINARY_API_SECRET,
  secure: true // Usa HTTPS
});
console.log('Cloudinary Configurado.'); // Para verificar que se carga

// --- Configuración de Multer (Igual que antes) ---
const multerStorage = multer.memoryStorage(); // Guarda el archivo en memoria
const upload = multer({ 
    storage: multerStorage,
    limits: { fileSize: 5 * 1024 * 1024 } // Límite 5MB
});




// 2. Crear la aplicación de Express
const app = express();
const port = 3000; // Puedes usar el puerto que prefieras

// --- AÑADE ESTA LÍNEA AQUÍ ---
app.use(cors());
app.use(express.json()); // Middleware para que Express entienda el formato JSON
// --- FIN DEL CÓDIGO A AÑADIR ---

// 3. Configurar la conexión a la base de datos
const db = mysql.createPool({
    host: process.env.DB_HOST,
    user: process.env.DB_USER,
    password: process.env.DB_PASSWORD,
    database: process.env.DB_DATABASE,
    port: process.env.DB_PORT || 3306,
    ssl: {
        "rejectUnauthorized": true // <-- ESTA ES LA LÍNEA CRUCIAL
    }
}).promise(); // Usamos .promise() para poder usar async/await, que es más moderno

// --- AÑADE ESTE MIDDLEWARE DE AUTORIZACIÓN ---
const checkAdminRole = (req, res, next) => {
    // 1. Obtener el token del encabezado de la petición
    const authHeader = req.headers['authorization'];
    const token = authHeader && authHeader.split(' ')[1]; // Formato "Bearer TOKEN"
    if (token == null) {
        return res.sendStatus(401); // No hay token, no autorizado
    }
    // 2. Verificar el token y decodificarlo
    jwt.verify(token, JWT_SECRET, (err, user) => {
        if (err) {
            return res.sendStatus(403); // El token no es válido, prohibido
        }
        // 3. Revisar si el rol del usuario es 'admin'
        if (user.rol !== 'admin') {
            return res.status(403).json({ message: 'Acceso denegado. Se requiere rol de administrador.' });
        }
        // 4. Si todo está bien, permite que la petición continúe
        req.user = user;
        next();
    });
};




// POST: Subir foto de perfil para un veterinario (Usando Cloudinary)
// 'profilePic' es el nombre del campo en el formulario del front-end
app.post('/api/veterinarios/:id/upload-photo', checkAdminRole, upload.single('profilePic'), async (req, res) => {
    try {
        const { id } = req.params;
        if (!req.file) {
            return res.status(400).json({ message: 'No se subió ningún archivo.' });
        }
        // 1. Validar que el veterinario existe (opcional)
        const [vetExists] = await db.query("SELECT id FROM Veterinarios WHERE id = ?", [id]);
        if (vetExists.length === 0) {
            return res.status(404).json({ message: 'Veterinario no encontrado.' });
        }
        // 2. Subir la imagen a Cloudinary desde el buffer en memoria
        // Usamos upload_stream que es adecuado para buffers
        const uploadStream = cloudinary.uploader.upload_stream(
            { 
                folder: "vet_profiles", // Carpeta opcional en Cloudinary
                // public_id: `vet_${id}`, // Opcional: Nombre fijo (sobrescribe)
                // Opcional: Aplicar transformaciones al subir (ej. redimensionar)
                // transformation: [{ width: 300, height: 300, crop: "limit" }] 
                    transformation: [
                { 
                width: 200, 
                height: 200, 
                crop: "fill", 
                gravity: "face",
                radius: "max", // <-- AÑADIDO: Esto hace la imagen circular
                background: "transparent", // Fondo transparente para PNG
                fetch_format: "png" // <-- AÑADIDO: Fuerza la salida a PNG (soporta transparencia)
            }
                ]
            },
            async (error, result) => {
                if (error) {
                    console.error('Error al subir a Cloudinary:', error);
                    return res.status(500).json({ message: 'Error al subir la imagen.' });
                }
                if (!result) {
                    return res.status(500).json({ message: 'Resultado inesperado de Cloudinary.' });
                }
                // 3. Obtener la URL segura de la imagen subida
                const publicUrl = result.secure_url;
                try {
                    // 4. Guardar la URL en la base de datos
                    await db.query("UPDATE Veterinarios SET foto_perfil_url = ? WHERE id = ?", [publicUrl, id]);
                    
                    console.log(`Foto actualizada para Vet ID ${id}: ${publicUrl}`);
                    res.status(200).json({ message: 'Foto de perfil actualizada.', foto_perfil_url: publicUrl });
                } catch (dbError) {
                    console.error('Error al actualizar la BD:', dbError);
                    // Opcional: Intentar borrar la imagen de Cloudinary si falla la BD
                    // cloudinary.uploader.destroy(result.public_id); 
                    res.status(500).json({ message: 'Error al guardar la URL de la imagen.' });
                }
            }
        );
        // 5. Enviar el buffer del archivo al stream de Cloudinary
        uploadStream.end(req.file.buffer);
    } catch (error) {
        console.error('Error general en upload-photo:', error);
        res.status(500).json({ message: 'Error interno del servidor.' });
    }
});







// GET: Obtener lista única de colonias existentes
app.get('/api/colonias', async (req, res) => {
    try {
        // DISTINCT asegura que cada colonia aparezca solo una vez
        // Filtramos NULLs y vacíos, y ordenamos alfabéticamente
        const sql = `
            SELECT DISTINCT colonia 
            FROM Ubicaciones 
            WHERE colonia IS NOT NULL AND colonia != '' 
            ORDER BY colonia ASC
        `;
        const [results] = await db.query(sql);
        // Extraemos solo los nombres de las colonias del resultado
        const colonias = results.map(row => row.colonia); 
        res.status(200).json(colonias);
    } catch (error) {
        console.error('Error al obtener colonias:', error);
        res.status(500).json({ message: 'Error interno del servidor.' });
    }
});
// 4. Crear una ruta de prueba para verificar la conexión a la BD
app.get('/check-db', async (req, res) => {
    try {
        // Intenta hacer una consulta muy simple a la base de datos
        const [results, fields] = await db.query('SELECT 1');
        res.status(200).json({
            message: '¡Conexión a la base de datos exitosa!',
            db_response: results
        });
    } catch (error) {
        console.error('Error al conectar con la base de datos:', error);
        res.status(500).json({
            message: 'Error al conectar con la base de datos.'
        });
    }
});

// server.js

// GET: Obtener todos los veterinarios con filtros opcionales
// GET: Obtener todos los veterinarios CON sus ubicaciones, especialidades y estudios COMPLETOS (Consulta Única Corregida)

// GET: Obtener todos los veterinarios con filtros opcionales (Versión Simplificada - CON FILTRO URGENCIAS)
app.get('/api/veterinarios', async (req, res) => {
    try {
        // 1. Extrae filtros (incluyendo 'urgencias')
        const { search = '', especialidad, colonia, urgencias } = req.query;
        const searchTerm = `%${search}%`;
        // 2. Consulta principal para OBTENER LOS IDs de los veterinarios que coinciden
        let baseSql = `
            SELECT DISTINCT v.id, v.nombre_completo
            FROM Veterinarios v
            LEFT JOIN Veterinario_Especialidades ve ON v.id = ve.veterinario_id
            LEFT JOIN Especialidades e ON ve.especialidad_id = e.id
            LEFT JOIN Veterinario_Ubicaciones vu ON v.id = vu.veterinario_id
            LEFT JOIN Ubicaciones u ON vu.ubicacion_id = u.id
            WHERE (v.nombre_completo LIKE ? OR u.nombre_clinica LIKE ? OR e.nombre LIKE ?)
        `;
        const params = [searchTerm, searchTerm, searchTerm];
        // 3. Añade filtros dinámicos
        if (especialidad) { baseSql += ` AND ve.especialidad_id = ?`; params.push(especialidad); }
        if (colonia) { baseSql += ` AND u.colonia = ?`; params.push(colonia); }
        // --- AÑADE ESTE BLOQUE PARA URGENCIAS ---
        if (urgencias === 'true') {
            baseSql += ` AND v.acepta_urgencias = 1`; // 1 es TRUE en MySQL
        } else if (urgencias === 'false') {
             baseSql += ` AND v.acepta_urgencias = 0`; // 0 es FALSE en MySQL
        }
        // --- FIN BLOQUE URGENCIAS ---
        baseSql += ` ORDER BY v.nombre_completo ASC;`;
        // Ejecuta la consulta para obtener IDs
        const [vetIdsResult] = await db.query(baseSql, params);
        const vetIds = vetIdsResult.map(row => row.id);
        if (vetIds.length === 0) {
            return res.status(200).json([]);
        }
        // 4. Busca detalles completos para cada ID encontrado (Este código no cambia)
        const detailedVetsPromises = vetIds.map(async (vetId) => {
            const vetSql = "SELECT * FROM Veterinarios WHERE id = ?";
            const [vetResult] = await db.query(vetSql, [vetId]);
            if (vetResult.length === 0) return null;
            const ubicacionesSql = `SELECT u.*, u.servicios_texto, u.capacidades_texto, u.horarios_texto FROM Ubicaciones u JOIN Veterinario_Ubicaciones vu ON u.id = vu.ubicacion_id WHERE vu.veterinario_id = ?`;
            const [ubicaciones] = await db.query(ubicacionesSql, [vetId]);
            const especialidadesSql = `SELECT e.* FROM Especialidades e JOIN Veterinario_Especialidades ve ON e.id = ve.especialidad_id WHERE ve.veterinario_id = ?`;
            const [especialidades] = await db.query(especialidadesSql, [vetId]);
            const estudiosSql = `SELECT est.id, ne.nombre as nivel_estudio, est.institucion, est.titulo_obtenido, est.ano_graduacion FROM Estudios est JOIN Niveles_Estudio ne ON est.nivel_estudio_id = ne.id WHERE est.veterinario_id = ?`;
            const [estudios] = await db.query(estudiosSql, [vetId]);
            return { ...vetResult[0], ubicaciones, especialidades, estudios };
        });
        const detailedVets = (await Promise.all(detailedVetsPromises)).filter(v => v !== null);
        res.status(200).json(detailedVets);
    } catch (error) {
        console.error('Error al obtener los veterinarios filtrados:', error);
        res.status(500).json({ message: 'Error interno del servidor.' });
    }
});



/*
app.get('/api/veterinarios', async (req, res) => {
    try {
        const { search = '', especialidad, colonia, urgencias } = req.query;
        const searchTerm = `%${search}%`;
        // Construye la base de la consulta SQL
        let sql = `
            SELECT DISTINCT
                v.id, v.nombre_completo, v.cedula_profesional, v.descripcion, v.foto_perfil_url, v.acepta_urgencias, v.costo_consulta,
                u.id as ubicacion_id, u.nombre_clinica, u.calle_numero, u.colonia as ubicacion_colonia, u.ciudad, u.estado, u.telefono_contacto, u.latitud, u.longitud, u.servicios_texto, u.capacidades_texto, u.horarios_texto,
                e.id as especialidad_id, e.nombre as especialidad_nombre,
                est.id as estudio_id, ne.nombre as nivel_estudio, est.institucion, est.titulo_obtenido, est.ano_graduacion
            FROM Veterinarios v
            LEFT JOIN Veterinario_Ubicaciones vu ON v.id = vu.veterinario_id
            LEFT JOIN Ubicaciones u ON vu.ubicacion_id = u.id
            LEFT JOIN Veterinario_Especialidades ve ON v.id = ve.veterinario_id
            LEFT JOIN Especialidades e ON ve.especialidad_id = e.id
            LEFT JOIN Estudios est ON v.id = est.veterinario_id
            LEFT JOIN Niveles_Estudio ne ON est.nivel_estudio_id = ne.id
            WHERE (v.nombre_completo LIKE ? OR u.nombre_clinica LIKE ? OR e.nombre LIKE ?)
        `;
        const params = [searchTerm, searchTerm, searchTerm];
        if (especialidad) {
            sql += ` AND ve.especialidad_id = ?`;
            params.push(especialidad); // Añade el ID de especialidad a los parámetros
        }
        if (colonia) {
            sql += ` AND u.colonia = ?`;
            params.push(colonia); // Añade la colonia a los parámetros
        }
        // Aquí iría el 'if' para 'urgencias' que añadimos después
        sql += ` ORDER BY v.nombre_completo ASC;`;
        // Ejecuta la consulta
        const [filteredVets] = await db.query(sql, params);
        // Agrupa los resultados (este código es delicado pero debería funcionar)
        const veterinarios = {};
        for (const row of rows) {
            if (!veterinarios[row.id]) {
                veterinarios[row.id] = {
                    id: row.id,
                    nombre_completo: row.nombre_completo,
                    cedula_profesional: row.cedula_profesional,
                    descripcion: row.descripcion,
                    foto_perfil_url: row.foto_perfil_url,
                    acepta_urgencias: row.acepta_urgencias, // Incluido
                    costo_consulta: row.costo_consulta,   // Incluido
                    ubicaciones: [],
                    especialidades: [],
                    estudios: []
                };
            }
            // Evita duplicados en arrays
            if (row.ubicacion_id && !veterinarios[row.id].ubicaciones.some(u => u.id === row.ubicacion_id)) {
                veterinarios[row.id].ubicaciones.push({ 
                    id: row.ubicacion_id, nombre_clinica: row.nombre_clinica, 
                    calle_numero: row.calle_numero, colonia: row.ubicacion_colonia, 
                    ciudad: row.ciudad, estado: row.estado, telefono_contacto: row.telefono_contacto,
                    latitud: row.latitud, longitud: row.longitud,
                    servicios_texto: row.servicios_texto, 
                    capacidades_texto: row.capacidades_texto, 
                    horarios_texto: row.horarios_texto 
                });
            }
            if (row.especialidad_id && !veterinarios[row.id].especialidades.some(e => e.id === row.especialidad_id)) {
                veterinarios[row.id].especialidades.push({ id: row.especialidad_id, nombre: row.especialidad_nombre });
            }
            if (row.estudio_id && !veterinarios[row.id].estudios.some(s => s.id === row.estudio_id)) {
                veterinarios[row.id].estudios.push({
                    id: row.estudio_id, nivel_estudio: row.nivel_estudio,
                    institucion: row.institucion, titulo_obtenido: row.titulo_obtenido,
                    ano_graduacion: row.ano_graduacion
                });
            }
        }
        res.status(200).json(Object.values(veterinarios));
    } catch (error) {
        console.error('Error al obtener los veterinarios filtrados:', error);
        res.status(500).json({ message: 'Error interno del servidor.' });
    }
});  */

// --- AÑADE ESTE NUEVO CÓDIGO AQUÍ ---
// Endpoint para crear un nuevo veterinario
app.post('/api/veterinarios',checkAdminRole, async (req, res) => {
    try {
        // 1. Extraemos los datos del cuerpo (body) de la petición
        const { usuario_id, nombre_completo, cedula_profesional } = req.body;
        // Validación básica (en un proyecto real sería más robusta)
        if (!usuario_id || !nombre_completo) {
            return res.status(400).json({ message: 'Los campos usuario_id y nombre_completo son obligatorios.' });
        }
        // 2. Definimos la consulta SQL para insertar los datos
        const sql = "INSERT INTO Veterinarios (usuario_id, nombre_completo, cedula_profesional) VALUES (?, ?, ?)";
        // 3. Ejecutamos la consulta con los datos recibidos
        const [result] = await db.query(sql, [usuario_id, nombre_completo, cedula_profesional]);
        // 4. Enviamos una respuesta de éxito con el ID del nuevo registro
        res.status(201).json({ 
            message: 'Veterinario creado con éxito.',
            nuevoId: result.insertId 
        });
    } catch (error) {
        console.error('Error al crear el veterinario:', error);
        res.status(500).json({ message: 'Error interno del servidor.' });
    }
});
// --- FIN DEL NUEVO CÓDIGO ---
// --- AÑADE ESTE NUEVO CÓDIGO AQUÍ ---
// Endpoint para actualizar un veterinario por su ID
app.put('/api/veterinarios/:id', checkAdminRole, async (req, res) => {
    try {
        // 1. Extraemos el ID de los parámetros de la URL y los nuevos datos del cuerpo
        const { id } = req.params;
        const { nombre_completo, cedula_profesional, descripcion, costo_consulta, acepta_urgencias } = req.body;
        // Validación básica
        if (!nombre_completo) {
            return res.status(400).json({ message: 'El campo nombre_completo es obligatorio.' });
        }
        // 2. Definimos la consulta SQL para actualizar el registro
        const sql = `UPDATE Veterinarios SET 
                        nombre_completo = ?, 
                        cedula_profesional = ?,
                        descripcion = ?,
                        costo_consulta = ?,
                        acepta_urgencias = ? 
                        WHERE id = ?`;
        // 3. Ejecutamos la consulta
        const [result] = await db.query(sql, [nombre_completo, cedula_profesional, descripcion, costo_consulta,acepta_urgencias, id]);
        // 4. Verificamos si algún registro fue afectado
        if (result.affectedRows === 0) {
            // Si no se afectó ninguna fila, significa que no se encontró el ID
            return res.status(404).json({ message: 'Veterinario no encontrado.' });
        }
        // 5. Enviamos una respuesta de éxito
        res.status(200).json({ message: 'Información del veterinario actualizada con éxito.' });
    } catch (error) {
        console.error('Error al actualizar el veterinario:', error);
        res.status(500).json({ message: 'Error interno del servidor.' });
    }
});
// --- FIN DEL NUEVO CÓDIGO ---


// --- AÑADE ESTE NUEVO CÓDIGO AQUÍ ---
// Endpoint para eliminar un veterinario por su ID
app.delete('/api/veterinarios/:id', checkAdminRole, async (req, res) => {
    try {
        // 1. Extraemos el ID de los parámetros de la URL
        const { id } = req.params;
        // 2. Definimos la consulta SQL para eliminar el registro
        const sql = "DELETE FROM Veterinarios WHERE id = ?";
        // 3. Ejecutamos la consulta
        const [result] = await db.query(sql, [id]);
        // 4. Verificamos si algún registro fue afectado
        if (result.affectedRows === 0) {
            return res.status(404).json({ message: 'Veterinario no encontrado.' });
        }
        // 5. Enviamos una respuesta de éxito
        res.status(200).json({ message: 'Veterinario eliminado con éxito.' });
    } catch (error) {
        console.error('Error al eliminar el veterinario:', error);
        res.status(500).json({ message: 'Error interno del servidor.' });
    }
});
// --- FIN DEL NUEVO CÓDIGO ---

// --- CRUD PARA UBICACIONES ---

// GET: Obtener todas las ubicaciones
app.get('/api/ubicaciones', async (req, res) => {
    try {
        const [ubicaciones] = await db.query("SELECT * FROM Ubicaciones ORDER BY nombre_clinica ASC");
        res.status(200).json(ubicaciones);
    } catch (error) {
        console.error('Error al obtener ubicaciones:', error);
        res.status(500).json({ message: 'Error interno del servidor.' });
    }
});

// POST: Crear una nueva ubicación
app.post('/api/ubicaciones', checkAdminRole, async (req, res) => {
    try {
        const { nombre_clinica, calle_numero, colonia, codigo_postal, ciudad, estado, 
            telefono_contacto, latitud, longitud, 
            servicios_texto, capacidades_texto, horarios_texto
            } = req.body;
        if (!nombre_clinica || !calle_numero || !ciudad || !estado) {
            return res.status(400).json({ message: 'Los campos obligatorios son: nombre_clinica, calle_numero, ciudad, estado.' });
        }
        const sql = `INSERT INTO Ubicaciones (
                nombre_clinica, calle_numero, colonia, codigo_postal, ciudad, estado, 
                telefono_contacto, latitud, longitud, 
                servicios_texto, capacidades_texto, horarios_texto
            ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)`;
        
            const values = [
            nombre_clinica, calle_numero, colonia, codigo_postal, ciudad, estado, 
            telefono_contacto || null, // Usa null si vienen vacíos
            latitud || null, 
            longitud || null, 
            servicios_texto || null, 
            capacidades_texto || null, 
            horarios_texto || null
        ];
        const [result] = await db.query(sql, values);
        res.status(201).json({ message: 'Ubicación creada con éxito.', nuevoId: result.insertId });
    } catch (error) {
        console.error('Error al crear ubicación:', error);
        res.status(500).json({ message: 'Error interno del servidor.' });
    }
});

// PUT: Actualizar una ubicación por su ID
app.put('/api/ubicaciones/:id',checkAdminRole, async (req, res) => {
    try {
        const { id } = req.params;
        // Asegúrate de extraer TODOS los campos del body
        const { 
            nombre_clinica, calle_numero, colonia, codigo_postal, ciudad, estado, 
            telefono_contacto, latitud, longitud, 
            servicios_texto, capacidades_texto, horarios_texto
        } = req.body;
        // Validación básica (puedes hacerla más robusta)
        if (!nombre_clinica || !calle_numero || !ciudad || !estado) {
            return res.status(400).json({ message: 'Los campos nombre_clinica, calle_numero, ciudad, estado son obligatorios.' });
        }
        // Asegúrate de que la consulta UPDATE incluya TODOS los campos que quieres actualizar
        const sql = `
            UPDATE Ubicaciones SET 
                nombre_clinica = ?, calle_numero = ?, colonia = ?, codigo_postal = ?, 
                ciudad = ?, estado = ?, telefono_contacto = ?, latitud = ?, longitud = ?, 
                servicios_texto = ?, capacidades_texto = ?, horarios_texto = ? 
            WHERE id = ?`;
        // Asegúrate de que el array de valores tenga el MISMO ORDEN y NÚMERO de elementos que los '?'
        const values = [
            nombre_clinica, calle_numero, colonia, codigo_postal, ciudad, estado, 
            telefono_contacto || null, 
            latitud || null, 
            longitud || null, 
            servicios_texto || null, 
            capacidades_texto || null, 
            horarios_texto || null,
            id // El ID va al final para el WHERE
        ];
        const [result] = await db.query(sql, values);
        if (result.affectedRows === 0) {
            return res.status(404).json({ message: 'Ubicación no encontrada.' });
        }
        res.status(200).json({ message: 'Ubicación actualizada con éxito.' });
    } catch (error) {
        console.error('Error al actualizar ubicación:', error);
        res.status(500).json({ message: 'Error interno del servidor.' });
    }
});

// DELETE: Eliminar una ubicación por su ID
app.delete('/api/ubicaciones/:id',checkAdminRole, async (req, res) => {
    try {
        const { id } = req.params;
        const [result] = await db.query("DELETE FROM Ubicaciones WHERE id = ?", [id]);
        if (result.affectedRows === 0) {
            return res.status(404).json({ message: 'Ubicación no encontrada.' });
        }
        res.status(200).json({ message: 'Ubicación eliminada con éxito.' });
    } catch (error) {
        console.error('Error al eliminar ubicación:', error);
        res.status(500).json({ message: 'Error interno del servidor.' });
    }
});

// --- MANEJO DE RELACIONES ---

// POST: Asignar una ubicación a un veterinario
app.post('/api/veterinarios/:vetId/ubicaciones',checkAdminRole, async (req, res) => {
    try {
        const { vetId } = req.params;
        const { ubicacionId } = req.body;
        if (!ubicacionId) {
            return res.status(400).json({ message: 'El ID de la ubicación es obligatorio.' });
        }
        // Evitar duplicados
        const checkSql = "SELECT * FROM Veterinario_Ubicaciones WHERE veterinario_id = ? AND ubicacion_id = ?";
        const [existing] = await db.query(checkSql, [vetId, ubicacionId]);
        if (existing.length > 0) {
            return res.status(409).json({ message: 'Esta ubicación ya está asignada a este veterinario.' }); // 409 Conflict
        }
        // Insertar la nueva relación
        const insertSql = "INSERT INTO Veterinario_Ubicaciones (veterinario_id, ubicacion_id) VALUES (?, ?)";
        await db.query(insertSql, [vetId, ubicacionId]);
        res.status(201).json({ message: 'Ubicación asignada con éxito.' });
    } catch (error) {
        console.error('Error al asignar ubicación:', error);
        res.status(500).json({ message: 'Error interno del servidor.' });
    }
});



// Endpoint para el inicio de sesión
app.post('/api/login', async (req, res) => {
    try {
    const { email, password } = req.body;
    console.log(`\n--- Intento de login para: ${email} ---`); // <-- LOG 1
    const sql = "SELECT * FROM Usuarios WHERE email = ?";
    const [users] = await db.query(sql, [email]);
    if (users.length === 0) { /* ... */ }
    const user = users[0];
    console.log('Contraseña recibida del front-end:', password); // <-- LOG 2
    console.log('Hash guardado en la Base de Datos:', user.password); // <-- LOG 3
    const isMatch = await bcrypt.compare(password, user.password);
        if (!isMatch) {
            return res.status(401).json({ message: 'Credenciales inválidas.' });
        }
        // 3. Si las credenciales son correctas, crear un token
        const payload = {
            userId: user.id,
            rol: user.rol,
             email: user.email // <-- AÑADE ESTA LÍNEA SI NO LA TIENES
        };
        const token = jwt.sign(payload, JWT_SECRET, { expiresIn: '8h' }); // El token expira en 8 horas
        // 4. Enviar el token al cliente
        res.status(200).json({
            message: 'Inicio de sesión exitoso.',
            token: token
        });
    } catch (error) {
        console.error('Error en el login:', error);
        res.status(500).json({ message: 'Error interno del servidor.' });
    }
});
// --- FIN DEL NUEVO CÓDIGO ---
//

// POST: Solicitar restablecimiento de contraseña
app.post('/api/forgot-password', async (req, res) => {
    try {
        const { email } = req.body;
        if (!email) {
            return res.status(400).json({ message: 'El correo es obligatorio.' });
        }
        // 1. Buscar al usuario por email
        const [users] = await db.query("SELECT * FROM Usuarios WHERE email = ?", [email]);
        // !! IMPORTANTE POR SEGURIDAD !!
        // Siempre envía una respuesta genérica, incluso si el email no existe.
        // Esto evita que alguien pueda adivinar qué correos están registrados.
        if (users.length === 0) {
            console.log(`Intento de restablecimiento para email no registrado: ${email}`);
            return res.status(200).json({ message: 'Si tu correo está registrado, recibirás un enlace.' });
        }
        const user = users[0];
        // 2. Generar un token seguro
        const resetToken = crypto.randomBytes(32).toString('hex');
        // Guarda un hash del token en la BD, no el token original
        const hashedToken = crypto.createHash('sha256').update(resetToken).digest('hex'); 
        // 3. Establecer tiempo de expiración (ej. 1 hora)
        const tokenExpires = new Date(Date.now() + 3600000); // 1 hora en milisegundos
        // 4. Guardar el token HASHEADO y la expiración en la BD
        await db.query(
            "UPDATE Usuarios SET reset_token = ?, reset_token_expires = ? WHERE id = ?",
            [hashedToken, tokenExpires, user.id]
        );
        // 5. Crear el enlace de restablecimiento (para el email)
        // (Asegúrate de cambiar 'localhost:4200' por tu dominio real cuando despliegues)
        const resetUrl = `http://localhost:4200/reset-password?token=${resetToken}`; // Usa el token original aquí
        console.log(`Enlace de restablecimiento generado (NO ENVIADO): ${resetUrl}`); // Para pruebas
        // 6. ---- SIMULACIÓN DE ENVÍO DE EMAIL ----
        // En un proyecto real, configurarías nodemailer aquí para enviar el email.
        // const transporter = nodemailer.createTransport({ /*...config...*/ });
        // await transporter.sendMail({
        //     to: user.email,
        //     subject: 'Restablecimiento de contraseña - VetDirectorio',
        //     html: `<p>Haz clic aquí para restablecer tu contraseña: <a href="${resetUrl}">${resetUrl}</a></p>
        //            <p>Este enlace expira en 1 hora.</p>`
        // });
        // console.log(`Email (simulado) enviado a ${user.email}`);
        // ---- FIN SIMULACIÓN ----
        // 7. Enviar respuesta genérica al front-end
        res.status(200).json({ message: 'Si tu correo está registrado, recibirás un enlace.' });
    } catch (error) {
        console.error('Error en forgot-password:', error);
        res.status(500).json({ message: 'Error interno del servidor.' });
    }
});
// POST: Restablecer la contraseña usando el token
app.post('/api/reset-password', async (req, res) => {
    try {
        const { token, password } = req.body;
        if (!token || !password) {
            return res.status(400).json({ message: 'El token y la nueva contraseña son obligatorios.' });
        }
        // 1. Hashea el token recibido para compararlo con el de la BD
        const hashedToken = crypto.createHash('sha256').update(token).digest('hex');
        // 2. Buscar al usuario por el token HASHEADO y verificar que no haya expirado
        const [users] = await db.query(
            "SELECT * FROM Usuarios WHERE reset_token = ? AND reset_token_expires > NOW()",
            [hashedToken]
        );
        if (users.length === 0) {
            return res.status(400).json({ message: 'Token inválido o expirado.' });
        }
        const user = users[0];
        // 3. Hashear la nueva contraseña
        const salt = await bcrypt.genSalt(10);
        const hashedPassword = await bcrypt.hash(password, salt);
        // 4. Actualizar la contraseña en la BD y limpiar los campos del token
        await db.query(
            "UPDATE Usuarios SET password = ?, reset_token = NULL, reset_token_expires = NULL WHERE id = ?",
            [hashedPassword, user.id]
        );
        // 5. Enviar respuesta de éxito
        res.status(200).json({ message: 'Contraseña actualizada con éxito.' });
    } catch (error) {
        console.error('Error en reset-password:', error);
        res.status(500).json({ message: 'Error interno del servidor.' });
    }
});
// GET: Obtener todas las ubicaciones de un veterinario específico
app.get('/api/veterinarios/:vetId/ubicaciones', async (req, res) => {
    try {
        const { vetId } = req.params;
        // Usamos un JOIN para conectar las tablas y obtener los datos de las ubicaciones
        const sql = `
            SELECT u.* FROM Ubicaciones u
            JOIN Veterinario_Ubicaciones vu ON u.id = vu.ubicacion_id
            WHERE vu.veterinario_id = ?`;
        const [ubicaciones] = await db.query(sql, [vetId]);
        res.status(200).json(ubicaciones);
    } catch (error) {
        console.error('Error al obtener las ubicaciones del veterinario:', error);
        res.status(500).json({ message: 'Error interno del servidor.' });
    }
});
// DELETE: Quitar la asignación de una ubicación a un veterinario
app.delete('/api/veterinarios/:vetId/ubicaciones/:ubicacionId',checkAdminRole, async (req, res) => {
    try {
        const { vetId, ubicacionId } = req.params;
        const sql = "DELETE FROM Veterinario_Ubicaciones WHERE veterinario_id = ? AND ubicacion_id = ?";
        const [result] = await db.query(sql, [vetId, ubicacionId]);
        if (result.affectedRows === 0) {
            return res.status(404).json({ message: 'Asignación no encontrada.' });
        }
        res.status(200).json({ message: 'Asignación de ubicación eliminada con éxito.' });
    } catch (error) {
        console.error('Error al quitar asignación:', error);
        res.status(500).json({ message: 'Error interno del servidor.' });
    }
});
// server.js

// GET: Obtener un solo veterinario por su ID CON sus ubicaciones Y especialidades
app.get('/api/veterinarios/:id', async (req, res) => {
    try {
        const { id } = req.params;
        const vetSql = "SELECT * FROM Veterinarios WHERE id = ?";
        const [vetResult] = await db.query(vetSql, [id]);
        if (vetResult.length === 0) {
            return res.status(404).json({ message: 'Veterinario no encontrado.' });
        }
        const ubicacionesSql = `
            SELECT 
                u.id, u.nombre_clinica, u.calle_numero, u.colonia, 
                u.codigo_postal, u.ciudad, u.estado, u.telefono_contacto, -- <-- Teléfono aquí
                u.latitud, u.longitud, 
                u.servicios_texto, u.capacidades_texto, u.horarios_texto 
            FROM Ubicaciones u 
            JOIN Veterinario_Ubicaciones vu ON u.id = vu.ubicacion_id 
            WHERE vu.veterinario_id = ?`;
        const [ubicaciones] = await db.query(ubicacionesSql, [id]);
        const especialidadesSql = `SELECT e.* FROM Especialidades e JOIN Veterinario_Especialidades ve ON e.id = ve.especialidad_id WHERE ve.veterinario_id = ?`;
        const [especialidades] = await db.query(especialidadesSql, [id]);
        const estudiosSql = `
        SELECT 
            est.id, 
            ne.nombre as nivel_estudio, 
            est.institucion, 
            est.titulo_obtenido, 
            est.ano_graduacion 
        FROM Estudios est 
        JOIN Niveles_Estudio ne ON est.nivel_estudio_id = ne.id 
        WHERE est.veterinario_id = ?`;
        const [estudios] = await db.query(estudiosSql, [id]);
        const [imagenes] = await db.query(
            "SELECT id, imagen_url, descripcion FROM Veterinario_Imagenes WHERE veterinario_id = ? ORDER BY fecha_subida DESC", 
            [id]
        );
        const perfilCompleto = {
            ...vetResult[0],
            ubicaciones: ubicaciones,
            especialidades: especialidades,
            estudios: estudios, // <-- AÑADE LOS ESTUDIOS AL OBJETO
            imagenes: imagenes
        };
        res.status(200).json(perfilCompleto);
    } catch (error) {
        console.error('Error al obtener el perfil del veterinario:', error);
        res.status(500).json({ message: 'Error interno del servidor.' });
    }
});
// GET: Obtener todas las especialidades
app.get('/api/especialidades', async (req, res) => {
    try {
        const [especialidades] = await db.query("SELECT * FROM Especialidades ORDER BY nombre ASC");
        res.status(200).json(especialidades);
    } catch (error) {
        console.error('Error al obtener especialidades:', error);
        res.status(500).json({ message: 'Error interno del servidor.' });
    }
});
// POST: Crear una nueva especialidad
app.post('/api/especialidades',checkAdminRole, async (req, res) => {
    try {
        const { nombre } = req.body;
        if (!nombre) {
            return res.status(400).json({ message: 'El campo nombre es obligatorio.' });
        }
        const sql = `INSERT INTO Especialidades (nombre) VALUES (?)`;
        const [result] = await db.query(sql, [nombre]);
        res.status(201).json({ message: 'Especialidad creada con éxito.', nuevoId: result.insertId });
    } catch (error) {
        // Manejar error de duplicado (código de error 1062 en MySQL)
        if (error.code === 'ER_DUP_ENTRY') {
            return res.status(409).json({ message: 'Esa especialidad ya existe.' });
        }
        console.error('Error al crear especialidad:', error);
        res.status(500).json({ message: 'Error interno del servidor.' });
    }
});
// PUT: Actualizar una especialidad por su ID
app.put('/api/especialidades/:id',checkAdminRole, async (req, res) => {
    try {
        const { id } = req.params;
        const { nombre } = req.body;
        if (!nombre) {
            return res.status(400).json({ message: 'El campo nombre es obligatorio.' });
        }
        const sql = `UPDATE Especialidades SET nombre = ? WHERE id = ?`;
        const [result] = await db.query(sql, [nombre, id]);
        if (result.affectedRows === 0) {
            return res.status(404).json({ message: 'Especialidad no encontrada.' });
        }
        res.status(200).json({ message: 'Especialidad actualizada con éxito.' });
    } catch (error) {
        if (error.code === 'ER_DUP_ENTRY') {
            return res.status(409).json({ message: 'Esa especialidad ya existe.' });
        }
        console.error('Error al actualizar especialidad:', error);
        res.status(500).json({ message: 'Error interno del servidor.' });
    }
});
// DELETE: Eliminar una especialidad por su ID
app.delete('/api/especialidades/:id',checkAdminRole, async (req, res) => {
    try {
        const { id } = req.params;
        const [result] = await db.query("DELETE FROM Especialidades WHERE id = ?", [id]);
        if (result.affectedRows === 0) {
            return res.status(404).json({ message: 'Especialidad no encontrada.' });
        }
        res.status(200).json({ message: 'Especialidad eliminada con éxito.' });
    } catch (error) {
        console.error('Error al eliminar especialidad:', error);
        res.status(500).json({ message: 'Error interno del servidor.' });
    }
});
// POST: Asignar una especialidad a un veterinario
app.post('/api/veterinarios/:vetId/especialidades',checkAdminRole, async (req, res) => {
    try {
        const { vetId } = req.params;
        const { especialidadId } = req.body;
        if (!especialidadId) {
            return res.status(400).json({ message: 'El ID de la especialidad es obligatorio.' });
        }
        // Evitar duplicados
        const checkSql = "SELECT * FROM Veterinario_Especialidades WHERE veterinario_id = ? AND especialidad_id = ?";
        const [existing] = await db.query(checkSql, [vetId, especialidadId]);
        if (existing.length > 0) {
            return res.status(409).json({ message: 'Esta especialidad ya está asignada a este veterinario.' });
        }
        // Insertar la nueva relación
        const insertSql = "INSERT INTO Veterinario_Especialidades (veterinario_id, especialidad_id) VALUES (?, ?)";
        await db.query(insertSql, [vetId, especialidadId]);
        res.status(201).json({ message: 'Especialidad asignada con éxito.' });
    } catch (error) {
        console.error('Error al asignar especialidad:', error);
        res.status(500).json({ message: 'Error interno del servidor.' });
    }
});
// DELETE: Quitar la asignación de una especialidad a un veterinario
app.delete('/api/veterinarios/:vetId/especialidades/:especialidadId',checkAdminRole, async (req, res) => {
    try {
        const { vetId, especialidadId } = req.params;
        const sql = "DELETE FROM Veterinario_Especialidades WHERE veterinario_id = ? AND especialidad_id = ?";
        const [result] = await db.query(sql, [vetId, especialidadId]);
        if (result.affectedRows === 0) {
            return res.status(404).json({ message: 'Asignación no encontrada.' });
        }
        res.status(200).json({ message: 'Asignación de especialidad eliminada con éxito.' });
    } catch (error) {
        console.error('Error al quitar asignación de especialidad:', error);
        res.status(500).json({ message: 'Error interno del servidor.' });
    }
});

// server.js

// POST: Registrar un nuevo usuario (con encriptación)
// POST: Registrar un nuevo usuario (CORREGIDO Y SEGURO)
app.post('/api/register', async (req, res) => {
    try {
        // 1. SOLO extraemos email y password. Ignoramos 'rol' del body.
        const { email, password } = req.body; 
        if (!email || !password) {
            return res.status(400).json({ message: 'Email y contraseña son obligatorios.' });
        }
        // 2. Definimos el rol manualmente. Todos los registros nuevos son 'veterinario'.
        const rol = 'veterinario'; 
        // 3. Encriptar la contraseña
        const salt = await bcrypt.genSalt(10);
        const hashedPassword = await bcrypt.hash(password, salt);
        // 4. Guardar el nuevo usuario con el rol 'veterinario'
        const sql = "INSERT INTO Usuarios (email, password, rol) VALUES (?, ?, ?)";
        const [result] = await db.query(sql, [email, hashedPassword, rol]);
        res.status(201).json({ message: 'Usuario registrado con éxito.', userId: result.insertId });
    } catch (error) {
        if (error.code === 'ER_DUP_ENTRY') {
            return res.status(409).json({ message: 'El correo electrónico ya está en uso.' });
        }
        console.error('Error en el registro:', error);
        res.status(500).json({ message: 'Error interno del servidor.' });
    }
});
// server.js

// Middleware para verificar que hay un token y adjuntar el usuario a la petición
const authenticateToken = (req, res, next) => {
    const authHeader = req.headers['authorization'];
    const token = authHeader && authHeader.split(' ')[1];
    if (token == null) return res.sendStatus(401);
    jwt.verify(token, JWT_SECRET, (err, user) => {
        if (err) return res.sendStatus(403);
        req.user = user; // Adjunta el payload del token (userId, rol, email)
        next();
    });
};

// --- AÑADE ESTOS DOS NUEVOS ENDPOINTS ---

// GET: Obtener el perfil del veterinario actualmente logueado
app.get('/api/perfil', authenticateToken, async (req, res) => {
    try {
        const userId = req.user.userId; // Obtenemos el ID del token, no de la URL
        const sql = "SELECT * FROM Veterinarios WHERE usuario_id = ?";
        const [vetResult] = await db.query(sql, [userId]);
        if (vetResult.length === 0) {
            return res.status(404).json({ message: 'Perfil de veterinario no encontrado para este usuario.' });
        }
        res.status(200).json(vetResult[0]);
    } catch (error) {
        res.status(500).json({ message: 'Error interno del servidor.' });
    }
});

// PUT: Actualizar el perfil del veterinario actualmente logueado
app.put('/api/perfil', authenticateToken, async (req, res) => {
    try {
        const userId = req.user.userId;
        // Definimos los campos que el veterinario SÍ puede editar
        const { descripcion, costo_consulta, acepta_urgencias } = req.body;
        const sql = `UPDATE Veterinarios SET descripcion = ?, costo_consulta = ?, acepta_urgencias = ? WHERE usuario_id = ?`;
        const [result] = await db.query(sql, [descripcion, costo_consulta, acepta_urgencias, userId]);
        if (result.affectedRows === 0) {
            return res.status(404).json({ message: 'Perfil de veterinario no encontrado.' });
        }
        res.status(200).json({ message: 'Perfil actualizado con éxito.' });
    } catch (error) {
        res.status(500).json({ message: 'Error interno del servidor.' });
    }
});
// GET: Obtener usuarios que NO tienen un perfil de veterinario asociado
app.get('/api/usuarios-sin-perfil', checkAdminRole, async (req, res) => { // Protegido para admin
    try {
        // Esta consulta busca usuarios cuyo ID NO está en la columna usuario_id de Veterinarios
        const sql = `
            SELECT u.id, u.email, u.rol 
            FROM Usuarios u
            LEFT JOIN Veterinarios v ON u.id = v.usuario_id
            WHERE v.usuario_id IS NULL 
            ORDER BY u.email ASC; 
        `;
        const [usuarios] = await db.query(sql);
        res.status(200).json(usuarios);
    } catch (error) {
        console.error('Error al obtener usuarios sin perfil:', error);
        res.status(500).json({ message: 'Error interno del servidor.' });
    }
});
app.post('/api/ubicaciones', async (req, res) => {
    try {
        // Añade servicios_texto aquí
        const { nombre_clinica, calle_numero, colonia, codigo_postal, ciudad, estado, servicios_texto, capacidades_texto, horarios_texto } = req.body;
        // ... (validación existente)
        const sql = `INSERT INTO Ubicaciones (nombre_clinica, calle_numero, colonia, codigo_postal, ciudad, estado, servicios_texto, capacidades_texto, horarios_texto) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)`; // Añade '?'
        const [result] = await db.query(sql, [nombre_clinica, calle_numero, colonia, codigo_postal, ciudad, estado, servicios_texto, capacidades_texto, horarios_texto]); // Añade la variable
        // ... (respuesta)
    } catch (error) { /* ... */ }
});

// --- MANEJO DE RELACIONES (ESTUDIOS) ---

// POST: Agregar un estudio a un veterinario
app.post('/api/veterinarios/:vetId/estudios', checkAdminRole, async (req, res) => {
    try {
        const { vetId } = req.params;
        // nivel_estudio_id viene del dropdown, institucion y titulo del input
        const { nivel_estudio_id, institucion, titulo_obtenido, ano_graduacion } = req.body;

        if (!nivel_estudio_id || !institucion || !titulo_obtenido) {
            return res.status(400).json({ message: 'Nivel, institución y título son obligatorios.' });
        }

        const sql = `INSERT INTO Estudios (veterinario_id, nivel_estudio_id, institucion, titulo_obtenido, ano_graduacion) VALUES (?, ?, ?, ?, ?)`;
        const [result] = await db.query(sql, [vetId, nivel_estudio_id, institucion, titulo_obtenido, ano_graduacion || null]); // Permite año nulo

        res.status(201).json({ message: 'Estudio agregado con éxito.', nuevoId: result.insertId });

    } catch (error) {
        console.error('Error al agregar estudio:', error);
        res.status(500).json({ message: 'Error interno del servidor.' });
    }
});

// DELETE: Eliminar un estudio por su ID específico
app.delete('/api/estudios/:estudioId', checkAdminRole, async (req, res) => {
    try {
        const { estudioId } = req.params;
        const sql = "DELETE FROM Estudios WHERE id = ?";
        const [result] = await db.query(sql, [estudioId]);

        if (result.affectedRows === 0) {
            return res.status(404).json({ message: 'Estudio no encontrado.' });
        }
        res.status(200).json({ message: 'Estudio eliminado con éxito.' });
    } catch (error) {
        console.error('Error al eliminar estudio:', error);
        res.status(500).json({ message: 'Error interno del servidor.' });
    }
});

// GET: Obtener todos los niveles de estudio (para el dropdown)
app.get('/api/niveles-estudio', async (req, res) => {
    try {
        const [niveles] = await db.query("SELECT * FROM Niveles_Estudio ORDER BY id");
        res.status(200).json(niveles);
    } catch (error) {
        console.error('Error al obtener niveles de estudio:', error);
        res.status(500).json({ message: 'Error interno del servidor.' });
    }
});


// --- MANEJO DE IMAGENES ADICIONALES DEL VETERINARIO ---

// GET: Obtener todas las imágenes adicionales de un veterinario
// (No necesita protección especial ya que es información pública del perfil)
app.get('/api/veterinarios/:vetId/imagenes', async (req, res) => {
    try {
        const { vetId } = req.params;
        const [imagenes] = await db.query(
            "SELECT id, imagen_url, descripcion FROM Veterinario_Imagenes WHERE veterinario_id = ? ORDER BY fecha_subida DESC", 
            [vetId]
        );
        res.status(200).json(imagenes);
    } catch (error) {
        console.error('Error al obtener imágenes del veterinario:', error);
        res.status(500).json({ message: 'Error interno del servidor.' });
    }
});

// POST: Subir una nueva imagen adicional para un veterinario
// 'additionalImage' será el nombre del campo en el form-data
app.post('/api/veterinarios/:vetId/imagenes', authenticateToken, upload.single('additionalImage'), async (req, res) => {
    try {
        const { vetId } = req.params;
        const loggedInUserId = req.user.userId; // ID del usuario que hace la petición (del token)
        const userRole = req.user.rol;
        if (!req.file) {
            return res.status(400).json({ message: 'No se subió ningún archivo.' });
        }
        // 1. Verificar si el veterinario existe
        const [vetResult] = await db.query("SELECT usuario_id FROM Veterinarios WHERE id = ?", [vetId]);
        if (vetResult.length === 0) {
            return res.status(404).json({ message: 'Veterinario no encontrado.' });
        }
        const vetOwnerUserId = vetResult[0].usuario_id;
        // 2. Verificar Permisos: ¿Es admin O es el dueño del perfil?
        if (userRole !== 'admin' && loggedInUserId !== vetOwnerUserId) {
            return res.status(403).json({ message: 'No tienes permiso para subir fotos a este perfil.' });
        }
        
        // 3. Subir a Cloudinary (similar a la foto de perfil, puedes ajustar transformaciones)
        const uploadStream = cloudinary.uploader.upload_stream(
            { 
                folder: `vet_galleries/${vetId}`, // Carpeta específica para cada vet
                 transformation: [ // Ejemplo: Limitar tamaño
                    { width: 1024, height: 1024, crop: "limit" } 
                ]
            },
            async (error, result) => {
                if (error || !result) { /* ... manejo de error ... */ return res.status(500).json({ message: 'Error al subir la imagen.' }); }
                const imageUrl = result.secure_url;
                const description = req.body.descripcion || null; // Opcional: Descripción desde el form-data
                try {
                    // 4. Guardar URL en la nueva tabla
                    const [insertResult] = await db.query(
                        "INSERT INTO Veterinario_Imagenes (veterinario_id, imagen_url, descripcion) VALUES (?, ?, ?)",
                        [vetId, imageUrl, description]
                    );
                    res.status(201).json({ 
                        message: 'Imagen agregada con éxito.', 
                        id: insertResult.insertId, 
                        imagen_url: imageUrl, 
                        descripcion: description 
                    });
                } catch (dbError) { /* ... manejo de error BD ... */ }
            }
        );
        uploadStream.end(req.file.buffer);
    } catch (error) {
        console.error('Error al subir imagen adicional:', error);
        res.status(500).json({ message: 'Error interno del servidor.' });
    }
});

// DELETE: Eliminar una imagen adicional por su ID
app.delete('/api/imagenes/:imageId', authenticateToken, async (req, res) => {
    try {
        const { imageId } = req.params;
        const loggedInUserId = req.user.userId;
        const userRole = req.user.rol;
        // 1. Obtener la imagen y a qué veterinario pertenece
        const [imageResult] = await db.query(
            "SELECT i.imagen_url, v.usuario_id FROM Veterinario_Imagenes i JOIN Veterinarios v ON i.veterinario_id = v.id WHERE i.id = ?",
            [imageId]
        );
        if (imageResult.length === 0) {
            return res.status(404).json({ message: 'Imagen no encontrada.' });
        }
        const vetOwnerUserId = imageResult[0].usuario_id;
        // 2. Verificar Permisos: ¿Es admin O es el dueño del perfil?
        if (userRole !== 'admin' && loggedInUserId !== vetOwnerUserId) {
            return res.status(403).json({ message: 'No tienes permiso para eliminar esta imagen.' });
        }
        // 3. Eliminar de la Base de Datos
        await db.query("DELETE FROM Veterinario_Imagenes WHERE id = ?", [imageId]);
        
        // 4. Opcional: Eliminar de Cloudinary (requiere el public_id si lo guardaste o extraerlo de la URL)
        // const publicId = ... extraer de imageResult[0].imagen_url ...;
        // if (publicId) cloudinary.uploader.destroy(publicId);
        res.status(200).json({ message: 'Imagen eliminada con éxito.' });
    } catch (error) {
        console.error('Error al eliminar imagen:', error);
        res.status(500).json({ message: 'Error interno del servidor.' });
    }
});



// 5. Iniciar el servidor
app.listen(port, () => {
    console.log(`Servidor corriendo en http://localhost:${port}`);
    console.log('Presiona CTRL+C para detener el servidor.');
});

