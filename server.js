// 1. IMPORTACIONES
const express = require('express');
const cors = require('cors');
const bcrypt = require('bcryptjs');
const jwt = require('jsonwebtoken');
const db = require('./db.js');
const multer = require('multer'); // Para manejar la subida de archivos
const path = require('path');   // Para manejar rutas de archivos
const fs = require('fs');         // Para manejar el sistema de archivos
const PDFDocument = require('pdfkit'); // Para crear PDFs

// 2. CONFIGURACIÓN INICIAL
const app = express();
const PORT = 3000;
const JWT_SECRET = 'tu_secreto_super_secreto_y_largo_para_produccion';

// 3. MIDDLEWARES
app.use(cors());
app.use(express.json());
// Servir archivos estáticos (imágenes subidas)
app.use('/uploads', express.static(path.join(__dirname, 'uploads')));

// Configuración de Multer para la subida de avatares
const avatarStorage = multer.diskStorage({
    destination: (req, file, cb) => {
        cb(null, 'uploads/avatars/');
    },
    filename: (req, file, cb) => {
        // Aseguramos un nombre de archivo único para evitar sobreescribir
        cb(null, `avatar-${req.user.userId}-${Date.now()}${path.extname(file.originalname)}`);
    }
});
const uploadAvatar = multer({ storage: avatarStorage });

// Configuración de Multer para la subida de imágenes de reportes
const reportStorage = multer.diskStorage({
    destination: (req, file, cb) => {
        cb(null, 'uploads/reports/');
    },
    filename: (req, file, cb) => {
        cb(null, `report-${Date.now()}-${file.originalname}`);
    }
});
const uploadReportImages = multer({ storage: reportStorage });


// Middleware para verificar el Token JWT
const authMiddleware = (req, res, next) => {
    const authHeader = req.headers.authorization;
    if (!authHeader || !authHeader.startsWith('Bearer ')) {
        return res.status(401).json({ message: 'Acceso denegado. No se proveyó un token.' });
    }
    const token = authHeader.split(' ')[1];
    try {
        const decoded = jwt.verify(token, JWT_SECRET);
        req.user = decoded; // Añadimos los datos del token (id, email, role) a la petición
        next();
    } catch (error) {
        res.status(401).json({ message: 'Token inválido.' });
    }
};

// 4. RUTAS DE AUTENTICACIÓN
app.post('/login', (req, res) => {
    const { email, password } = req.body;
    const sql = "SELECT * FROM users WHERE email = ?";
    db.query(sql, [email], async (err, results) => {
        if (err || results.length === 0) {
            return res.status(401).json({ message: 'Correo o contraseña incorrectos.' });
        }
        const user = results[0];
        const isMatch = await bcrypt.compare(password, user.password);
        if (!isMatch) {
            return res.status(401).json({ message: 'Correo o contraseña incorrectos.' });
        }
        // IMPORTANTE: Incluimos el ROL en el token
        const token = jwt.sign(
            { userId: user.id, email: user.email, role: user.role },
            JWT_SECRET,
            { expiresIn: '8h' }
        );
        res.json({ message: 'Inicio de sesión exitoso', token, role: user.role });
    });
});

app.post('/register', async (req, res) => {
    const { name, email, password } = req.body;
    if (!name || !email || !password) {
        return res.status(400).json({ message: 'Por favor, completa todos los campos.' });
    }
    try {
        const hashedPassword = await bcrypt.hash(password, 10);
        // Por defecto, el rol es 'empleado' según la DB
        const sql = "INSERT INTO users (name, email, password) VALUES (?, ?, ?)";
        db.query(sql, [name, email, hashedPassword], (err, result) => {
            if (err) {
                 if (err.code === 'ER_DUP_ENTRY') {
                    return res.status(409).json({ message: 'El correo electrónico ya está registrado.' });
                }
                return res.status(500).json({ message: 'Error en el servidor.' });
            }
            res.status(201).json({ message: 'Usuario registrado con éxito.' });
        });
    } catch (error) {
         res.status(500).json({ message: 'Error interno del servidor.' });
    }
});


// 5. RUTAS DE LA APLICACIÓN (Protegidas)

// Obtener datos del usuario actual (nombre, email, avatar)
app.get('/api/user', authMiddleware, (req, res) => {
    const sql = "SELECT id, name, email, role, avatar_url FROM users WHERE id = ?";
    db.query(sql, [req.user.userId], (err, results) => {
        if (err || results.length === 0) {
            return res.status(404).json({ message: 'Usuario no encontrado.' });
        }
        res.json(results[0]);
    });
});

// ... dentro de server.js

// OBTENER DETALLES DE UN REPORTE ESPECÍFICO (Solo Admin)
app.get('/api/reports/:id', authMiddleware, (req, res) => {
    if (req.user.role !== 'administrador') {
        return res.status(403).json({ message: 'Acceso denegado.' });
    }
    const reportId = req.params.id;
    const reportSql = "SELECT r.report_text, r.created_at, u.name as userName FROM reports r JOIN users u ON r.user_id = u.id WHERE r.id = ?";
    const imagesSql = "SELECT image_url FROM report_images WHERE report_id = ?";

    db.query(reportSql, [reportId], (err, reportResult) => {
        if (err || reportResult.length === 0) return res.status(404).json({ message: 'Reporte no encontrado.' });
        
        db.query(imagesSql, [reportId], (err, imagesResult) => {
            if (err) return res.status(500).json({ message: 'Error al obtener imágenes.' });
            
            res.json({
                ...reportResult[0],
                images: imagesResult.map(img => img.image_url)
            });
        });
    });
});

// OBTENER ESTADÍSTICAS GENERALES (Solo Admin)
app.get('/api/admin/stats', authMiddleware, (req, res) => {
    if (req.user.role !== 'administrador') {
        return res.status(403).json({ message: 'Acceso denegado.' });
    }
    const usersSql = "SELECT COUNT(id) as totalUsers FROM users WHERE role = 'empleado'";
    const reportsSql = "SELECT COUNT(id) as totalReports, DATE(created_at) as date FROM reports GROUP BY DATE(created_at) ORDER BY date DESC LIMIT 7";

    db.query(usersSql, (err, usersResult) => {
        if (err) return res.status(500).json({ message: 'Error al contar usuarios.' });
        
        db.query(reportsSql, (err, reportsResult) => {
            if (err) return res.status(500).json({ message: 'Error al obtener estadísticas de reportes.' });
            
            const totalReports = reportsResult.reduce((sum, r) => sum + r.totalReports, 0);

            res.json({
                totalUsers: usersResult[0].totalUsers,
                totalReports: totalReports,
                reportsByDay: reportsResult.reverse() // para que el gráfico muestre del más antiguo al más nuevo
            });
        });
    });
});


// ... el resto de tu server.js

// Actualizar foto de perfil
app.post('/api/upload-avatar', authMiddleware, uploadAvatar.single('avatar'), (req, res) => {
    if (!req.file) {
        return res.status(400).json({ message: 'No se subió ningún archivo.' });
    }
    const avatar_url = `/uploads/avatars/${req.file.filename}`;
    const sql = "UPDATE users SET avatar_url = ? WHERE id = ?";
    db.query(sql, [avatar_url, req.user.userId], (err, result) => {
        if (err) {
            return res.status(500).json({ message: 'Error al actualizar la foto en la base de datos.' });
        }
        res.json({ message: 'Foto de perfil actualizada.', avatar_url });
    });
});

// Enviar un reporte con múltiples imágenes
app.post('/api/submit-report', authMiddleware, uploadReportImages.array('reportImages', 5), (req, res) => {
    const { reportText } = req.body;
    const userId = req.user.userId;

    if (!reportText) {
        return res.status(400).json({ message: 'El texto del reporte es obligatorio.' });
    }

    const reportSql = "INSERT INTO reports (user_id, report_text) VALUES (?, ?)";
    db.query(reportSql, [userId, reportText], (err, result) => {
        if (err) {
            return res.status(500).json({ message: 'Error al guardar el reporte.' });
        }
        const reportId = result.insertId;
        
        if (req.files && req.files.length > 0) {
            const images = req.files.map(file => [reportId, `/uploads/reports/${file.filename}`]);
            const imagesSql = "INSERT INTO report_images (report_id, image_url) VALUES ?";
            db.query(imagesSql, [images], (err, result) => {
                if (err) {
                    return res.status(500).json({ message: 'Reporte guardado, pero hubo un error con las imágenes.' });
                }
                res.status(201).json({ message: 'Reporte e imágenes enviados con éxito.' });
            });
        } else {
            res.status(201).json({ message: 'Reporte enviado con éxito.' });
        }
    });
});

// OBTENER TODOS LOS REPORTES (Solo para rol 'administrador')
app.get('/api/reports', authMiddleware, (req, res) => {
    if (req.user.role !== 'administrador') {
        return res.status(403).json({ message: 'Acceso denegado. Se requiere rol de administrador.' });
    }
    
    const sql = `
        SELECT r.id, r.report_text, r.created_at, u.name as userName 
        FROM reports r
        JOIN users u ON r.user_id = u.id
        ORDER BY r.created_at DESC
    `;
    db.query(sql, (err, results) => {
        if (err) {
            return res.status(500).json({ message: 'Error al obtener los reportes.' });
        }
        res.json(results);
    });
});

// DESCARGAR UN REPORTE COMO PDF (Solo para rol 'administrador')
app.get('/api/reports/:id/pdf', authMiddleware, (req, res) => {
    if (req.user.role !== 'administrador') {
        return res.status(403).json({ message: 'Acceso denegado.' });
    }

    const reportId = req.params.id;

    const reportSql = "SELECT r.*, u.name, u.email FROM reports r JOIN users u ON r.user_id = u.id WHERE r.id = ?";
    db.query(reportSql, [reportId], (err, reportResults) => {
        if (err || reportResults.length === 0) {
            return res.status(404).send('Reporte no encontrado');
        }
        const report = reportResults[0];

        const imagesSql = "SELECT image_url FROM report_images WHERE report_id = ?";
        db.query(imagesSql, [reportId], (err, imageResults) => {
            if (err) {
                return res.status(500).send('Error al obtener imágenes del reporte.');
            }

            const doc = new PDFDocument({ margin: 50 });
            res.setHeader('Content-Type', 'application/pdf');
            res.setHeader('Content-Disposition', `attachment; filename=reporte-${report.id}.pdf`);
            doc.pipe(res);

            // Contenido del PDF
            doc.fontSize(20).text(`Reporte #${report.id}`, { align: 'center' });
            doc.moveDown();
            doc.fontSize(12).text(`Fecha: ${new Date(report.created_at).toLocaleString('es-CO')}`);
            doc.text(`Empleado: ${report.name} (${report.email})`);
            doc.moveDown();
            doc.fontSize(16).text('Descripción del Reporte:', { underline: true });
            doc.fontSize(12).text(report.report_text);
            doc.moveDown();

            if (imageResults.length > 0) {
                doc.addPage().fontSize(16).text('Imágenes Adjuntas:', { underline: true }).moveDown();
                
                // Usamos un bucle for...of para manejar la asincronía de la existencia de archivos
                for (const image of imageResults) {
                    const imagePath = path.join(__dirname, image.image_url);
                    if (fs.existsSync(imagePath)) {
                        doc.image(imagePath, { fit: [500, 400], align: 'center' });
                        doc.moveDown();
                    }
                }
            }

            doc.end();
        });
    });
});


// 6. INICIAR EL SERVIDOR
app.listen(PORT, () => {
    console.log(`Servidor corriendo en http://localhost:${PORT}`);
});