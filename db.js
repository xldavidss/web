// Archivo: db.js
// Su única responsabilidad es crear y exportar la conexión a la base de datos.

const mysql = require('mysql2');

// 1. Creamos el objeto con las "credenciales"
// Esta configuración es la estándar para XAMPP.
const connection = mysql.createConnection({
  host: 'localhost',
  user: 'root',
  password: '',
  database: 'reports',
  port: 3306 // El puerto por defecto de MySQL que se ve en tu XAMPP
});

// 2. Intentamos establecer la conexión
connection.connect(error => {
  if (error) {
    // Si hay un error, lo mostramos en la consola y detenemos todo.
    console.error('ERROR: No se pudo conectar a la base de datos.', error);
    return;
  }
  console.log('¡Conexión a la base de datos MySQL exitosa!');
});

// 3. Hacemos que la conexión esté disponible para otros archivos
module.exports = connection;
