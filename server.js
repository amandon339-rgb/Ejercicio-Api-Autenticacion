
const express = require("express");
const bcrypt = require("bcryptjs");
const fs = require("fs");
const path = require("path");

const app = express();
const PORT = process.env.PORT || 3000;

// Permite recibir solicitudes cuyo contenido está en formato JSON.
app.use(express.json());

// Define la ubicación del archivo donde se almacenan los usuarios.
const dataDirectory = path.join(__dirname, "data");
const usersFile = path.join(dataDirectory, "users.json");

// Crea la carpeta y el archivo de usuarios si todavía no existen.
if (!fs.existsSync(dataDirectory)) {
  fs.mkdirSync(dataDirectory, { recursive: true });
}

if (!fs.existsSync(usersFile)) {
  fs.writeFileSync(usersFile, "[]", "utf8");
}

// Lee los usuarios guardados en el archivo JSON.
function readUsers() {
  return JSON.parse(fs.readFileSync(usersFile, "utf8"));
}

// Guarda la lista actualizada de usuarios.
function saveUsers(users) {
  fs.writeFileSync(
    usersFile,
    JSON.stringify(users, null, 2),
    "utf8"
  );
}

// Ruta inicial para comprobar que el servicio está activo.
app.get("/", (req, res) => {
  res.status(200).json({
    mensaje: "API de autenticación funcionando correctamente."
  });
});

// REGISTRO: crea una cuenta con usuario y contraseña.
app.post("/api/auth/register", async (req, res) => {
  try {
    const { usuario, contrasena } = req.body;

    // Comprueba que se hayan enviado los dos campos.
    if (
      typeof usuario !== "string" ||
      typeof contrasena !== "string" ||
      !usuario.trim() ||
      !contrasena
    ) {
      return res.status(400).json({
        mensaje: "Debe proporcionar un usuario y una contraseña."
      });
    }

    const nombreUsuario = usuario.trim();

    // Evita registrar dos cuentas con el mismo nombre.
    const users = readUsers();
    const existe = users.some(
      (user) => user.usuario.toLowerCase() === nombreUsuario.toLowerCase()
    );

    if (existe) {
      return res.status(409).json({
        mensaje: "El usuario ya está registrado."
      });
    }

    // Convierte la contraseña en un hash antes de almacenarla.
    const hash = await bcrypt.hash(contrasena, 10);

    // Guarda el usuario y el hash, nunca la contraseña original.
    users.push({
      usuario: nombreUsuario,
      contrasena: hash
    });

    saveUsers(users);

    return res.status(201).json({
      mensaje: "Usuario registrado correctamente."
    });
  } catch (error) {
    console.error("Error en el registro:", error);

    return res.status(500).json({
      mensaje: "Error interno al registrar el usuario."
    });
  }
});

// INICIO DE SESIÓN: verifica las credenciales recibidas.
app.post("/api/auth/login", async (req, res) => {
  try {
    const { usuario, contrasena } = req.body;

    // Valida que los campos sean cadenas de texto no vacías.
    if (
      typeof usuario !== "string" ||
      typeof contrasena !== "string" ||
      !usuario.trim() ||
      !contrasena
    ) {
      return res.status(400).json({
        mensaje: "Debe proporcionar un usuario y una contraseña."
      });
    }

    const users = readUsers();

    // Busca la cuenta sin distinguir mayúsculas y minúsculas.
    const user = users.find(
      (item) =>
        item.usuario.toLowerCase() === usuario.trim().toLowerCase()
    );

    // Si la cuenta no existe, rechaza la autenticación.
    if (!user) {
      return res.status(401).json({
        mensaje: "Error en la autenticación."
      });
    }

    // Compara la contraseña recibida con el hash almacenado.
    const passwordCorrecta = await bcrypt.compare(
      contrasena,
      user.contrasena
    );

    if (!passwordCorrecta) {
      return res.status(401).json({
        mensaje: "Error en la autenticación."
      });
    }

    // Devuelve una respuesta positiva si las credenciales coinciden.
    return res.status(200).json({
      mensaje: "Autenticación satisfactoria."
    });
  } catch (error) {
    console.error("Error en el inicio de sesión:", error);

    return res.status(500).json({
      mensaje: "Error interno durante la autenticación."
    });
  }
});

// Inicia el servidor para recibir solicitudes HTTP.
app.listen(PORT, () => {
  console.log(`API disponible en http://localhost:${PORT}`);
});
