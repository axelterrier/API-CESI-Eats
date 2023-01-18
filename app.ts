//#region require

require("dotenv").config();
require("./config/mongoose").connect();

const cors = require("cors");
const { config } = require("./config/SQLServer");
const { exit } = require("process");
const { default: jwtDecode } = require("jwt-decode");
const { format } = require('date-fns');
const MongoClient = require('mongodb').MongoClient;
const mongoose = require('mongoose');
const sql = require("mssql");
const express = require("express");
const bcrypt = require('bcryptjs');
const jwt = require("jsonwebtoken");
const cookieParser = require('cookie-parser');
const app = express();
const auth = require("./middleware/auth");
const jwt_decode = require("jwt-decode");
const Menu = require("./model/menuMongoose.ts")
const Logs = require("./model/logMongoose.ts")
const Commande = require("./model/commandeMongoose.ts")
const Perf = require("./model/perfMongoose.ts")
const swaggerJsDoc = require('swagger-jsdoc')
const swaggerUi = require('swagger-ui-express')
const url = "/api/V1"
const swaggerOptions = {
  swaggerDefinition: {
    info: {
      title: "API Client",
      contact: {
        name: "UwU Eats"
      },
      servers: ["https://localhost:8888/api/V1"]
    }
  },
  // on donne l'endroit ou sont les routes
  apis: ["app.ts"]
};

app.use(cors({ origin: 'http://localhost:8100/', methods: "GET,HEAD,PUT,PATCH,POST,DELETE", allowedHeaders: ['content-type'], credentials: true }));
const swaggerDocs = swaggerJsDoc(swaggerOptions)
//#endregion

app.use('/api-docs', swaggerUi.serve, swaggerUi.setup(swaggerDocs));

app.use(cookieParser());
app.use(express.json());

var listener = app.listen(8888, function () {
  console.log('Listening on port ' + listener.address().port); //Listening on port 8888
});

//#region route

//#region api utilisateur

// Register dans la table person et la table client
/**
 * @swagger
 * /api/V1/register/client:
 *   post:
 *     tags:
 *       - Connexion
 *     description: Register a new client
 *     produces:
 *       - application/json
 *     parameters:
 *       - name: body
 *         description: client object
 *         in: body
 *         required: true
 *         schema:
 *           $ref: '#/definitions/Client'
 *     responses:
 *       201:
 *         description: client created successfully
 *       400:
 *         description: email already exists
 *       500:
 *         description: internal server error
 */
/**
 *  @swagger
 *  definitions:
 *    Client:
 *      type: object
 *      required:
 *        - name
 *        - phone_number
 *        - email
 *        - password
 *      properties:
 *        name:
 *          type: string
 *        phone_number:
 *          type: string
 *        email:
 *          type: string
 *          format: email
 *        password:
 *          type: string
 */
app.post(url + "/register/client", async (req, res) => {
  let data = req.body;
  try {

    let pool = await sql.connect(config);
    let userAlreadyExist = false;

    const requestSelect = pool.request();
    requestSelect.input("email", sql.VarChar, data.email);
    const result = await requestSelect.query(
      "SELECT COUNT (*) AS compte FROM dbo.person WHERE email = @email"
    );
    if (parseInt(JSON.stringify(result.recordset[0].compte)) != 0) {
      userAlreadyExist = true;
    }

    if (userAlreadyExist) {
      const log = new Logs({
        logType: 'inscription client',
        timestamp: new Date(),
        email: data.email,
        success: false,
        error_message: 'Adresse mail déjà utilisée'
      });
      await log.save();
      res
        .status(400)
        .send(`L'addresse mail : "${data.email}" est déjà utilisée, veuillez vous connecter`)
        .end();
    } else {
      let encryptedPassword = await bcrypt.hash(data.password, 10);

      const request = pool.request();
      request.input("name", sql.VarChar, data.name);
      request.input("phone_number", sql.VarChar, data.phone_number);
      request.input("email", sql.VarChar, data.email);
      request.input("password", sql.VarChar, encryptedPassword);
      await request.query(
        "INSERT INTO dbo.person(name, phone_number, email, password, role) VALUES (@name, @phone_number, @email, @password, 1)"
      );


      const requestSelect = pool.request();
      requestSelect.input("email", sql.VarChar, data.email);
      const result = await requestSelect.query("SELECT id_person FROM dbo.person WHERE email = @email");

      console.log(result.recordset[0].id_person)


      const requestClient = pool.request();
      requestClient.input("id_person", sql.Int, result.recordset[0].id_person);
      await requestClient.query(
        "INSERT INTO dbo.client (id_person, code_parrainage) VALUES (@id_person, '')"
      );
      const expirationTime = 5 * 24 * 60 * 60; // 5 jours en secondes
      const token = jwt.sign({ email: data.email }, process.env.TOKEN_KEY, { expiresIn: expirationTime });

      const log = new Logs({
        logType: 'inscription client',
        timestamp: new Date(),
        email: data.email,
        success: true,
      });
      await log.save();

      res.cookie('token', token, { httpOnly: true, maxAge: expirationTime * 1000 }).send("Inscris !").end();
    }
  } catch (error) {
    const log = new Logs({
      logType: 'inscription client',
      timestamp: new Date(),
      email: data.email,
      success: false,
      error_message: error.message
    });
    await log.save();
    res.status(500).send(error).end();
  }
});

// Login
/**
 * @swagger
 * /api/V1/login/client:
 *   post:
 *     tags:
 *       - Connexion
 *     description: Login to the application
 *     produces:
 *       - application/json
 *     parameters:
 *       - name: body
 *         description: login object
 *         in: body
 *         required: true
 *         schema:
 *           $ref: '#/definitions/Login'
 *     responses:
 *       200:
 *         description: login success
 *       400:
 *         description: Invalid email or password
 *       500:
 *         description: internal server error
 */
/**
 *  @swagger
 *  definitions:
 *    Login:
 *      type: object
 *      required:
 *        - email
 *        - password
 *      properties:
 *        email:
 *          type: string
 *          format: email
 *        password:
 *          type: string
 */
app.post(url + "/login/client", async (req, res) => {
  let data = req.body;
  let pool = await sql.connect(config);

  const request = pool.request();
  request.input('email', sql.VarChar, data.email);
  request.query("SELECT email, password FROM dbo.person WHERE email = @email", async (err, result) => {
    if (err) {
      return res.status(500).send(err);
    }
    if (result.recordset.length == 0) {
      const log = new Logs({
        logType: 'connexion client',
        timestamp: new Date(),
        email: data.email,
        success: false,
        error_message: 'Adresse mail non existante'
      });
      await log.save();
      return res.status(400).send("Adresse mail non existante");
    }
    const validPassword = bcrypt.compareSync(data.password, result.recordset[0].password);
    if (!validPassword) {
      const log = new Logs({
        logType: 'connexion client',
        timestamp: new Date(),
        email: data.email,
        success: false,
        error_message: 'Mot de passe invalide'
      });
      await log.save();
      return res.status(400).send('Mot de passe invalide');
    }
    const expirationTime = 5 * 24 * 60 * 60; // 5 jours en secondes
    const token = jwt.sign({ email: data.email }, process.env.TOKEN_KEY, { expiresIn: expirationTime });

    const log = new Logs({
      logType: 'connexion client',
      timestamp: new Date(),
      email: data.email,
      success: true,
    });
    await log.save();
    res.cookie('token', token, { httpOnly: true, maxAge: expirationTime * 1000 }).send("Connecté !").end();
  });
});

/**
 * @swagger
 * /api/V1/logout:
 *   post:
 *     tags:
 *       - Utilisateurs
 *     description: Déconnecte un utilisateur.
 *     responses:
 *       200:
 *         description: Déconnecté avec succès
 */
app.post(url + "/logout", (req, res) => {
  let decodedToken = getInfoToken(req, res)
  const log = new Logs({
    logType: 'déconnexion',
    timestamp: new Date(),
    email: decodedToken.email,
    success: true
  });
  log.save();
  res.clearCookie("token").send("Déconnecté !");
});


//Changement de mot de passe de l'addresse mail contenue dans le token utilisateur
/**
* @swagger
* /api/V1/updatePassword:
*   put:
*     tags:
*       - Connexion
*     description: Met à jour le mot de passe de l'utilisateur connecté
*     produces:
*       - application/json
*     parameters:
*       - name: body
*         description: Informations de mise à jour de mot de passe
*         in: body
*         required: true
*         schema:
*           type: object
*           properties:
*             password:
*               type: string
*               description: Nouveau mot de passe de l'utilisateur
*     responses:
*       200:
*         description: Mot de passe mis à jour avec succès
*       400:
*         description: Adresse mail ou mot de passe non valide
*       500:
*         description: Erreur interne du serveur
*/
app.put(url + "/updatePassword", async (req, res) => {
  let data = req.body;
  let decodedToken = getInfoToken(req, res)
  let email = decodedToken.email
  let pool = await sql.connect(config);

  // Si l'utilisateur a fourni un nouveau mot de passe, cryptez-le avant de l'enregistrer
  let password = data.password;
  if (password) {
    password = bcrypt.hashSync(password, 10);
  }

  // Met à jour les informations de l'utilisateur
  const request = pool.request();
  request.input('email', sql.VarChar, email);
  request.input('newPassword', sql.VarChar, password);
  request.query("UPDATE dbo.person SET password = @newPassword WHERE email = @email", (err, result) => {
    if (err) {
      const log = new Logs({
        logType: 'updatePassword',
        timestamp: new Date(),
        email: email,
        success: false,
        error_message: err.message
      });
      log.save();
      return res.status(500).send(err);
    }
    const log = new Logs({
      logType: 'updatePassword',
      timestamp: new Date(),
      email: email,
      success: true,
    });
    log.save();
    res.status(200).send(`Informations mises à jour avec succès, nouveau mot de passe : ${password}`);
  });
});


//Changement de mot de passe avec une addresse mail spécifique
/**
 * @swagger
 * /api/V1/updatePassword/{email}:
 *    put:
 *      tags:
 *        - Admin
 *      summary: Met à jour le mot de passe de l'utilisateur correspondant à l'email spécifié
 *      parameters:
 *        - in: path
 *          name: email
 *          required: true
 *          description: Email de l'utilisateur dont le mot de passe doit être mis à jour
 *        - in: body
 *          name: password
 *          required: true
 *          description: Nouveau mot de passe de l'utilisateur (crypté avant enregistrement)
 *      responses:
 *        200:
 *          description: Informations mises à jour avec succès
 */
app.put(url + "/updatePassword/:email", async (req, res) => {
  let data = req.body;
  let email = req.params.email
  let pool = await sql.connect(config);

  // Si l'utilisateur a fourni un nouveau mot de passe, cryptez-le avant de l'enregistrer
  let password = data.password;
  let success = true;
  let error_message;
  if (password) {
    password = bcrypt.hashSync(password, 10);
  }

  // Met à jour les informations de l'utilisateur
  const request = pool.request();
  request.input('email', sql.VarChar, email);
  request.input('newPassword', sql.VarChar, password);
  request.query("UPDATE dbo.person SET password = @newPassword WHERE email = @email", (err, result) => {
    if (err) {
      success = false;
      error_message = err;
      return res.status(500).send(err);
    }
    const log = new Logs({
      logType: 'updatePassword admin',
      timestamp: new Date(),
      email: email,
      success: success,
      error_message: error_message
    });
    log.save();
    res.status(200).send(`Informations mises à jour avec succès, nouveau mot de passe : ${data.newPassword}`);
  });
});


//Lecture des informations de l'utilisateur connecté indépendamment du role
/**
 * @swagger
 * /api/V1/user:
 *   get:
 *     tags:
 *        - Utilisateurs 
 *     description: Récupère les informations d'un utilisateur connecté
 *     produces:
 *       - application/json
 *     responses:
 *       200:
 *         description: Retourne les informations de l'utilisateur connecté
 *         schema:
 *           type: object
 *           properties:
 *             surname:
 *               type: string
 *             name:
 *               type: string
 *             birth:
 *               type: string
 *             phone_number:
 *               type: string
 *             email:
 *               type: string
 *       401:
 *         description: Retourne un message d'erreur si l'utilisateur n'est pas connecté
 *       500:
 *         description: Retourne un message d'erreur en cas d'erreur serveur
 */
app.get(url + "/user", async (req, res) => {
  checkToken(req, res)
  let pool = await sql.connect(config);
  const request = pool.request();
  let decodedToken = getInfoToken(req, res);
  let email = decodedToken.email
  request.input('email', sql.VarChar, email);

  request.query("SELECT surname, name, birth, phone_number, email FROM dbo.person WHERE email = @email", (err, result) => {
    if (err) {
      return res.status(500).send(err);
    }
    res.status(200).json(result.recordset[0]);
  });
});

//Suppression de l'utilisateur
/**
 * @swagger
 * /api/V1/client:
 *   delete:
 *     tags:
 *       - Utilisateurs
 *     description: Supprime un utilisateur de la table dbo.client et de la table dbo.person
 *     produces:
 *       - application/json
 *     parameters:
 *     responses:
 *       200:
 *         description: Utilisateur supprimé avec succès
 *       401:
 *         description: L'utilisateur n'a pas été supprimé
 *       500:
 *         description: Erreur interne du serveur
 */
app.delete(url + "/client", async (req, res) => {
  try {
    let pool = await sql.connect(config);
    const request = pool.request();
    const requestClient = pool.request();
    let decodedToken = getInfoToken(req, res);
    let email = decodedToken.email
    const requestSelect = pool.request();
    requestSelect.input("email", sql.VarChar, email);
    const result = await requestSelect.query("SELECT id_person FROM dbo.person WHERE email = @email");
    request.input('email', sql.VarChar, email);
    console.log(result.recordset[0].id_person)
    requestClient.input('id_person', sql.Int, result.recordset[0].id_person);
    await requestClient.query("DELETE FROM dbo.client WHERE id_person = @id_person;")
    await request.query("DELETE FROM dbo.person WHERE email = @email;")
    res.status(200).send(`Le compte lié à l'address : ${email} a bien été supprimé`);
    sql.close()
  } catch (err) {
    res.status(500).json({ message: err.message });
  }
});

//Mets à jour les informations utilisateurs
/**
 * @swagger
 * /api/V1/user:
 *   put:
 *     tags:
 *       - Utilisateurs
 *     description: Mettre à jour les informations d'un utilisateur
 *     produces:
 *       - application/json
 *     parameters:
 *       - name: body
 *         in: body
 *         required: true
 *         schema:
 *           type: object
 *           properties:
 *             surname:
 *               type: string
 *             name:
 *               type: string
 *             birth:
 *               type: string
 *             phone_number:
 *               type: integer
 *     responses:
 *       200:
 *         description: Informations mises à jour avec succès
 *       400:
 *         description: Problème lors de la mise à jour des informations
 *       401:
 *         description: Non authentifié
 *       500:
 *         description: Erreur interne
 */
app.put(url + "/user", async (req, res) => {
  let data = req.body;

  let decodedToken = getInfoToken(req, res)
  let email = decodedToken.email;
  let surname = data.surname;
  let name = data.name;
  let birth = new Date(data.birth)
  let phone_number = data.phone_number;

  let pool = await sql.connect(config);

  // Met à jour les informations de l'utilisateur
  const request = pool.request();
  request.input('email', sql.VarChar, email);
  request.input('surname', sql.VarChar, surname);
  request.input('name', sql.VarChar, name);
  request.input('birth', sql.Date, birth); //YYYY-MM-DD
  request.input('phone_number', sql.Int, phone_number);

  request.query("UPDATE dbo.person SET surname = @surname, name = @name, birth = @birth, phone_number = @phone_number WHERE email = @email", (err, result) => {
    if (err) {
      return res.status(500).send(err);
    }
    res.status(200).send(`Informations mises à jour avec succès`);
  });
});

//#endregion

//#region crud menu

//Crée un menu
/**
 * @swagger
 * /api/V1/menu:
 *   post:
 *     tags:
 *       - Menu
 *     description: Crée un nouveau menu pour un restaurant
 *     produces:
 *       - application/json
 *     parameters:
 *       - name: body
 *         description: Objet menu
 *         in: body
 *         required: true
 *         schema:
 *           type: object
 *           properties:
 *             idRestaurant:
 *               type: number
 *               example: 1
 *             menu:
 *               type: object
 *               properties:
 *                 items:
 *                   type: array
 *                   items:
 *                     type: object
 *                 restaurant_categories:
 *                   type: array
 *                   items:
 *                     type: string
 *     responses:
 *       201:
 *         description: Menu créé avec succès
 *         schema:
 *           type: object
 *           properties:
 *             message:
 *               type: string
 *               example: "Menu id : 1 crée"
 *       400:
 *         description: Erreur lors de la création du menu
 */
app.post(url + "/menu", async (req, res) => {
  try {
    checkToken(req, res);
    let decodedToken = getInfoToken(req, res);
    let pool = await sql.connect(config);

    const request = pool.request();
    request.input('email', sql.VarChar, decodedToken.email);
    const result = await request.query("SELECT id_person FROM dbo.person WHERE email = @email");

    const newMenu = new Menu(req.body);
    let menuNumber = await Menu.estimatedDocumentCount();
    newMenu.idRestaurant = result.recordset[0].id_person;
    const menu = await newMenu.save();

    res.status(201).json({ message: `Menu id : ${menu.id} crée` });
  } catch (err) {
    res.status(400).json({ message: err.message });
  }
});


app.post(url + "/menu/:email", async (req, res) => {
  try {
    checkToken(req, res);
    let decodedToken = getInfoToken(req, res);
    let pool = await sql.connect(config);
    let email = req.params.email
    const request = pool.request();
    request.input('email', sql.VarChar, email);
    const result = await request.query("SELECT id_person FROM dbo.person WHERE email = @email");

    const newMenu = new Menu(req.body);
    let menuNumber = await Menu.estimatedDocumentCount();
    newMenu.idRestaurant = result.recordset[0].id_person;
    const menu = await newMenu.save();

    res.status(201).json({ message: `Menu id : ${menu.id} crée` });
  } catch (err) {
    res.status(400).json({ message: err.message });
  }
});

//Récupère les menus //A corriger
/**
 * @swagger
 * /api/V1/restaurants:
 *   get:
 *     tags:
 *       - Restaurant
 *     description: Retourne la liste des restaurants
 *     produces:
 *       - application/json
 *     responses:
 *       200:
 *         description: Liste des restaurants
 *         schema:
 *           type: array
 *           items:
 *             $ref: '#/definitions/Restaurant'
 *       500:
 *         description: Erreur interne du serveur
 */
/**
 * @swagger
 * definitions:
 *   Restaurant:
 *     properties:
 *       id_restaurant:
 *         type: number
 *       address:
 *         type: number
 *       code_parrainage:
 *         type: number
 *       payment_information:
 *         type: number
 */
app.get(url + '/restaurants', async (req, res) => {
  const start = Date.now();
  try {
    const restaurants = await Menu.find();
    const elapsed = Date.now() - start;
    await Perf.create({ route: '/restaurants', time: elapsed });
    res.send(restaurants);
  } catch (err) {
    res.status(500).json({ message: err.message });
  }
});

/**
 * @swagger
 * /api/V1/restaurant/name/{id_restaurant}:
 *   get:
 *     tags:
 *       - Restaurant
 *     summary: Retourne le nom d'un restaurant via son ID
 *     parameters:
 *       - in: path
 *         name: id_restaurant
 *         schema:
 *           type: string
 *         required: true
 *         description: ID of the restaurant to retrieve
 *     responses:
 *       200:
 *         description: Successfully returned the name of the restaurant
 *       500:
 *         description: An error occurred
 */
app.get(url + '/restaurant/name/:id_restaurant', async (req, res) => {
  try {
    let pool = await sql.connect(config);
    const request = await pool.request();
    let id_restaurant = req.params.id_restaurant
    request.input('id_restaurant', sql.VarChar, id_restaurant);
    const result = await request.query("SELECT restaurant_name FROM dbo.restaurateur WHERE id_restaurant = @id_restaurant");
    res.send(result.recordset[0]);
  } catch (err) {
    res.status(500).send(err.message);
  }
});

app.get(url + '/restaurants/name', async (req, res) => {
  try {
    let pool = await sql.connect(config);
    const request = await pool.request();
    const result = await request.query("SELECT restaurant_name, id_restaurant FROM dbo.restaurateur");
    res.send(result.recordset);
  } catch (err) {
    res.status(500).send(err.message);
  }
});



//Récupère le menu d'un restaurant avec son id
/**
 * @swagger
 * /api/V1/menu/{id}:
 *   get:
 *     tags:
 *       - Menu
 *     description: Récupère le menu d'un restaurant en fonction de son ID
 *     parameters:
 *       - in: path
 *         name: id
 *         required: true
 *         description: ID du menu à récupérer
 *     responses:
 *       200:
 *         description: Le menu du restaurant
 *         schema:
 *           type: object
 *           properties:
 *             id:
 *               type: string
 *             name:
 *               type: string
 *             items:
 *               type: array
 *               items:
 *                 type: object
 *                 properties:
 *                   name:
 *                     type: string
 *                   description:
 *                     type: string
 *                   price:
 *                     type: number
 *       401:
 *         description: Token non valide ou expiré
 *       404:
 *         description: Menu introuvable
 */
app.get(url + '/menu/:id', function (req, res) {
  checkToken(req, res)
  const menuId = req.params.id
  Menu.findOne({ id: menuId }, (err, restaurant) => {
    if (err) return handleError(err);
    res.send(restaurant);
  });
});

//Mets à jour un menu
/**
 * @swagger
 * tags:
 *   - name: Menu
 * paths:
 *  /api/V1/menu/{id}:
 *    put:
 *      summary: Update a specific menu
 *      tags:
 *        - Menu
 *      parameters:
 *        - in: path
 *          name: id
 *          required: true
 *          schema:
 *            type: string
 *      requestBody:
 *        required: true
 *        content:
 *          application/json:
 *            schema:
 *      responses:
 *        '200':
 *          description: Menu updated
 *        '404':
 *          description: Menu not found
 *        '400':
 *          description: Bad Request
 */
app.put(url + "/menu/:id", async (req, res) => {
  checkToken(req, res)
  try {
    const menu = await Menu.findOneAndUpdate({ id: req.params.id }, req.body, { new: true });
    if (!menu) {
      return res.status(404).json({ message: 'Menu not found' });
    }
    res.status(200).json({ message: `Menu id : ${menu.id} mis à jour` });
  } catch (err) {
    res.status(400).json({ message: err.message });
  }
});

//Supprime un menu
/**
 * @swagger
 * /api/V1/menu/{id}:
 *   delete:
 *     tags:
 *       - Menu
 *     description: Deletes a menu by id
 *     produces:
 *       - application/json
 *     parameters:
 *       - name: id
 *         in: path
 *         required: true
 *         type: number
 *         description: ID of menu to delete
 *     responses:
 *       200:
 *         description: Menu deleted successfully
 *         schema:
 *           type: object
 *           properties:
 *             message:
 *               type: string
 *               example: Menu removed successfully
 *       400:
 *         description: Invalid request
 *         schema:
 *           type: object
 *           properties:
 *             message:
 *               type: string
 *               example: Invalid request
 *       404:
 *         description: Menu not found
 *         schema:
 *           type: object
 *           properties:
 *             message:
 *               type: string
 *               example: Menu not found
 *       500:
 *         description: Internal server error
 *         schema:
 *           type: object
 *           properties:
 *             error:
 *               type: string
 *               example: handleError
 */
app.delete(url + '/menu/:id', async function (req, res) {
  checkToken(req, res)
  try {
    const menuId = req.params.id
    Menu.findOne({ id: menuId }, (err, restaurant) => {
      if (err) return handleError(err);
      if (!restaurant) {
        return res.status(404).json({ message: 'Menu not found' });
      }
      restaurant.remove();
      res.json({ message: 'Menu removed successfully' });
    });
  } catch (err) {
    res.status(500).json({ message: err.message });
  }
});


//Crée une commande
/**
 * @swagger
 * /api/V1/commande:
 *   post:
 *     tags:
 *       - Commande
 *     description: Crée une nouvelle commande en assignant un livreur disponible de manière aléatoire
 *     produces:
 *       - application/json
 *     parameters:
 *       - name: body
 *         description: Objet commande
 *         in: body
 *         required: true
 *         schema:
 *           $ref: "#/definitions/Commande"
 *     responses:
 *       201:
 *         description: Commande créée avec succès
 *       400:
 *         description: Erreur lors de la création de la commande
 *       401:
 *         description: Aucun livreur disponible n'a été trouvé pour cette commande
 */
app.post(url + "/commande", async (req, res) => {
  //checkToken(res,res)
  let decodedToken = getInfoToken(req, res);
  let email = decodedToken.email;
  try {
      const start = Date.now();
      let pool = await sql.connect(config);
      const request = pool.request();
      request.input('email', sql.VarChar, email);
      let resultDeliverer = await request.query("SELECT id_person FROM dbo.deliverer WHERE statut_activite = 1");
      if (resultDeliverer.recordset.length > 0) {
          let result = await request.query("SELECT id_person FROM dbo.person WHERE email = @email");
          let availableDeliverers = resultDeliverer.recordset;
          let randomIndex = Math.floor(Math.random() * availableDeliverers.length);
          let randomlySelectedDeliverer = availableDeliverers[randomIndex];
          // Create new commande object from request body
          let newCommande = new Commande(req.body);
          // Get the count of commande in database
          let documentNumber = await Commande.estimatedDocumentCount();
          // Set idCommande and id_person to new commande
          newCommande.idCommande = documentNumber;
          newCommande.date = new Date();
          newCommande.client = result.recordset[0].id_person;
          newCommande.deliverer = randomlySelectedDeliverer.id_person;
          // Save the commande in database
          const elapsed = Date.now() - start;
          await Perf.create({ route: '/commande', time: elapsed });
          await newCommande.save();
          // Respond with 201 status and success message
          res.status(201).json({ message: 'Commande créée avec succès' });

          let log = new Logs({
              logType: 'create commande',
              timestamp: new Date(),
              email: email,
              success: true,
              error_message: null
          });
          await log.save();
      } else {
          res.status(401).json({ message: 'Désolé, nous ne trouvons pas de livreur disponible dans votre zone géographique !' });
      }
  } catch (err) {
      let log = new Logs({
          logType: 'create commande',
          timestamp: new Date(),
          email: email,
          success: false,
          error_message: err.message
      });
      await log.save();
      // Respond with 400 status and error message
      res.status(400).json({ message: err.message });
  }
});

//Récupère le nombre de commande
/**
 * @swagger
 * /api/V1/commande/count:
 *   get:
 *     tags:
 *       - Commande
 *     description: Retrieves the count of commande
 *     produces:
 *       - application/json
 *     responses:
 *       200:
 *         description: The count of commande
 *         schema:
 *           type: object
 *           properties:
 *             count:
 *               type: integer
 *       500:
 *         description: Internal server error
 *         schema:
 *           type: object
 *           properties:
 *             message:
 *               type: string
 */
app.get(url + "/commande/count", async (req, res) => {
  checkToken(req, res)
  try {
    const count = await Commande.estimatedDocumentCount();
    res.json({ count });
  } catch (err) {
    res.status(500).json({ message: err.message });
  }
});

//Récupère le nombre de commande par client
/**
 * @swagger
 * /api/V1/commande/count/{client}:
 *   get:
 *     tags:
 *       - Commande
 *     description: Retrieves the count of commande by client
 *     produces:
 *       - application/json
 *     parameters:
 *       - name: client
 *         in: path
 *         required: true
 *         type: number
 *         description: ID of the client
 *     responses:
 *       200:
 *         description: The count of commande
 *         schema:
 *           type: object
 *           properties:
 *             count:
 *               type: integer
 *       500:
 *         description: Internal server error
 *         schema:
 *           type: object
 *           properties:
 *             message:
 *               type: string
 */
app.get(url + "/commande/count/:client", async (req, res) => {
  checkToken(req, res)
  try {
    const count = await Commande.countDocuments({ client: req.params.client });
    res.json({ count });
  } catch (err) {
    res.status(500).json({ message: err.message });
  }
});

//Récupère le statut d'une commande 
/**
 * @swagger
 * /api/V1/commande/{idCommande}/status:
 *   get:
 *     tags:
 *       - Commande
 *     description: Retrieves the status of commande by idCommande
 *     produces:
 *       - application/json
 *     parameters:
 *       - name: idCommande
 *         in: path
 *         required: true
 *         type: number
 *         description: ID of the commande
 *     responses:
 *       200:
 *         description: The status of commande
 *         schema:
 *           type: object
 *           properties:
 *             status:
 *               type: string
 *       404:
 *         description: Commande not found
 *         schema:
 *           type: object
 *           properties:
 *             message:
 *               type: string
 *               example: Commande non trouvée
 *       500:
 *         description: Internal server error
 *         schema:
 *           type: object
 *           properties:
 *             message:
 *               type: string
 */
app.get(url + "/commande/:idCommande/status", async (req, res) => {
  checkToken(req, res)
  try {
    const idCommande = req.params.idCommande;
    const commande = await Commande.findOne({ idCommande });
    if (!commande) {
      return res.status(404).json({ message: "Commande non trouvée" });
    }
    res.status(200).json({ status: commande.status });
  } catch (err) {
    res.status(500).json({ message: err.message });
  }
});

//modifie une commande via son id
/**
 * @swagger
 * /api/V1/commande/{id}:
 *   put:
 *     tags:
 *       - Commande
 *     description: Updates a commande by id
 *     produces:
 *       - application/json
 *     parameters:
 *       - name: id
 *         in: path
 *         required: true
 *         type: number
 *         description: ID of commande to update
 *     requestBody:
 *       required: true
 *       content:
 *         application/json:
 *           schema:
 *             $ref: '#/definitions/Commande'
 *     responses:
 *       200:
 *         description: Commande updated successfully
 *         schema:
 *           type: object
 *           properties:
 *             message:
 *               type: string
 *               example: Commande mise à jour avec succès
 *       400:
 *         description: Invalid request
 *         schema:
 *           type: object
 *           properties:
 *             message:
 *               type: string
 *               example: Invalid request
 *       404:
 *         description: Commande not found
 *         schema:
 *           type: object
 *           properties:
 *             message:
 *               type: string
 *               example: Commande introuvable
 */
/**
 * @swagger
 * definitions:
 *   Commande:
 *     type: object
 *     properties:
 *       idCommande:
 *         type: number
 *       date:
 *         type: string
 *         format: date-time
 *       client:
 *         type: number
 *       restaurant:
 *         type: number
 *       items:
 *         type: array
 *         items:
 *           type: object
 *           properties:
 *             name:
 *               type: string
 *             price:
 *               type: number
 *             qty:
 *               type: number
 *       total:
 *         type: number
 *       deliverer:
 *         type: number
 *       status:
 *         type: string
 */
app.put(url + "/commande/:id", async (req, res) => {
  checkToken(req, res)
  try {
    // Récupère l'id de la commande à mettre à jour à partir de la requête
    let id = req.params.id;
    // Récupère les données à mettre à jour à partir de la requête
    const updates = req.body;
    updates.idCommande = id
    // Trouve la commande à mettre à jour en utilisant l'id
    const commande = await Commande.find({ idCommande: id }, (error, result) => {
      if (error) {
        res.status(404).json({ message: "Les problèmes" });
      }
    })
    // Vérifie si la commande a été trouvée
    if (!commande) {
      res.status(404).json({ message: "Commande introuvable" });
    }
    // Répond avec un statut 200 et un message de succès
    res.status(200).json({ message: "Commande mise à jour avec succès" });
  } catch (err) {
    // Répond avec un statut 400 et un message d'erreur
    res.status(400).json({ message: err.message });
  }
});


//Récupère (ou crée si code inexistant) le code de parrainage de l'utilisateur connecté (peut importer son role)
/**
* @swagger
* tags:
*   - name: Utilisateurs
* paths:
*  /api/V1/sponsorship:
*    get:
*      summary: récupérer le code de parrainage de l'utilisateur connecté
*      tags:
*        - Utilisateurs
*      responses:
*        '200':
*          description: Code de parrainage retourné
*        '404':
*          description: Utilisateur non trouvé
*        '400':
*          description: Bad Request
*/
app.get(url + "/sponsorship", async (req, res) => {
  checkToken(req, res)
  let decodedToken = getInfoToken(req, res)
  let email = decodedToken.email

  try {
    let pool = await sql.connect(config);
    const requestSelect = pool.request();


    requestSelect.input("email", sql.VarChar, email);
    const result = await requestSelect.query("SELECT id_person, role FROM dbo.person WHERE email = @email");
    const role = result.recordset[0].role

    if (!result.recordset[0]) {
      res.status(404).json({ message: "personne non trouvée" });
      return;
    }

    switch (role) {
      case 1:
        const requestSelectClient = pool.request();
        requestSelectClient.input("id_person", sql.Int, result.recordset[0].id_person);
        const client = await requestSelectClient.query("SELECT code_parrainage FROM dbo.client WHERE id_person = @id_person");
        if (client.recordset[0].code_parrainage == null || client.recordset[0].code_parrainage === "") {
          // le champ est null ou un string vide
          console.log("champ null ou vide")
          const randomString = Math.random().toString(36).slice(-4);
          const sponsorshipId = result.recordset[0].id_person + randomString;

          const insert = pool.request();
          insert.input("code_parrainage", sql.VarChar, sponsorshipId)
          insert.input("id_person", sql.Int, result.recordset[0].id_person)

          await insert.query(
            "UPDATE dbo.client SET code_parrainage = @code_parrainage WHERE id_person = @id_person"
          );
          return res.status(200).json({ sponsorshipId });
        } else {
          // le champ contient une valeur
          console.log("champ rempli")
          const sponsorship = client.recordset[0].code_parrainage
          return res.status(200).json({ sponsorship });
        }
        break;
      case 2:
        const requestSelectRestaurant = pool.request();
        requestSelectRestaurant.input("id_person", sql.Int, result.recordset[0].id_person);
        const restaurateur = await requestSelectRestaurant.query("SELECT code_parrainage FROM dbo.restaurateur WHERE id_restaurant = @id_person");
        if (restaurateur.recordset[0].code_parrainage == null || restaurateur.recordset[0].code_parrainage === "" || restaurateur.recordset[0].code_parrainage == 0) {
          // le champ est null ou un string vide
          console.log("champ null ou vide")
          const randomString = Math.random().toString(36).slice(-4);
          const sponsorshipId = result.recordset[0].id_person + randomString;

          const insert = pool.request();
          insert.input("code_parrainage", sql.VarChar, sponsorshipId)
          insert.input("id_person", sql.Int, result.recordset[0].id_person)

          await insert.query(
            "UPDATE dbo.restaurateur SET code_parrainage = @code_parrainage WHERE id_restaurant = @id_person"
          );
          return res.status(200).json({ sponsorshipId });
        } else {
          // le champ contient une valeur
          console.log("champ rempli")
          const sponsorship = restaurateur.recordset[0].code_parrainage
          return res.status(200).json({ sponsorship });
        }
        break;
      case 3:
        const requestSelectDeliverer = pool.request();
        requestSelectDeliverer.input("id_person", sql.Int, result.recordset[0].id_person);
        const livreur = await requestSelectDeliverer.query("SELECT code_parrainage FROM dbo.deliverer WHERE id_person = @id_person");
        if (livreur.recordset[0].code_parrainage == null || livreur.recordset[0].code_parrainage === "" || livreur.recordset[0].code_parrainage == 0) {
          // le champ est null ou un string vide
          console.log("champ null ou vide")
          const randomString = Math.random().toString(36).slice(-4);
          const sponsorshipId = result.recordset[0].id_person + "-" + randomString;

          const insert = pool.request();
          insert.input("code_parrainage", sql.VarChar, sponsorshipId)
          insert.input("id_person", sql.Int, result.recordset[0].id_person)

          await insert.query(
            "UPDATE dbo.deliverer SET code_parrainage = @code_parrainage WHERE id_person = @id_person"
          );
          return res.status(200).json({ sponsorshipId });
        } else {
          // le champ contient une valeur
          console.log("champ rempli")
          const sponsorship = livreur.recordset[0].code_parrainage
          return res.status(200).json({ sponsorship });
        }
        break;

      default:
        break;
    }







    sql.close()
  } catch (err) {
    res.status(500).json({ message: err.message });
  }
});


//#endregion

//#region Stat

//Get specified restaurant all time orders //AJOUTER ID EN DYNAMIQUE
/**
 * @swagger
 * /api/V1/restaurant/{id}/stats/countAllTime:
 *   get:
 *     tags:
 *       - Statistique
 *     description: Retourne le nombre de commandes pour un restaurant spécifique
 *     produces:
 *       - application/json
 *     parameters:
 *       - name: id
 *         description: ID du restaurant
 *         in: path
 *         required: true
 *         type: string
 *     responses:
 *       200:
 *         description: Nombre de commandes pour un restaurant spécifique
 *         schema:
 *           type: object
 *           properties:
 *             countAllTime:
 *               type: integer
 *       500:
 *         description: Erreur interne du serveur
 */
app.get(url + "/restaurant/:id/stats/countAllTime", async (req, res) => {
  try {
    const id = req.params.id
    const countAllTime = await Commande.countDocuments({ "restaurant": id });
    res.json({ countAllTime });
  } catch (err) {
    res.status(500).json({ message: err.message });
  }
});

//Get specified restaurant last 24h orders
/**
 * @swagger
 * /api/V1/restaurant/{id}/stats/count24h:
 *   get:
 *     tags:
 *       - Statistique
 *     description: Retourne le nombre de commandes pour un restaurant spécifique dans les dernières 24 heures
 *     produces:
 *       - application/json
 *     parameters:
 *       - name: id
 *         description: ID du restaurant
 *         in: path
 *         required: true
 *         type: string
 *     responses:
 *       200:
 *         description: Nombre de commandes pour un restaurant spécifique dans les dernières 24 heures
 *         schema:
 *           type: object
 *           properties:
 *             countLast24h:
 *               type: integer
 *       500:
 *         description: Erreur interne du serveur
 */
app.get(url + "/restaurant/:id/stats/count24h", async (req, res) => {
  try {
    const id = req.params.id
    const twentyFourHoursAgo = new Date(Date.now() - (24 * 60 * 60 * 1000));
    const countLast24h = await Commande.countDocuments({
      "restaurant": id,
      "date": { $gt: twentyFourHoursAgo }
    });

    res.json({ countLast24h });
  } catch (err) {
    res.status(500).json({ message: err.message });
  }
});

//Get specified restaurant last 72h orders
/**
 * @swagger
 * /api/V1/restaurant/{id}/stats/count72h:
 *   get:
 *     tags:
 *       - Statistique
 *     description: Retourne le nombre de commandes pour un restaurant spécifique dans les dernières 72 heures
 *     produces:
 *       - application/json
 *     parameters:
 *       - name: id
 *         description: ID du restaurant
 *         in: path
 *         required: true
 *         type: string
 *     responses:
 *       200:
 *         description: Nombre de commandes pour un restaurant spécifique dans les dernières 72 heures
 *         schema:
 *           type: object
 *           properties:
 *             countLast72h:
 *               type: integer
 *       500:
 *         description: Erreur interne du serveur
 */
app.get(url + "/restaurant/:id/stats/count72h", async (req, res) => {
  try {
    const id = req.params.id
    const seventyTwoHoursAgo = new Date(Date.now() - (72 * 60 * 60 * 1000));
    const countLast72h = await Commande.countDocuments({
      "restaurant": id,
      "date": { $gt: seventyTwoHoursAgo }
    });
    res.json({ countLast72h });
  } catch (err) {
    res.status(500).json({ message: err.message });
  }
});

//Get specified restaurant last 7 days orders
/**
 * @swagger
 * /api/V1/restaurant/{id}/stats/count7days:
 *   get:
 *     tags:
 *       - Statistique
 *     description: Retourne le nombre de commandes pour un restaurant spécifique dans les dernières 7 jours
 *     produces:
 *       - application/json
 *     parameters:
 *       - name: id
 *         description: ID du restaurant
 *         in: path
 *         required: true
 *         type: string
 *     responses:
 *       200:
 *         description: Nombre de commandes pour un restaurant spécifique dans les dernières 7 jours
 *         schema:
 *           type: object
 *           properties:
 *             countLast7days:
 *               type: integer
 *       500:
 *         description: Erreur interne du serveur
 */
app.get(url + "/restaurant/:id/stats/count7days", async (req, res) => {
  try {
    const id = req.params.id
    const sevenDaysAgo = new Date(Date.now() - (7 * 24 * 60 * 60 * 1000));
    const countLast7days = await Commande.countDocuments({
      "restaurant": id,
      "date": { $gt: sevenDaysAgo }
    });
    res.json({ countLast7days });
  } catch (err) {
    res.status(500).json({ message: err.message });
  }
});


///Client Stats
//Get specified client last 24h orders
/**
 * @swagger
 * /api/V1/client/{id}/stats/count24h:
 *   get:
 *     tags:
 *       - Statistique
 *     description: Retourne le nombre de commandes pour un client spécifique dans les dernières 24 heures
 *     produces:
 *       - application/json
 *     parameters:
 *       - name: id
 *         description: ID du client
 *         in: path
 *         required: true
 *         type: string
 *     responses:
 *       200:
 *         description: Nombre de commandes pour un client spécifique dans les dernières 24 heures
 *         schema:
 *           type: object
 *           properties:
 *             countLast24h:
 *               type: integer
 *       500:
 *         description: Erreur interne du serveur
 */
app.get(url + "/client/:id/stats/count24h", async (req, res) => {
  try {
    const id = req.params.id
    const twentyFourHoursAgo = new Date(Date.now() - (24 * 60 * 60 * 1000));
    const countLast24h = await Commande.countDocuments({
      "client": id,
      "date": { $gt: twentyFourHoursAgo }
    });

    res.json({ countLast24h });
  } catch (err) {
    res.status(500).json({ message: err.message });
  }
});

//Get specified client last 72h orders
/**
 * @swagger
 * /api/V1/client/{id}/stats/count72h:
 *   get:
 *     tags:
 *       - Statistique
 *     description: Retourne le nombre de commandes pour un client spécifique dans les dernières 72 heures
 *     produces:
 *       - application/json
 *     parameters:
 *       - name: id
 *         description: ID du client
 *         in: path
 *         required: true
 *         type: string
 *     responses:
 *       200:
 *         description: Nombre de commandes pour un client spécifique dans les dernières 72 heures
 *         schema:
 *           type: object
 *           properties:
 *             countLast72h:
 *               type: integer
 *       500:
 *         description: Erreur interne du serveur
 */
app.get(url + "/client/:id/stats/count72h", async (req, res) => {
  try {
    const id = req.params.id
    const seventyTwoHoursAgo = new Date(Date.now() - (72 * 60 * 60 * 1000));
    const countLast72h = await Commande.countDocuments({
      "client": id,
      "date": { $gt: seventyTwoHoursAgo }
    });
    res.json({ countLast72h });
  } catch (err) {
    res.status(500).json({ message: err.message });
  }
});

//Get specified client last 7 days orders
/**
 * @swagger
 * /api/V1/client/{id}/stats/count7days:
 *   get:
 *     tags:
 *       - Statistique
 *     description: Retourne le nombre de commandes pour un client spécifique dans les derniers 7 jours
 *     produces:
 *       - application/json
 *     parameters:
 *       - name: id
 *         description: ID du client
 *         in: path
 *         required: true
 *         type: string
 *     responses:
 *       200:
 *         description: Nombre de commandes pour un client spécifique dans les dernières 7 jours
 *         schema:
 *           type: object
 *           properties:
 *             countLast7days:
 *               type: integer
 *       500:
 *         description: Erreur interne du serveur
 */
app.get(url + "/client/:id/stats/count7days", async (req, res) => {
  try {
    const id = req.params.id
    const sevenDaysAgo = new Date(Date.now() - (7 * 24 * 60 * 60 * 1000));
    const countLast7days = await Commande.countDocuments({
      "client": id,
      "date": { $gt: sevenDaysAgo }
    });
    res.json({ countLast7days });
  } catch (err) {
    res.status(500).json({ message: err.message });
  }
});

//Get graph client Orders last 7 days
/**
* @swagger
* /api/V1/client/{id}/stats/graph/ordersLast7d:
*   get:
*     tags: 
*       - Statistique
*     summary: Obtenir les commandes des 7 derniers jours pour un client spécifique
*     parameters:
*       - name: id
*         in: path
*         required: true
*         description: L'ID du client pour lequel les commandes seront récupérées
*     responses:
*       200:
*         description: Obtention réussie des commandes pour le client spécifié
*       500:
*         description: Erreur lors de l'obtention des commandes
*/
app.get(url + "/client/:id/stats/graph/ordersLast7d", async (req, res) => {
  try {
    const id = req.params.id
    // Obtenir les commandes dans les 7 derniers jours
    const sevenDaysAgo = new Date(Date.now() - (7 * 24 * 60 * 60 * 1000));
    const commandes = await Commande.find({
      "client": id,
      "date": { $gt: sevenDaysAgo }
    }).sort({ date: 1 });

    // Compter le nombre de commandes par jour
    const commandesByDay = {};
    commandes.forEach(commande => {
      const date = new Date(commande.date);
      const day = date.toLocaleDateString();
      if (commandesByDay[day]) {
        commandesByDay[day]++;
      } else {
        commandesByDay[day] = 1;
      }
    });

    // Créer un tableau des jours manquants
    const allDays = Array.from({ length: 7 }, (_, i) => new Date(Date.now() - (6 - i) * 24 * 60 * 60 * 1000).toLocaleDateString());
    // Ajouter les jours manquants à commandesByDay avec une valeur de 0
    allDays.forEach(day => {
      if (!commandesByDay[day]) {
        commandesByDay[day] = 0;
      }
    });
    // Trier commandesByDay par jour
    const sortedCommandesByDay = {};
    allDays.forEach(day => {
      sortedCommandesByDay[day] = commandesByDay[day];
    });

    res.json(sortedCommandesByDay);
  } catch (err) {
    res.status(500).json({ message: err.message });
  }
});

//Get graph client Orders last month (last 30 days)
/**
* @swagger
* /api/V1/client/{id}/stats/graph/ordersLastM:
*   get:
*     tags: 
*       - Statistique
*     summary: Obtenir les commandes du mois en cours pour un client spécifique
*     parameters:
*       - name: id
*         in: path
*         required: true
*         description: L'ID du client pour lequel les commandes seront récupérées
*     responses:
*       200:
*         description: Obtention réussie des commandes pour le client spécifié
*       500:
*         description: Erreur lors de l'obtention des commandes
*/
app.get(url + "/client/:id/stats/graph/ordersLastM", async (req, res) => {
  try {
    const id = req.params.id
    // Obtenir les commandes du mois en cours'
    const oneMonthAgo = new Date(Date.now() - (30 * 24 * 60 * 60 * 1000));
    const commandes = await Commande.find({
      "client": id,
      "date": { $gt: oneMonthAgo }
    }).sort({ date: 1 });
    // Compter le nombre de commandes par jour
    const commandesByDay = {};
    commandes.forEach(commande => {
      const date = new Date(commande.date);
      const day = date.toLocaleDateString();
      if (commandesByDay[day]) {
        commandesByDay[day]++;
      } else {
        commandesByDay[day] = 1;
      }
    });

    // Créer un tableau des jours manquants
    const allDays = Array.from({ length: 30 }, (_, i) => new Date(oneMonthAgo.getTime() + (i * 24 * 60 * 60 * 1000)).toLocaleDateString());
    // Ajouter les jours manquants à commandesByDay avec une valeur de 0
    allDays.forEach(day => {
      if (!commandesByDay[day]) {
        commandesByDay[day] = 0;
      }
    });
    // Trier commandesByDay par jour
    const sortedCommandesByDay = {};
    allDays.forEach(day => {
      sortedCommandesByDay[day] = commandesByDay[day];
    });

    res.json(sortedCommandesByDay);
  } catch (err) {
    res.status(500).json({ message: err.message });
  }
});

//Get graph client Orders last year (last 365 days)
/**
* @swagger
* /api/V1/client/{id}/stats/graph/ordersLastY:
*   get:
*     tags: 
*       - Statistique
*     summary: Obtenir les commandes de l'année en cours pour un client spécifique
*     parameters:
*       - name: id
*         in: path
*         required: true
*         description: L'ID du client pour lequel les commandes seront récupérées
*     responses:
*       200:
*         description: Obtention réussie des commandes pour le client spécifié
*       500:
*         description: Erreur lors de l'obtention des commandes
*/
app.get(url + "/client/:id/stats/graph/ordersLastY", async (req, res) => {
  try {
    const id = req.params.id
    // Obtenir les commandes de l'année en cours'
    const oneYearAgo = new Date(Date.now() - (365 * 24 * 60 * 60 * 1000));
    const commandes = await Commande.find({
      "client": id,
      "date": { $gt: oneYearAgo }
    }).sort({ date: 1 });

    // Compter le nombre de commandes par mois
    const months = ["janvier", "février", "mars", "avril", "mai", "juin", "juillet", "août", "septembre", "octobre", "novembre", "décembre"];
    const commandesByMonth = {};
    commandes.forEach(commande => {
      const date = new Date(commande.date);
      const month = months[date.getMonth()];
      if (commandesByMonth[month]) {
        commandesByMonth[month]++;
      } else {
        commandesByMonth[month] = 1;
      }
    });
    // Ajouter les mois manquants à commandesByMonth avec une valeur de 0
    months.forEach(month => {
      if (!commandesByMonth[month]) {
        commandesByMonth[month] = 0;
      }
    });
    // Trier commandesByMonth par mois
    const sortedCommandesByMonth = {};
    months.forEach(month => {
      sortedCommandesByMonth[month] = commandesByMonth[month];
    });

    res.json(sortedCommandesByMonth);


  } catch (err) {
    res.status(500).json({ message: err.message });
  }
});

//Get graph client Orders last year (last 365 days) -> repartition des commandes selon les trimestres
/**
* @swagger
* /api/V1/client/{id}/stats/graph/ordersLastYSortByQuarter:
*   get:
*     tags: 
*       - Statistique
*     summary: Obtenir les commandes de l'année en cours pour un client spécifique, classées par trimestre
*     parameters:
*       - name: id
*         in: path
*         required: true
*         description: L'ID du client pour lequel les commandes seront récupérées
*     responses:
*       200:
*         description: Obtention réussie des commandes pour le client spécifié, classées par trimestre
*       500:
*         description: Erreur lors de l'obtention des commandes
*/
app.get(url + "/client/:id/stats/graph/ordersLastYSortByQuarter", async (req, res) => {
  try {
    const id = req.params.id
    // Obtenir les commandes de l'année en cours'
    const oneYearAgo = new Date(Date.now() - (365 * 24 * 60 * 60 * 1000));
    const commandes = await Commande.find({
      "client": id,
      "date": { $gt: oneYearAgo }
    }).sort({ date: 1 });

    // Compter le nombre de commandes par trimestre
    const commandesByQuarter = {};
    commandes.forEach(commande => {
      const date = new Date(commande.date);
      const quarter = Math.floor((date.getMonth() + 3) / 3);
      if (commandesByQuarter[quarter]) {
        commandesByQuarter[quarter]++;
      } else {
        commandesByQuarter[quarter] = 1;
      }
    });

    // Ajouter les trimestres manquants à commandesByQuarter avec une valeur de 0
    for (let i = 1; i <= 4; i++) {
      if (!commandesByQuarter[i]) {
        commandesByQuarter[i] = 0;
      }
    }

    // Modifier les clés pour être de la forme "Trimestre 1", "Trimestre 2"
    Object.keys(commandesByQuarter).forEach(quarter => {
      commandesByQuarter[`Trimestre ${quarter}`] = commandesByQuarter[quarter];
      delete commandesByQuarter[quarter];
    });

    res.json(commandesByQuarter);
  } catch (err) {
    res.status(500).json({ message: err.message });
  }
});

////Graph Restaurant
//Get graph restaurant Orders last 7 days
/**
* @swagger
* /api/V1/restaurant/{id}/stats/graph/ordersLast7d:
*   get:
*     tags: 
*       - Statistique
*     summary: Obtenir les commandes des 7 derniers jours pour un restaurant spécifique
*     parameters:
*       - name: id
*         in: path
*         required: true
*         description: L'ID du restaurant pour lequel les commandes seront récupérées
*     responses:
*       200:
*         description: Obtention réussie des commandes pour le restaurant spécifié
*       500:
*         description: Erreur lors de l'obtention des commandes
*/
app.get(url + "/restaurant/:id/stats/graph/ordersLast7d", async (req, res) => {
  try {
    const id = req.params.id
    // Obtenir les commandes dans les 7 derniers jours
    const sevenDaysAgo = new Date(Date.now() - (7 * 24 * 60 * 60 * 1000));
    const commandes = await Commande.find({
      "restaurant": id,
      "date": { $gt: sevenDaysAgo }
    }).sort({ date: 1 });

    // Compter le nombre de commandes par jour
    const commandesByDay = {};
    commandes.forEach(commande => {
      const date = new Date(commande.date);
      const day = date.toLocaleDateString();
      if (commandesByDay[day]) {
        commandesByDay[day]++;
      } else {
        commandesByDay[day] = 1;
      }
    });

    // Créer un tableau des jours manquants
    const allDays = Array.from({ length: 7 }, (_, i) => new Date(Date.now() - (6 - i) * 24 * 60 * 60 * 1000).toLocaleDateString());
    // Ajouter les jours manquants à commandesByDay avec une valeur de 0
    allDays.forEach(day => {
      if (!commandesByDay[day]) {
        commandesByDay[day] = 0;
      }
    });
    // Trier commandesByDay par jour
    const sortedCommandesByDay = {};
    allDays.forEach(day => {
      sortedCommandesByDay[day] = commandesByDay[day];
    });

    res.json(sortedCommandesByDay);
  } catch (err) {
    res.status(500).json({ message: err.message });
  }
});

//Get graph restaurant Orders last month (last 30 days)
/**
* @swagger
* tags:
*   - name: Statistique
* paths:
*  /api/V1/restaurant/{id}/stats/graph/ordersLastM:
*    get:
*      summary: Récupérer les statistiques des commandes d'un restaurant pour les 30 derniers jours
*      tags:
*        - Statistique
*      parameters:
*        - in: path
*          name: id
*          required: true
*          schema:
*            type: string
*      responses:
*        '200':
*          description: Statistiques des commandes retournées
*        '500':
*          description: Erreur interne du serveur
*/
app.get(url + "/restaurant/:id/stats/graph/ordersLastM", async (req, res) => {
  try {
    const id = req.params.id
    // Obtenir les commandes du mois en cours'
    const oneMonthAgo = new Date(Date.now() - (30 * 24 * 60 * 60 * 1000));
    const commandes = await Commande.find({
      "restaurant": id,
      "date": { $gt: oneMonthAgo }
    }).sort({ date: 1 });
    // Compter le nombre de commandes par jour
    const commandesByDay = {};
    commandes.forEach(commande => {
      const date = new Date(commande.date);
      const day = date.toLocaleDateString();
      if (commandesByDay[day]) {
        commandesByDay[day]++;
      } else {
        commandesByDay[day] = 1;
      }
    });

    // Créer un tableau des jours manquants
    const allDays = Array.from({ length: 30 }, (_, i) => new Date(oneMonthAgo.getTime() + (i * 24 * 60 * 60 * 1000)).toLocaleDateString());
    // Ajouter les jours manquants à commandesByDay avec une valeur de 0
    allDays.forEach(day => {
      if (!commandesByDay[day]) {
        commandesByDay[day] = 0;
      }
    });
    // Trier commandesByDay par jour
    const sortedCommandesByDay = {};
    allDays.forEach(day => {
      sortedCommandesByDay[day] = commandesByDay[day];
    });

    res.json(sortedCommandesByDay);
  } catch (err) {
    res.status(500).json({ message: err.message });
  }
});

//Get graph client Orders last year (last 365 days)
/**
* @swagger
* /api/V1/restaurant/{id}/stats/graph/ordersLastY:
*   get:
*     tags: 
*       - Statistique
*     summary: Obtenir les commandes de l'année en cours pour un restaurant spécifique
*     parameters:
*       - name: id
*         in: path
*         required: true
*         description: L'ID du restaurant pour lequel les commandes seront récupérées
*     responses:
*       200:
*         description: Obtention réussie des commandes pour le restaurant spécifié
*       500:
*         description: Erreur lors de l'obtention des commandes
*/
app.get(url + "/restaurant/:id/stats/graph/ordersLastY", async (req, res) => {
  try {
    const id = req.params.id
    // Obtenir les commandes de l'année en cours'
    const oneYearAgo = new Date(Date.now() - (365 * 24 * 60 * 60 * 1000));
    const commandes = await Commande.find({
      "restaurant": id,
      "date": { $gt: oneYearAgo }
    }).sort({ date: 1 });

    // Compter le nombre de commandes par mois
    const months = ["janvier", "février", "mars", "avril", "mai", "juin", "juillet", "août", "septembre", "octobre", "novembre", "décembre"];
    const commandesByMonth = {};
    commandes.forEach(commande => {
      const date = new Date(commande.date);
      const month = months[date.getMonth()];
      if (commandesByMonth[month]) {
        commandesByMonth[month]++;
      } else {
        commandesByMonth[month] = 1;
      }
    });
    // Ajouter les mois manquants à commandesByMonth avec une valeur de 0
    months.forEach(month => {
      if (!commandesByMonth[month]) {
        commandesByMonth[month] = 0;
      }
    });
    // Trier commandesByMonth par mois
    const sortedCommandesByMonth = {};
    months.forEach(month => {
      sortedCommandesByMonth[month] = commandesByMonth[month];
    });

    res.json(sortedCommandesByMonth);


  } catch (err) {
    res.status(500).json({ message: err.message });
  }
});

//Get graph restaurant Orders last year (last 365 days) -> repartition des commandes selon les trimestres
/**
 * @swagger
 * /api/V1/clients/{id}/stats/graph/ordersLastYSortByQuarter:
 *   get:
 *     tags:
 *       - Statistique
 *     description: Retourne le nombre de commandes d'un client par trimestre sur l'année en cours
 *     parameters:
 *       - name: id
 *         description: ID du client
 *         in: path
 *         required: true
 *         schema:
 *           type: string
 *     responses:
 *       200:
 *         description: Retourne le nombre de commandes par trimestre
 *         content:
 *           application/json:
 *             schema:
 *               type: object
 *               properties:
 *                 Trimestre 1:
 *                   type: integer
 *                 Trimestre 2:
 *                   type: integer
 *                 Trimestre 3:
 *                   type: integer
 *                 Trimestre 4:
 *                   type: integer
 *       500:
 *         description: Erreur serveur
 */
app.get(url + "/clients/:id/stats/graph/ordersLastYSortByQuarter", async (req, res) => {
  try {
    const id = req.params.id
    // Obtenir les commandes de l'année en cours'
    const oneYearAgo = new Date(Date.now() - (365 * 24 * 60 * 60 * 1000));
    const commandes = await Commande.find({
      "restaurant": id,
      "date": { $gt: oneYearAgo }
    }).sort({ date: 1 });

    // Compter le nombre de commandes par trimestre
    const commandesByQuarter = {};
    commandes.forEach(commande => {
      const date = new Date(commande.date);
      const quarter = Math.floor((date.getMonth() + 3) / 3);
      if (commandesByQuarter[quarter]) {
        commandesByQuarter[quarter]++;
      } else {
        commandesByQuarter[quarter] = 1;
      }
    });

    // Ajouter les trimestres manquants à commandesByQuarter avec une valeur de 0
    for (let i = 1; i <= 4; i++) {
      if (!commandesByQuarter[i]) {
        commandesByQuarter[i] = 0;
      }
    }

    // Modifier les clés pour être de la forme "Trimestre 1", "Trimestre 2"
    Object.keys(commandesByQuarter).forEach(quarter => {
      commandesByQuarter[`Trimestre ${quarter}`] = commandesByQuarter[quarter];
      delete commandesByQuarter[quarter];
    });

    res.json(commandesByQuarter);
  } catch (err) {
    res.status(500).json({ message: err.message });
  }
});

/////Commercial
////Graph
//Get graph all restaurant Orders last 7 days
/**
 * @swagger
 * /api/V1/commandes/stats/graph/ordersLast7d:
 *   get:
 *     tags:
 *       - Statistique
 *     description: Retourne le nombre de commandes pour les 7 derniers jours.
 *     produces:
 *       - application/json
 *     responses:
 *       200:
 *         description: Le nombre de commandes pour les 7 derniers jours.
 *       500:
 *         description: Erreur interne du serveur.
 */
app.get(url + "/commandes/stats/graph/ordersLast7d", async (req, res) => {
  try {
    // Obtenir les commandes dans les 7 derniers jours
    const sevenDaysAgo = new Date(Date.now() - (7 * 24 * 60 * 60 * 1000));
    const commandes = await Commande.find({
      "date": { $gt: sevenDaysAgo }
    }).sort({ date: 1 });

    // Compter le nombre de commandes par jour
    const commandesByDay = {};
    commandes.forEach(commande => {
      const date = new Date(commande.date);
      const day = date.toLocaleDateString();
      if (commandesByDay[day]) {
        commandesByDay[day]++;
      } else {
        commandesByDay[day] = 1;
      }
    });

    // Créer un tableau des jours manquants
    const allDays = Array.from({ length: 7 }, (_, i) => new Date(Date.now() - (6 - i) * 24 * 60 * 60 * 1000).toLocaleDateString());
    // Ajouter les jours manquants à commandesByDay avec une valeur de 0
    allDays.forEach(day => {
      if (!commandesByDay[day]) {
        commandesByDay[day] = 0;
      }
    });
    // Trier commandesByDay par jour
    const sortedCommandesByDay = {};
    allDays.forEach(day => {
      sortedCommandesByDay[day] = commandesByDay[day];
    });

    res.json(sortedCommandesByDay);
  } catch (err) {
    res.status(500).json({ message: err.message });
  }
});

//Get graph all restaurant Orders last month (last 30 days)
/**
* @swagger
* tags:
*   - name: Statistique
* paths:
*  /api/V1/commandes/stats/graph/ordersLastM:
*    get:
*      summary: Récupérer les statistiques des commandes pour les 30 derniers jours
*      tags:
*        - Statistique
*      responses:
*        '200':
*          description: Statistiques des commandes retournées
*        '500':
*          description: Erreur interne du serveur
*/
app.get(url + "/commandes/stats/graph/ordersLastM", async (req, res) => {
  try {
    // Obtenir les commandes du mois en cours'
    const oneMonthAgo = new Date(Date.now() - (30 * 24 * 60 * 60 * 1000));
    const commandes = await Commande.find({
      "date": { $gt: oneMonthAgo }
    }).sort({ date: 1 });
    // Compter le nombre de commandes par jour
    const commandesByDay = {};
    commandes.forEach(commande => {
      const date = new Date(commande.date);
      const day = date.toLocaleDateString();
      if (commandesByDay[day]) {
        commandesByDay[day]++;
      } else {
        commandesByDay[day] = 1;
      }
    });

    // Créer un tableau des jours manquants
    const allDays = Array.from({ length: 30 }, (_, i) => new Date(oneMonthAgo.getTime() + (i * 24 * 60 * 60 * 1000)).toLocaleDateString());
    // Ajouter les jours manquants à commandesByDay avec une valeur de 0
    allDays.forEach(day => {
      if (!commandesByDay[day]) {
        commandesByDay[day] = 0;
      }
    });
    // Trier commandesByDay par jour
    const sortedCommandesByDay = {};
    allDays.forEach(day => {
      sortedCommandesByDay[day] = commandesByDay[day];
    });

    res.json(sortedCommandesByDay);
  } catch (err) {
    res.status(500).json({ message: err.message });
  }
});

//Get graph all restaurant Orders last year (last 365 days)
/**
 * @swagger
 * /api/V1/commandes/stats/graph/ordersLastY:
 *   get:
 *     tags:
 *       - Statistique
 *     description: Retourne les commandes de l'année en cours, triées par mois
 *     produces:
 *       - application/json
 *     responses:
 *       200:
 *         description: Liste des commandes de l'année en cours, triées par mois
 *         schema:
 *           type: object
 *           properties:
 *            janvier:
 *              type: integer
 *            février:
 *              type: integer
 *            mars:
 *              type: integer
 *            avril:
 *              type: integer
 *            mai:
 *              type: integer
 *            juin:
 *              type: integer
 *            juillet:
 *              type: integer
 *            août:
 *              type: integer
 *            septembre:
 *              type: integer
 *            octobre:
 *              type: integer
 *            novembre:
 *              type: integer
 *            décembre:
 *              type: integer
 *       500:
 *         description: Erreur interne du serveur
 */
app.get(url + "/commandes/stats/graph/ordersLastY", async (req, res) => {
  try {
    // Obtenir les commandes de l'année en cours'
    const oneYearAgo = new Date(Date.now() - (365 * 24 * 60 * 60 * 1000));
    const commandes = await Commande.find({
      "date": { $gt: oneYearAgo }
    }).sort({ date: 1 });

    // Compter le nombre de commandes par mois
    const months = ["janvier", "février", "mars", "avril", "mai", "juin", "juillet", "août", "septembre", "octobre", "novembre", "décembre"];
    const commandesByMonth = {};
    commandes.forEach(commande => {
      const date = new Date(commande.date);
      const month = months[date.getMonth()];
      if (commandesByMonth[month]) {
        commandesByMonth[month]++;
      } else {
        commandesByMonth[month] = 1;
      }
    });
    // Ajouter les mois manquants à commandesByMonth avec une valeur de 0
    months.forEach(month => {
      if (!commandesByMonth[month]) {
        commandesByMonth[month] = 0;
      }
    });
    // Trier commandesByMonth par mois
    const sortedCommandesByMonth = {};
    months.forEach(month => {
      sortedCommandesByMonth[month] = commandesByMonth[month];
    });

    res.json(sortedCommandesByMonth);


  } catch (err) {
    res.status(500).json({ message: err.message });
  }
});

//Get graph all restaurant Orders last year (last 365 days) -> repartition des commandes selon les trimestres
/**
 * @swagger
 * /api/V1/commandes/stats/graph/ordersLastYSortByQuarter:
 *   get:
 *     tags:
 *       - Statistique
 *     description: Retourne les commandes de l'année en cours, triées par trimestre
 *     produces:
 *       - application/json
 *     responses:
 *       200:
 *         description: Liste des commandes de l'année en cours, triées par trimestre
 *         schema:
 *           type: object
 *           properties:
 *            Trimestre 1:
 *              type: integer
 *            Trimestre 2:
 *              type: integer
 *            Trimestre 3:
 *              type: integer
 *            Trimestre 4:
 *              type: integer
 *       500:
 *         description: Erreur interne du serveur
 */
app.get(url + "/commandes/stats/graph/ordersLastYSortByQuarter", async (req, res) => {
  try {
    // Obtenir les commandes de l'année en cours'
    const oneYearAgo = new Date(Date.now() - (365 * 24 * 60 * 60 * 1000));
    const commandes = await Commande.find({
      "date": { $gt: oneYearAgo }
    }).sort({ date: 1 });

    // Compter le nombre de commandes par trimestre
    const commandesByQuarter = {};
    commandes.forEach(commande => {
      const date = new Date(commande.date);
      const quarter = Math.floor((date.getMonth() + 3) / 3);
      if (commandesByQuarter[quarter]) {
        commandesByQuarter[quarter]++;
      } else {
        commandesByQuarter[quarter] = 1;
      }
    });

    // Ajouter les trimestres manquants à commandesByQuarter avec une valeur de 0
    for (let i = 1; i <= 4; i++) {
      if (!commandesByQuarter[i]) {
        commandesByQuarter[i] = 0;
      }
    }

    // Modifier les clés pour être de la forme "Trimestre 1", "Trimestre 2"
    Object.keys(commandesByQuarter).forEach(quarter => {
      commandesByQuarter[`Trimestre ${quarter}`] = commandesByQuarter[quarter];
      delete commandesByQuarter[quarter];
    });

    res.json(commandesByQuarter);
  } catch (err) {
    res.status(500).json({ message: err.message });
  }
});

//#endregion

//#region api restaurateur

//S'inscrire en tant que restaurateur
/**
 * @swagger
 * /api/V1/register/restaurateur:
 *   post:
 *     tags:
 *       - Connexion restaurateur
 *     summary: Ajout d'un restaurateur
 *     description: Ajout d'un restaurateur dans la base de données
 *     parameters:
 *       - name: body
 *         in: body
 *         required: true
 *         schema:
 *           type: object
 *           properties:
 *             name:
 *               type: string
 *             phone_number:
 *               type: string
 *             email:
 *               type: string
 *             password:
 *               type: string
 *             restaurant_name:
 *               type: string
 *     responses:
 *       200:
 *         description: Ajout réussi
 *       400:
 *         description: L'adresse mail est déjà utilisée
 *       500:
 *         description: Erreur interne
 */
app.post(url + "/register/restaurateur", async (req, res) => {
  try {
    let data = req.body;
    let pool = await sql.connect(config);
    let userAlreadyExist = false;

    const requestSelect = pool.request();
    requestSelect.input("email", sql.VarChar, data.email);
    const result = await requestSelect.query(
      "SELECT COUNT (*) AS compte FROM dbo.person WHERE email = @email"
    );
    if (parseInt(JSON.stringify(result.recordset[0].compte)) != 0) {
      userAlreadyExist = true;
    }

    if (userAlreadyExist) {
      res
        .status(400)
        .send(`L'addresse mail : "${data.email}" est déjà utilisée, veuillez vous connecter`)
        .end();
    } else {
      let encryptedPassword = await bcrypt.hash(data.password, 10);

      const request = pool.request();
      request.input("name", sql.VarChar, data.name);
      request.input("phone_number", sql.VarChar, data.phone_number);
      request.input("email", sql.VarChar, data.email);
      request.input("password", sql.VarChar, encryptedPassword);
      await request.query(
        "INSERT INTO dbo.person(name, phone_number, email, password, role) VALUES (@name, @phone_number, @email, @password, 2)"
      );


      const requestSelect = pool.request();
      requestSelect.input("email", sql.VarChar, data.email);
      const result = await requestSelect.query("SELECT id_person FROM dbo.person WHERE email = @email");

      console.log(result.recordset[0].id_person)


      const requestClient = pool.request();
      requestClient.input("id_restaurant", sql.Int, result.recordset[0].id_person);
      requestClient.input("restaurant_name", sql.VarChar, data.restaurant_name);
      await requestClient.query(
        "INSERT INTO dbo.restaurateur (id_restaurant, code_parrainage, restaurant_name) VALUES (@id_restaurant, '', @restaurant_name)"
      );
      const expirationTime = 5 * 24 * 60 * 60; // 5 jours en secondes
      const token = jwt.sign({ email: data.email }, process.env.TOKEN_KEY, { expiresIn: expirationTime });
      res.cookie('token', token, { httpOnly: true, maxAge: expirationTime * 1000 }).send("Inscris !").end();
    }
  } catch (error) {
    res.status(500).send(error).end();
  }
});

//Login restaurateur
/**
 * @swagger
 * /api/V1/login/restaurateur:
 *   post:
 *     tags:
 *       - Connexion restaurateur
 *     summary: Connexion d'un restaurateur
 *     description: Connexion d'un restaurateur avec vérification de l'email et du mot de passe
 *     parameters:
 *       - name: body
 *         in: body
 *         required: true
 *         schema:
 *           type: object
 *           properties:
 *             email:
 *               type: string
 *             password:
 *               type: string
 *     responses:
 *       200:
 *         description: Connexion réussie
 *       400:
 *         description: Adresse mail ou mot de passe invalide
 *       500:
 *         description: Erreur interne
 */
app.post(url + "/login/restaurateur", async (req, res) => {
  let data = req.body;
  let pool = await sql.connect(config);

  const request = pool.request();
  request.input('email', sql.VarChar, data.email);
  request.query("SELECT email, password FROM dbo.person WHERE email = @email", (err, result) => {
    if (err) {
      return res.status(500).send(err);
    }
    if (result.recordset.length == 0) {
      return res.status(400).send("Adresse mail non existante");
    }
    const validPassword = bcrypt.compareSync(data.password, result.recordset[0].password);
    if (!validPassword) {
      return res.status(400).send('Mot de passe invalide');
    }
    const expirationTime = 5 * 24 * 60 * 60; // 5 jours en secondes
    const token = jwt.sign({ email: data.email }, process.env.TOKEN_KEY, { expiresIn: expirationTime });

    res.cookie('token', token, { httpOnly: true, maxAge: expirationTime * 1000 }).send("Connecté !").end();
  });
});

//Mise à jour du nom du restaurant
/**
 * @swagger
 * /api/V1/restaurant/name:
 *   put:
 *     tags:
 *       - Restaurant
 *     description: Met à jour les informations du restaurant.
 *     parameters:
 *       - name: email
 *         in: query
 *         description: Email de l'utilisateur connecté.
 *         required: true
 *         type: string
 *       - name: restaurant_name
 *         in: body
 *         description: Nom du restaurant.
 *         required: true
 *         type: string
 *     responses:
 *       200:
 *         description: Informations mises à jour avec succès
 *       500:
 *         description: Erreur lors de la mise à jour des informations
 */
app.put(url + "/restaurant/name", async (req, res) => {
  checkToken(req, res)
  let data = req.body;

  let decodedToken = getInfoToken(req, res)
  let email = decodedToken.email;
  let restaurant_name = data.restaurant_name

  let pool = await sql.connect(config);
  const requestSelect = pool.request();

  requestSelect.input("email", sql.VarChar, email);

  const result = await requestSelect.query("SELECT id_person FROM dbo.person WHERE email = @email");
  const id_restaurant = result.recordset[0].id_person
  // Met à jour les informations de l'utilisateur
  const request = pool.request();
  request.input('email', sql.VarChar, email);
  request.input('restaurant_name', sql.VarChar, restaurant_name);
  request.input('id_restaurant', sql.Int, id_restaurant);

  request.query("UPDATE dbo.restaurateur SET restaurant_name = @restaurant_name WHERE id_restaurant = @id_restaurant", (err, result) => {
    if (err) {
      return res.status(500).send(err);
    }
    res.status(200).send(`Informations mises à jour avec succès`);
  });
});

//Suppression du compte restaurateur actuellement connecté
/**
 * @swagger
 * /api/V1/restaurateur:
 *   delete:
 *     tags:
 *       - Restaurateur
 *     description: Supprime un restaurateur.
 *     parameters:
 *       - name: email
 *         in: query
 *         description: Email de l'utilisateur connecté.
 *         required: true
 *         type: string
 *     responses:
 *       200:
 *         description: Compte supprimé avec succès
 *       500:
 *         description: Erreur lors de la suppression du compte
 */
app.delete(url + "/restaurateur", async (req, res) => {
  checkToken(req, res)
  try {
    let pool = await sql.connect(config);
    const request = pool.request();
    const requestClient = pool.request();
    let decodedToken = getInfoToken(req, res);
    let email = decodedToken.email
    const requestSelect = pool.request();
    requestSelect.input("email", sql.VarChar, email);
    const result = await requestSelect.query("SELECT id_person FROM dbo.person WHERE email = @email");
    request.input('email', sql.VarChar, email);
    console.log(result.recordset[0].id_person)
    requestClient.input('id_restaurant', sql.Int, result.recordset[0].id_person);
    await requestClient.query("DELETE FROM dbo.restaurateur WHERE id_restaurant = @id_restaurant;")
    await request.query("DELETE FROM dbo.person WHERE email = @email;")
    res.status(200).send(`Le compte lié à l'address : ${email} a bien été supprimé`);
    sql.close()
  } catch (err) {
    res.status(500).json({ message: err.message });
  }
});

//Supprimer un restaurateur spécifique
/**
 * @swagger
 * /api/V1/restaurateur/{email}:
 *   delete:
 *     tags:
 *       - Restaurateur
 *     description: Supprime un restaurateur.
 *     parameters:
 *       - name: email
 *         in: path
 *         description: Email de l'utilisateur connecté.
 *         required: true
 *         type: string
 *     responses:
 *       200:
 *         description: Compte supprimé avec succès
 *       500:
 *         description: Erreur lors de la suppression du compte
 */
app.delete(url + "/restaurateur/:email", async (req, res) => {
  checkToken(req, res)
  try {
    let pool = await sql.connect(config);
    const request = pool.request();
    const requestClient = pool.request();
    let decodedToken = getInfoToken(req, res);
    let email = req.params.email
    const requestSelect = pool.request();
    requestSelect.input("email", sql.VarChar, email);
    const result = await requestSelect.query("SELECT id_person FROM dbo.person WHERE email = @email");
    request.input('email', sql.VarChar, email);
    console.log(result.recordset[0].id_person)
    requestClient.input('id_restaurant', sql.Int, result.recordset[0].id_person);
    await requestClient.query("DELETE FROM dbo.restaurateur WHERE id_restaurant = @id_restaurant;")
    await request.query("DELETE FROM dbo.person WHERE email = @email;")
    res.status(200).send(`Le compte lié à l'address : ${email} a bien été supprimé`);
    sql.close()
  } catch (err) {
    res.status(500).json({ message: err.message });
  }
});

//#endregion

//#region api livreur

//Inscrit un nouveau livreur
/**
 * @swagger
 * /api/V1/register/livreur:
 *   post:
 *     tags:
 *       - Connexion livreur
 *     description: Register a new livreur
 *     consumes:
 *       - application/json
 *     produces:
 *       - application/json
 *     parameters:
 *       - name: livreur
 *         description: Livreur object
 *         in: body
 *         required: true
 *         schema:
 *           $ref: '#/definitions/Livreur'
 *     responses:
 *       200:
 *         description: Successfully registered
 *       400:
 *         description: Email already in use
 *       500:
 *         description: Internal server error
 */
/**
 * @swagger
 * definitions:
 *   Livreur:
 *     type: object
 *     required:
 *       - name
 *       - phone_number
 *       - email
 *       - password
 *     properties:
 *       name:
 *         type: string
 *       email:
 *         type: string
 *         format: email
 *       phone_number:
 *          type: string
 *          format: phone_number
 *       password:
 *         type: string
 *         format: password
 */
app.post(url + "/register/livreur", async (req, res) => {
  checkToken(req, res)
  try {
    let data = req.body;
    let pool = await sql.connect(config);
    let userAlreadyExist = false;

    const requestSelect = pool.request();
    requestSelect.input("email", sql.VarChar, data.email);
    const result = await requestSelect.query(
      "SELECT COUNT (*) AS compte FROM dbo.person WHERE email = @email"
    );
    if (parseInt(JSON.stringify(result.recordset[0].compte)) != 0) {
      userAlreadyExist = true;
    }

    if (userAlreadyExist) {
      res
        .status(400)
        .send(`L'addresse mail : "${data.email}" est déjà utilisée, veuillez vous connecter`)
        .end();
    } else {
      let encryptedPassword = await bcrypt.hash(data.password, 10);

      const request = pool.request();
      request.input("name", sql.VarChar, data.name);
      request.input("phone_number", sql.Int, data.phone_number);
      request.input("email", sql.VarChar, data.email);
      request.input("password", sql.VarChar, encryptedPassword);
      await request.query(
        "INSERT INTO dbo.person(name, phone_number, email, password, role) VALUES (@name, @phone_number, @email, @password, 3)"
      );


      const requestSelect = pool.request();
      requestSelect.input("email", sql.VarChar, data.email);
      const result = await requestSelect.query("SELECT id_person FROM dbo.person WHERE email = @email");

      console.log(result.recordset[0].id_person)


      const requestClient = pool.request();
      requestClient.input("id_person", sql.Int, result.recordset[0].id_person);
      await requestClient.query(
        "INSERT INTO dbo.deliverer (id_person, code_parrainage, statut_activite) VALUES (@id_person, '', 0)"
      );
      const expirationTime = 5 * 24 * 60 * 60; // 5 jours en secondes
      const token = jwt.sign({ email: data.email }, process.env.TOKEN_KEY, { expiresIn: expirationTime });
      res.cookie('token', token, { httpOnly: true, maxAge: expirationTime * 1000 }).send("Inscris !").end();
    }
  } catch (error) {
    res.status(500).send(error).end();
  }
});

//Permets à un livreur de se connecter (fonction redondante)
/**
 * @swagger
 * /api/V1/login/livreur:
 *   post:
 *     tags:
 *       - Connexion livreur
 *     description: Permet à un livreur de se connecter
 *     produces:
 *       - application/json
 *     parameters:
 *       - name: email
 *         description: Adresse mail du livreur
 *         in: body
 *         required: true
 *         type: string
 *       - name: password
 *         description: Mot de passe du livreur
 *         in: body
 *         required: true
 *         type: string
 *     responses:
 *       200:
 *         description: Connexion réussie
 *       400:
 *         description: Adresse mail non existante ou mot de passe invalide
 *       500:
 *         description: Erreur interne du serveur
 */
app.post(url + "/login/livreur", async (req, res) => {
  checkToken(req, res)
  let data = req.body;
  let pool = await sql.connect(config);

  const request = pool.request();
  request.input('email', sql.VarChar, data.email);
  request.query("SELECT email, password FROM dbo.person WHERE email = @email", (err, result) => {
    if (err) {
      return res.status(500).send(err);
    }
    if (result.recordset.length == 0) {
      return res.status(400).send("Adresse mail non existante");
    }
    const validPassword = bcrypt.compareSync(data.password, result.recordset[0].password);
    if (!validPassword) {
      return res.status(400).send('Mot de passe invalide');
    }
    const expirationTime = 5 * 24 * 60 * 60; // 5 jours en secondes
    const token = jwt.sign({ email: data.email }, process.env.TOKEN_KEY, { expiresIn: expirationTime });

    res.cookie('token', token, { httpOnly: true, maxAge: expirationTime * 1000 }).send("Connecté !").end();
  });
});

/**
 * @swagger
 * /api/V1/livreur/activite:
 *   put:
 *     tags:
 *       - Livreur
 *     description: Modification de l'activité d'un livreur
 *     produces:
 *       - application/json
 *     parameters:
 *       - name: body
 *         description: Objet JSON contenant le statut d'activité (actif ou inactif)
 *         in: body
 *         required: true
 *         schema:
 *           $ref: '#/definitions/StatutActivite'
 *     responses:
 *       200:
 *         description: Informations mises à jour avec succès
 *       500:
 *         description: Erreur lors de la mise à jour des informations
 */
/**
 * Definition of the StatutActivite object
 * @typedef {Object} StatutActivite
 * @property {string} statut_activite - Statut d'activité (actif ou inactif)
 */
app.put(url + "/livreur/activite", async (req, res) => {
  checkToken(req, res)
  let data = req.body;

  let decodedToken = getInfoToken(req, res)
  let email = decodedToken.email;
  let statut_activite = data.statut_activite

  let pool = await sql.connect(config);
  const requestSelect = pool.request();

  requestSelect.input("email", sql.VarChar, email);

  const result = await requestSelect.query("SELECT id_person FROM dbo.person WHERE email = @email");
  const id_person = result.recordset[0].id_person
  // Met à jour les informations de l'utilisateur
  const request = pool.request();
  request.input('email', sql.VarChar, email);
  request.input('statut_activite', sql.VarChar, statut_activite);
  request.input('id_person', sql.Int, id_person);

  request.query("UPDATE dbo.deliverer SET statut_activite = @statut_activite WHERE id_person = @id_person", (err, result) => {
    if (err) {
      return res.status(500).send(err);
    }
    res.status(200).send(`Informations mises à jour avec succès`);
  });
});

/**
 * @swagger
 * /api/V1/livreur:
 *    delete:
 *      tags:
 *        - Livreur
 *      description: Supprime un livreur
 *      produces:
 *        - application/json
 *      responses:
 *        200:
 *          description: Le compte lié à l'adresse mail a été supprimé avec succès
 *        400:
 *          description: Erreur lors de la suppression du compte
 */
app.delete(url + "/livreur", async (req, res) => {
  checkToken(req, res)
  try {
    let pool = await sql.connect(config);
    const request = pool.request();
    const requestClient = pool.request();
    let decodedToken = getInfoToken(req, res);
    let email = decodedToken.email
    const requestSelect = pool.request();
    requestSelect.input("email", sql.VarChar, email);
    const result = await requestSelect.query("SELECT id_person FROM dbo.person WHERE email = @email");
    request.input('email', sql.VarChar, email);
    console.log(result.recordset[0].id_person)
    requestClient.input('id_person', sql.Int, result.recordset[0].id_person);
    await requestClient.query("DELETE FROM dbo.deliverer WHERE id_person = @id_person;")
    await request.query("DELETE FROM dbo.person WHERE email = @email;")
    res.status(200).send(`Le compte lié à l'address : ${email} a bien été supprimé`);
    sql.close()
  } catch (err) {
    res.status(500).json({ message: err.message });
  }
});

//#endregion

//#region api administrateur

//Modifie un utilisateur spécifique
/**
 * @swagger
 * /api/V1/user/{email}:
 *   put:
 *     tags:
 *       - Admin
 *     description: Met à jour les informations d'un utilisateur.
 *     parameters:
 *       - name: email
 *         in: path
 *         description: Email de l'utilisateur à mettre à jour.
 *         required: true
 *         type: string
 *       - name: surname
 *         in: body
 *         description: Nom de l'utilisateur.
 *         required: true
 *         type: string
 *       - name: name
 *         in: body
 *         description: Prénom de l'utilisateur.
 *         required: true
 *         type: string
 *       - name: birth
 *         in: body
 *         description: Date de naissance de l'utilisateur.
 *         required: true
 *         type: date
 *       - name: phone_number
 *         in: body
 *         description: Numéro de téléphone de l'utilisateur.
 *         required: true
 *         type: integer
 *     responses:
 *       200:
 *         description: Informations mises à jour avec succès
 *       500:
 *         description: Erreur lors de la mise à jour des informations
 */
app.put(url + "/user/:email", checkTokenA, async (req, res) => {
  let data = req.body;

  let email = req.params.email;

  let surname = data.surname;
  let name = data.name;
  let birth = new Date(data.birth)
  let phone_number = data.phone_number;

  let pool = await sql.connect(config);

  // Met à jour les informations de l'utilisateur
  const request = pool.request();
  request.input('email', sql.VarChar, email);
  request.input('surname', sql.VarChar, surname);
  request.input('name', sql.VarChar, name);
  request.input('birth', sql.Date, birth); //YYYY-MM-DD
  request.input('phone_number', sql.Int, phone_number);

  request.query("UPDATE dbo.person SET surname = @surname, name = @name, birth = @birth, phone_number = @phone_number WHERE email = @email", (err, result) => {
    if (err) {
      return res.status(500).send(err);
    }
    res.status(200).send(`Informations mises à jour avec succès`);
  });
});

//Suppression d'un uilisateur spécifique
/**
 * @swagger
 * /api/V1/client/{email}:
 *   delete:
 *     tags:
 *       - Admin
 *     description: Supprime un client.
 *     parameters:
 *       - name: email
 *         in: path
 *         description: Email du client à supprimer.
 *         required: true
 *         type: string
 *     responses:
 *       200:
 *         description: Compte supprimé avec succès
 *       500:
 *         description: Erreur lors de la suppression du compte
 */
app.delete(url + "/client/:email", checkTokenA, async (req, res) => {
  try {
    let pool = await sql.connect(config);
    const request = pool.request();
    const requestClient = pool.request();
    const email = req.params.email
    const requestSelect = pool.request();

    requestSelect.input("email", sql.VarChar, email);

    const result = await requestSelect.query("SELECT id_person FROM dbo.person WHERE email = @email");

    request.input('email', sql.VarChar, email);
    console.log(result.recordset[0].id_person)

    requestClient.input('id_person', sql.Int, result.recordset[0].id_person);

    await requestClient.query("DELETE FROM dbo.client WHERE id_person = @id_person;")
    await request.query("DELETE FROM dbo.person WHERE email = @email;")

    res.status(200).send(`Le compte lié à l'address : ${email} a bien été supprimé`);
    sql.close()
  } catch (err) {
    res.status(500).json({ message: err.message });
  }
});

//Récupère un utilisateur via son addresse mail
/**
 * @swagger
 * /api/V1/user/{email}:
 *   get:
 *     tags:
 *       - Admin
 *     description: Returns the user's information by email
 *     parameters:
 *       - in: path
 *         name: email
 *         required: true
 *         schema:
 *           type: string
 *     responses:
 *       200:
 *         description: User information
 *       500:
 *         description: Internal server error
 */
app.get(url + '/user/:email', checkTokenA, async (req, res) => {
  let pool = await sql.connect(config);
  const request = pool.request();
  const email = req.params.email
  request.input('email', sql.VarChar, email);
  request.query("SELECT surname, name, birth, phone_number, email FROM dbo.person WHERE email = @email", (err, result) => {
    if (err) {
      return res.status(500).send(err);
    }
    return res.status(200).json(result.recordset);
  });
});


//Supprime un utilisateur sans prendre en compte son role
/**
 * @swagger
 * /api/V1/user/{email}:
 *    delete:
 *      tags:
 *        - Admin
 *      description: delete a user by email
 *      parameters:
 *        - name: email
 *          in: path
 *          required: true
 *          type: string
 *      responses:
 *        200:
 *          description: user account deleted
 *        500:
 *          description: internal server error
 */
app.delete(url + "/user/:email", checkTokenA, async (req, res) => {
  try {
    let pool = await sql.connect(config);
    const request = pool.request();

    const email = req.params.email
    const requestSelect = pool.request();
    request.input("email", sql.VarChar, email)
    requestSelect.input("email", sql.VarChar, email);

    const result = await requestSelect.query("SELECT id_person, role FROM dbo.person WHERE email = @email");

    const role = result.recordset[0].role

    switch (role) {
      case 1:
        const requestClient = pool.request();
        requestClient.input('id_person', sql.Int, result.recordset[0].id_person);
        requestClient.input('email', sql.VarChar, email);
        await requestClient.query("DELETE FROM dbo.client WHERE id_person = @id_person;")
        break;
      case 2:
        const requestRestaurant = pool.request();
        requestRestaurant.input('id_restaurant', sql.Int, result.recordset[0].id_person);
        requestRestaurant.input('email', sql.VarChar, email);
        await requestRestaurant.query("DELETE FROM dbo.restaurateur WHERE id_restaurant = @id_restaurant")
        break;
      case 3:
        const requestDeliverer = pool.request();
        requestDeliverer.input('id_person', sql.Int, result.recordset[0].id_person);
        requestDeliverer.input('email', sql.VarChar, email);
        await requestDeliverer.query("DELETE FROM dbo.deliverer WHERE id_person = @id_person")
        break;
      default:
        break;
    }

    await request.query("DELETE FROM dbo.person WHERE email = @email;")

    res.status(200).send(`Le compte ${role} lié à l'address : ${email} a bien été supprimé`);
    sql.close()
  } catch (err) {
    res.status(500).json({ message: err.message });
  }
});

//Création d'un utilisateur et attribution de son role
/**
* @swagger
* /api/V1/register:
*   post:
*     tags:
*       - Admin
*     description: Inscrit un utilisateur
*     produces:
*       - application/json
*     parameters:
*       - name: body
*         in: body
*         schema:
*           type: object
*           properties:
*             name:
*               type: string
*             phone_number:
*               type: string
*             email:
*               type: string
*             password:
*               type: string
*             role:
*               type: number
*         required:
*           - name
*           - phone_number
*           - email
*           - password
*           - role
*     responses:
*       200:
*         description: Utilisateur inscrit avec succès
*       400:
*         description: Adresse mail déjà utilisée
*       500:
*         description: Erreur lors de l'inscription de l'utilisateur
*/
app.post(url + "/register/", checkTokenA, async (req, res) => {
  try {
    let data = req.body;
    let pool = await sql.connect(config);
    let userAlreadyExist = false;

    const requestSelect = pool.request();
    requestSelect.input("email", sql.VarChar, data.email);
    const result = await requestSelect.query(
      "SELECT COUNT (*) AS compte FROM dbo.person WHERE email = @email"
    );
    if (parseInt(JSON.stringify(result.recordset[0].compte)) != 0) {
      userAlreadyExist = true;
    }

    if (userAlreadyExist) {
      res
        .status(400)
        .send(`L'addresse mail : "${data.email}" est déjà utilisée, veuillez vous connecter`)
        .end();
    } else {
      let encryptedPassword = await bcrypt.hash(data.password, 10);

      const request = pool.request();
      request.input("name", sql.VarChar, data.name);
      request.input("phone_number", sql.VarChar, data.phone_number);
      request.input("email", sql.VarChar, data.email);
      request.input("password", sql.VarChar, encryptedPassword);
      request.input("role", sql.Int, data.role)
      await request.query(
        "INSERT INTO dbo.person(name, phone_number, email, password, role) VALUES (@name, @phone_number, @email, @password, @role)"
      );


      const requestSelect = pool.request();
      requestSelect.input("email", sql.VarChar, data.email);
      const result = await requestSelect.query("SELECT id_person FROM dbo.person WHERE email = @email");

      console.log(result.recordset[0].id_person)


      const requestClient = pool.request();
      requestClient.input("id_person", sql.Int, result.recordset[0].id_person);
      await requestClient.query(
        "INSERT INTO dbo.client (id_person, code_parrainage) VALUES (@id_person, '')"
      );
      const expirationTime = 5 * 24 * 60 * 60; // 5 jours en secondes
      const token = jwt.sign({ email: data.email }, process.env.TOKEN_KEY, { expiresIn: expirationTime });
      res.header('authorization', token)
      res.cookie('token', token, { httpOnly: true, maxAge: expirationTime * 1000 }).send("Inscris !").end();
    }
  } catch (error) {
    res.status(500).send(error).end();
  }
});

/**
 * @swagger
 * /api/V1/users:
 *   get:
 *     tags:
 *       - Admin
 *     description: Return all users
 *     produces:
 *       - application/json
 *     responses:
 *       200:
 *         description: An array of users
 *         schema:
 *           type: array
 *           items:
 *             $ref: '#/definitions/User'
 *       401:
 *         description: Invalid token
 *       403:
 *         description: A token is required for authentication
 *       500:
 *         description: Internal server error
 */
/**
 * @swagger
 * definitions:
 *   User:
 *     type: object
 *     properties:
 *       surname:
 *         type: string
 *       name:
 *         type: string
 *       birth:
 *         type: string
 *         format: date
 *       phone_number:
 *         type: string
 *       email:
 *         type: string
 *         format: email
 */
app.get(url + '/users', checkTokenA, async (req, res) => {
  let pool = await sql.connect(config);
  const request = pool.request();
  request.query("SELECT surname, name, birth, phone_number, email FROM dbo.person", (err, result) => {
    if (err) {
      return res.status(500).send(err);
    }
    return res.status(200).json(result.recordset);
  });
});


//#endregion

//#region service technique

//inscription développeur tier
/**
 * @swagger
 * /api/V1/register/dev:
 *   post:
 *     tags:
 *       - Développeur
 *     description: Inscrire un développeur
 *     produces:
 *       - application/json
 *     parameters:
 *       - name: body
 *         in: body
 *         required: true
 *         schema:
 *           type: object
 *           required:
 *             - name
 *             - phone_number
 *             - email
 *             - password
 *           properties:
 *             name:
 *               type: string
 *             phone_number:
 *               type: string
 *             email:
 *               type: string
 *             password:
 *               type: string
 *     responses:
 *       200:
 *         description: Successful registration
 *       400:
 *         description: Email already in use
 *       500:
 *         description: Internal server error
 */
app.post(url + "/register/dev", async (req, res) => {
  let data = req.body;
  try {

    let pool = await sql.connect(config);
    let userAlreadyExist = false;

    const requestSelect = pool.request();
    requestSelect.input("email", sql.VarChar, data.email);
    const result = await requestSelect.query(
      "SELECT COUNT (*) AS compte FROM dbo.person WHERE email = @email"
    );
    if (parseInt(JSON.stringify(result.recordset[0].compte)) != 0) {
      userAlreadyExist = true;
    }

    if (userAlreadyExist) {
      const log = new Logs({
        logType: 'inscription dev',
        timestamp: new Date(),
        email: data.email,
        success: false,
        error_message: 'Adresse mail déjà utilisée'
      });
      await log.save();
      res
        .status(400)
        .send(`L'addresse mail : "${data.email}" est déjà utilisée, veuillez vous connecter`)
        .end();
    } else {
      let encryptedPassword = await bcrypt.hash(data.password, 10);

      const request = pool.request();
      request.input("name", sql.VarChar, data.name);
      request.input("phone_number", sql.VarChar, data.phone_number);
      request.input("email", sql.VarChar, data.email);
      request.input("password", sql.VarChar, encryptedPassword);
      await request.query(
        "INSERT INTO dbo.person(name, phone_number, email, password, role) VALUES (@name, @phone_number, @email, @password, 4)"
      );


      const requestSelect = pool.request();
      requestSelect.input("email", sql.VarChar, data.email);
      const result = await requestSelect.query("SELECT id_person FROM dbo.person WHERE email = @email");

      console.log(result.recordset[0].id_person)


      const requestClient = pool.request();
      requestClient.input("id_person", sql.Int, result.recordset[0].id_person);
      await requestClient.query(
        "INSERT INTO dbo.developer (id_person) VALUES (@id_person)"
      );
      const expirationTime = 5 * 24 * 60 * 60; // 5 jours en secondes
      const token = jwt.sign({ email: data.email }, process.env.TOKEN_KEY, { expiresIn: expirationTime });

      const log = new Logs({
        logType: 'inscription dev',
        timestamp: new Date(),
        email: data.email,
        success: true,
      });
      await log.save();

      res.cookie('token', token, { httpOnly: true, maxAge: expirationTime * 1000 }).send("Inscris !").end();
    }
  } catch (error) {
    const log = new Logs({
      logType: 'inscription dev',
      timestamp: new Date(),
      email: data.email,
      success: false,
      error_message: error.message
    });
    await log.save();
    res.status(500).send(error).end();
  }
});

//login dev
/**
 * @swagger
 * /api/V1/login/dev:
 *   post:
 *     tags:
 *       - Développeur
 *     description: Connecter un développeur
 *     produces:
 *       - application/json
 *     parameters:
 *       - name: body
 *         in: body
 *         required: true
 *         schema:
 *           type: object
 *           required:
 *             - email
 *             - password
 *           properties:
 *             email:
 *               type: string
 *             password:
 *               type: string
 *     responses:
 *       200:
 *         description: Successful login
 *       400:
 *         description: Invalid email or password
 *       500:
 *         description: Internal server error
 */
app.post(url + "/login/dev", async (req, res) => {
  let data = req.body;
  let pool = await sql.connect(config);

  const request = pool.request();
  request.input('email', sql.VarChar, data.email);
  request.query("SELECT email, password FROM dbo.person WHERE email = @email", async (err, result) => {
    if (err) {
      return res.status(500).send(err);
    }
    if (result.recordset.length == 0) {
      const log = new Logs({
        logType: 'connexion dev',
        timestamp: new Date(),
        email: data.email,
        success: false,
        error_message: 'Adresse mail non existante'
      });
      await log.save();
      return res.status(400).send("Adresse mail non existante");
    }
    const validPassword = bcrypt.compareSync(data.password, result.recordset[0].password);
    if (!validPassword) {
      const log = new Logs({
        logType: 'connexion dev',
        timestamp: new Date(),
        email: data.email,
        success: false,
        error_message: 'Mot de passe invalide'
      });
      await log.save();
      return res.status(400).send('Mot de passe invalide');
    }
    const expirationTime = 5 * 24 * 60 * 60; // 5 jours en secondes
    const token = jwt.sign({ email: data.email }, process.env.TOKEN_KEY, { expiresIn: expirationTime });

    const log = new Logs({
      logType: 'connexion dev',
      timestamp: new Date(),
      email: data.email,
      success: true,
    });
    await log.save();
    res.cookie('token', token, { httpOnly: true, maxAge: expirationTime * 1000 }).send("Connecté !").end();
  });
});

/**
 * @swagger
 * /api/V1/dev:
 *   delete:
 *     tags:
 *       - Développeur
 *     description: Supprimer un développeur
 *     produces:
 *       - application/json
 *     parameters:
 *       - name: token
 *         in: header
 *         required: true
 *         type: string
 *     responses:
 *       200:
 *         description: Successful deletion
 *       401:
 *         description: Unauthorized
 *       500:
 *         description: Internal server error
 */
app.delete(url + "/dev", async (req, res) => {
  try {
    let pool = await sql.connect(config);
    const request = pool.request();
    const requestClient = pool.request();
    let decodedToken = getInfoToken(req, res);
    let email = decodedToken.email
    const requestSelect = pool.request();
    requestSelect.input("email", sql.VarChar, email);
    const result = await requestSelect.query("SELECT id_person FROM dbo.person WHERE email = @email");
    request.input('email', sql.VarChar, email);
    console.log(result.recordset[0].id_person)
    requestClient.input('id_person', sql.Int, result.recordset[0].id_person);
    await requestClient.query("DELETE FROM dbo.developer WHERE id_person = @id_person;")
    await request.query("DELETE FROM dbo.person WHERE email = @email;")
    res.status(200).send(`Le compte lié à l'address : ${email} a bien été supprimé`);
    sql.close()
  } catch (err) {
    res.status(500).json({ message: err.message });
  }
});

//permets d'éditer les logs
/**
 * @swagger
 * /api/V1/logs/{id}:
 *   put:
 *     tags:
 *       - Service technique
 *     description: 
 *       - Update a log by ID
 *     parameters:
 *       - in: path
 *         name: id
 *         required: true
 *         schema:
 *           type: string
 *       - in: body
 *         name: log
 *         required: true
 *         schema:
 *           $ref: '#/definitions/Log'
 *     responses:
 *       200:
 *         description: Updated log object
 *       500:
 *         description: Internal server error
 * 
 * definitions:
 *   Log:
 *     type: object
 *     required:
 *       - logType
 *       - timestamp
 *       - email
 *       - success
 *       - error_message
 *     properties:
 *       logType:
 *         type: string
 *       timestamp:
 *         type: string
 *         format: date-time
 *       email:
 *         type: string
 *       success:
 *         type: boolean
 *       error_message:
 *         type: string
 */
app.put(url + "/logs/:id", async (req, res) => {
  try {
    const id = req.params.id;
    const data = req.body;

    // Find and update the log object
    const log = await Logs.findByIdAndUpdate(id, {
      logType: data.logType,
      timestamp: data.timestamp,
      email: data.email,
      success: data.success,
      error_message: data.error_message
    }, { new: true });

    // Send the updated log object as response
    res.status(200).json(log);
  } catch (err) {
    // Handle errors
    res.status(500).json({ message: err.message });
  }
});

//#endregion


//#endregion

//#region fonction

//Vérifie qu'un token existe et qu'y a pas d'erreur dans le token
function checkToken(req, res) {
  const token = req.cookies['token']

  if (!token) {
    res.status(403).send("A token is required for authentication").end();
  } else {
    var payload
    try {
      payload = jwt.verify(token, process.env.TOKEN_KEY)
    } catch (e) {
      if (e instanceof jwt.JsonWebTokenError) {
        return res.status(401).end()
      }
      return res.status(400).end()
    }
  }
  exit
}

//récupère et décode le token
function getInfoToken(req, res) {
  const token = req.cookies['token'];
  let decodedToken = jwt_decode(token);
  return decodedToken;
}

//Vérifie l'ID du token et l'ID demandé dans l'URL correspond
function checkIDToken(req, res) {
  let decodedToken = JSON.stringify(getInfoToken(req, res).user.id);
}

async function checkIfEmailExists(email) {
  let pool = await sql.connect(config);
  const request = pool.request();
  request.input('email', sql.VarChar, email);
  const result = await request.query("SELECT COUNT(*) as count FROM dbo.person WHERE email = @email");
  return result.recordset[0].count > 0;
}

function checkTokenA(req, res, next) {
  const expirationTime = 5 * 24 * 60 * 60; // 5 jours en secondes
  const tokenU = jwt.sign({}, process.env.TOKEN_KEY, { expiresIn: expirationTime });
  res.header('authorization', tokenU)
  const bearerHeader = req.headers['authorization'];
  if (!bearerHeader) {
    console.log("JWT n'existe pas ");
    return res.status(403).json({ message: "A token is required for authentication" });
  }
  const token = bearerHeader.split(' ')[1];
  try {
    const decoded = jwt.verify(token, process.env.TOKEN_KEY);
    console.log('JWT est valide:', decoded);
    next();
  } catch (err) {
    console.log('JWT est invalide:', err);
    return res.status(401).json({ message: "Invalid token" });
  }
}
//#endregion

module.exports = app;