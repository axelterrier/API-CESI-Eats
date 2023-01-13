//#region require

require("dotenv").config();
require("./config/mongoose").connect();

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
const Commande = require("./model/commandeMongoose.ts")
const swaggerJsDoc = require('swagger-jsdoc')
const swaggerUi = require('swagger-ui-express')
const swaggerOptions = {
  swaggerDefinition: {
    info: {
      title: "API Client",
      contact:{
        name:"UwU Eats"
      },
      servers:["https://localhost:8888"]
    }
  },
  // on donne l'endroit ou sont les routes
  apis:["app.ts"]
};

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
 * /register/client:
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
app.post("/register/client", async (req, res) => {
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
      res.cookie('token', token, { httpOnly: true, maxAge: expirationTime * 1000 }).send("Inscris !").end();
    }
  } catch (error) {
    res.status(500).send(error).end();
  }
});

// Login
/**
 * @swagger
 * /login:
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
app.post("/login", async (req, res) => {
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

//Changement de mot de passe de l'addresse mail contenue dans le token utilisateur
/**
* @swagger
* /updatePassword:
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
app.put("/updatePassword", async (req, res) => {
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
      return res.status(500).send(err);
    }
    res.status(200).send(`Informations mises à jour avec succès, nouveau mot de passe : ${password}`);
  });
});

//Lecture des informations de l'utilisateur
/**
 * @swagger
 * /user:
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
app.get("/user", async (req, res) => {
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
 * /user:
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
app.delete("/client", async (req, res) => {
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
    requestClient.input('id_person',sql.Int, result.recordset[0].id_person);
    await requestClient.query("DELETE FROM dbo.client WHERE id_person = @id_person;")
    await request.query("DELETE FROM dbo.person WHERE email = @email;")
    res.status(200).send(`Le compte lié à l'address : ${email} a bien été supprimé`);
    sql.close()
  } catch (err) {
    res.status(500).json({ message: err.message });
  }
});

app.delete("/client/:email", async (req, res) => {
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

    requestClient.input('id_person',sql.Int, result.recordset[0].id_person);

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
 * /user:
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
app.put("/user", async (req, res) => {
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
 * /menu:
 *   post:
 *     tags:
 *       - restaurant
 *     description: Creates a new menu
 *     produces:
 *       - application/json
 *     requestBody:
 *       required: true
 *       content:
 *         application/json:
 *           schema:
 *             $ref: '#/definitions/Menu'
 *     responses:
 *       201:
 *         description: Menu created successfully
 *         schema:
 *           type: object
 *           properties:
 *             message:
 *               type: string
 *               example: Menu id : 1 created
 *       400:
 *         description: Invalid request
 *         schema:
 *           type: object
 *           properties:
 *             message:
 *               type: string
 *               example: Invalid request
 */
/**
 * @swagger
 * definitions:
 *   Menu:
 *     type: object
 *     properties:
 *       id:
 *         type: number
 *       menu:
 *         type: object
 *         properties:
 *           items:
 *             type: array
 *             items:
 *               type: object
 *               properties:
 *                 mixed:
 *                   type: object
 *           restaurant_categories:
 *             type: array
 *             items:
 *               type: string
 */
app.post("/menu", async (req, res) => {
  const newMenu = new Menu(req.body);
  try {
    let menuNumber = await Menu.estimatedDocumentCount();
    newMenu.id = menuNumber++
    const menu = await newMenu.save();

    res.status(201).json({ message: `Menu id : ${menu.id} crée` });
  } catch (err) {
    res.status(400).json({ message: err.message });
  }
});

//Récupère tous les restaurants et leur menus
/**
 * @swagger
 * /restaurants:
 *   get:
 *     tags:
 *       - restaurants
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
app.get('/restaurants', function (req, res) {
  Menu.find((err, restaurants) => {
    if (err) return handleError(err);
    res.send(restaurants);
  });
});

//Récupère un restaurant et son menu
/**
 * @swagger
 * /restaurants:
 *   get:
 *     description: Retrieves a list of all restaurants
 *     produces:
 *       - application/json
 *     responses:
 *       200:
 *         description: A list of restaurants
 *         schema:
 *           type: array
 *           items:
 *             $ref: '#/definitions/Menu'
 *       500:
 *         description: Internal server error
 *         schema:
 *           type: object
 *           properties:
 *             error:
 *               type: string
 *               example: handleError
 */
app.get('/restaurants/:id', function (req, res) {
  const menuId = req.params.id
  Menu.findOne({ id: menuId }, (err, restaurant) => {
    if (err) return handleError(err);
    res.send(restaurant);
  });
});

//Mets à jour un menu
/**
 * @swagger
 * /menu/{id}:
 *   put:
 *     description: Updates a menu by id
 *     produces:
 *       - application/json
 *     parameters:
 *       - name: id
 *         in: path
 *         required: true
 *         type: number
 *         description: ID of menu to update
 *     requestBody:
 *       required: true
 *       content:
 *         application/json:
 *           schema:
 *             $ref: '#/definitions/Menu'
 *     responses:
 *       200:
 *         description: Menu updated successfully
 *         schema:
 *           type: object
 *           properties:
 *             message:
 *               type: string
 *               example: Menu id : 1 updated
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
 */
app.put("/menu/:id", async (req, res) => {
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
 * /menu/{id}:
 *   delete:
 *     tags:
 *       - restaurants
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
app.delete('/menu/:id', async function (req, res) {
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
 * /commande:
 *   post:
 *     tags:
 *       - restaurants
 *     description: Creates a new commande
 *     produces:
 *       - application/json
 *     requestBody:
 *       required: true
 *       content:
 *         application/json:
 *           schema:
 *             $ref: '#/definitions/Commande'
 *     responses:
 *       201:
 *         description: Commande created successfully
 *         schema:
 *           type: object
 *           properties:
 *             message:
 *               type: string
 *               example: Commande created successfully
 *       400:
 *         description: Invalid request
 *         schema:
 *           type: object
 *           properties:
 *             message:
 *               type: string
 *               example: Invalid request
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
app.post("/commande", async (req, res) => {
  try {

    // Crée un nouvel objet commande à partir des données de la requête
    let newCommande = new Commande(req.body);
    let documentNumber = await Commande.estimatedDocumentCount();
    // Sauvegarde la commande dans la base de données
    newCommande.idCommande = documentNumber
    const commande = await newCommande.save();
    // Répond avec un statut 201 et un message de succès
    res.status(201).json({ message: 'Commande créée avec succès' });
  } catch (err) {
    // Répond avec un statut 400 et un message d'erreur
    res.status(400).json({ message: err.message });
  }
});

//Récupère le nombre de commande
/**
 * @swagger
 * /commande/count:
 *   get:
 *     tags:
 *       - restaurants
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
app.get("/commande/count", async (req, res) => {
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
 * /commande/count/{client}:
 *   get:
 *     tags:
 *       - restaurants
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
app.get("/commande/count/:client", async (req, res) => {
  try {
    const count = await Commande.countDocuments({ client: req.params.client });
    res.json({ count });
  } catch (err) {
    res.status(500).json({ message: err.message });
  }
});

/**
 * @swagger
 * /commande/{idCommande}/status:
 *   get:
 *     tags:
 *       - restaurants
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
app.get("/commande/:idCommande/status", async (req, res) => {
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
 * /commande/{id}:
 *   put:
 *     tags:
 *       - restaurants
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
app.put("/commande/:id", async (req, res) => {
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


//Récupère le code de parrainage de l'utilisateur connecté (si le code n'existe pas il est généré)
//Il faut que la "person" soit renseigné dans la table "client"
/**
 * @swagger
 * /sponsorship:
 *   get:
 *     tags:
 *       - Utilisateurs
 *     description: Returns sponsorship code
 *     produces:
 *       - application/json
 *     security:
 *      - bearerAuth: []
 *     responses:
 *       200:
 *         description: Sponsorship code retrieved successfully
 *         schema:
 *           type: object
 *           properties:
 *             sponsorshipId:
 *               type: string
 *               example: "5678"
 *       404:
 *         description: person not found
 *         schema:
 *           type: object
 *           properties:
 *             message:
 *               type: string
 *               example: personne non trouvée
 *       500:
 *         description: Internal server error
 *         schema:
 *           type: object
 *           properties:
 *             message:
 *               type: string
 *               example: "Internal server error"
 */
app.get("/sponsorship", async (req, res) => {
  let decodedToken = getInfoToken(req, res)
  let email = decodedToken.email

  try {
    let pool = await sql.connect(config);
    const requestSelect = pool.request();
    const requestSelectClient = pool.request();

    requestSelect.input("email", sql.VarChar, email);
    const result = await requestSelect.query("SELECT id_person FROM dbo.person WHERE email = @email");

    requestSelectClient.input("id_person", sql.Int, result.recordset[0].id_person);
    const client = await requestSelectClient.query("SELECT code_parrainage FROM dbo.client WHERE id_person = @id_person");

    if(!result.recordset[0]) {
      res.status(404).json({ message: "personne non trouvée" });
      return;
    }

    console.log(client.recordset[0].code_parrainage)

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
 * /restaurant/{id}/stats/countAllTime:
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
app.get("/restaurant/:id/stats/countAllTime", async (req, res) => {
  try {
    const id = req.params.id
    const countAllTime = await Commande.countDocuments({"restaurant":id});
    res.json({ countAllTime});
  } catch (err) {
    res.status(500).json({ message: err.message });
  }
});

//Get specified restaurant last 24h orders
/**
 * @swagger
 * /restaurant/{id}/stats/count24h:
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
app.get("/restaurant/:id/stats/count24h", async (req, res) => {
  try {
    const id = req.params.id
    const twentyFourHoursAgo = new Date(Date.now() - (24 * 60 * 60 * 1000));
    const countLast24h = await Commande.countDocuments({
      "restaurant": id,
      "date": {$gt: twentyFourHoursAgo}
    });
    
    res.json({ countLast24h });
  } catch (err) {
    res.status(500).json({ message: err.message });
  }
});

//Get specified restaurant last 72h orders
/**
 * @swagger
 * /restaurant/{id}/stats/count72h:
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
app.get("/restaurant/:id/stats/count72h", async (req, res) => {
  try {
    const id = req.params.id
    const seventyTwoHoursAgo = new Date(Date.now() - (72 * 60 * 60 * 1000));
    const countLast72h = await Commande.countDocuments({
      "restaurant": id,
      "date": {$gt: seventyTwoHoursAgo}
    });
    res.json({ countLast72h });
  } catch (err) {
    res.status(500).json({ message: err.message });
  }
});

//Get specified restaurant last 7 days orders
/**
 * @swagger
 * /restaurant/{id}/stats/count7days:
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
app.get("/restaurant/:id/stats/count7days", async (req, res) => {
  try {
    const id = req.params.id
    const sevenDaysAgo = new Date(Date.now() - (7 * 24 * 60 * 60 * 1000));
    const countLast7days = await Commande.countDocuments({
      "restaurant": id,
      "date": {$gt: sevenDaysAgo}
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
 * /client/{id}/stats/count24h:
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
app.get("/client/:id/stats/count24h", async (req, res) => {
  try {
    const id = req.params.id
    const twentyFourHoursAgo = new Date(Date.now() - (24 * 60 * 60 * 1000));
    const countLast24h = await Commande.countDocuments({
      "client": id,
      "date": {$gt: twentyFourHoursAgo}
    });
    
    res.json({ countLast24h });
  } catch (err) {
    res.status(500).json({ message: err.message });
  }
});

//Get specified client last 72h orders
/**
 * @swagger
 * /client/{id}/stats/count72h:
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
app.get("/client/:id/stats/count72h", async (req, res) => {
  try {
    const id = req.params.id
    const seventyTwoHoursAgo = new Date(Date.now() - (72 * 60 * 60 * 1000));
    const countLast72h = await Commande.countDocuments({
      "client": id,
      "date": {$gt: seventyTwoHoursAgo}
    });
    res.json({ countLast72h });
  } catch (err) {
    res.status(500).json({ message: err.message });
  }
});

//Get specified client last 7 days orders
/**
 * @swagger
 * /client/{id}/stats/count7days:
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
app.get("/client/:id/stats/count7days", async (req, res) => {
  try {
    const id = req.params.id
    const sevenDaysAgo = new Date(Date.now() - (7 * 24 * 60 * 60 * 1000));
    const countLast7days = await Commande.countDocuments({
      "client": id,
      "date": {$gt: sevenDaysAgo}
    });
    res.json({ countLast7days });
  } catch (err) {
    res.status(500).json({ message: err.message });
  }
});


//Get graph UwU A TESTER
app.get("/commandes/stats/graph", async (req, res) => {
  try {
    // Obtenir les commandes dans les 7 derniers jours
    const sevenDaysAgo = new Date(Date.now() - (7 * 24 * 60 * 60 * 1000));
    const commandes = await Commande.find({
      "date": { $gt: sevenDaysAgo }
    });
    
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
    
    res.json(commandesByDay);
  } catch (err) {
    res.status(500).json({ message: err.message });
  }
});

//#endregion

//#region api restaurateur

//S'inscrire en tant que restaurateur
/**
 * @swagger
 * /register/restaurateur:
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
app.post("/register/restaurateur", async (req, res) => {
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
 * /login/restaurateur:
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
app.post("/login/restaurateur", async (req, res) => {
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

/* CONTINUE LE CRUD AXEL*/

//#endregion

//#endregion

//#region fonction

//Vérifie qu'un token existe et qu'y a pas d'erreur dans le token
/**
 * @swagger
 * tags:
 *   - fonction
 * 
 * /checkToken:
 *   get:
 *     description: Check if token exists and is valid
 *     produces:
 *       - application/json
 *     responses:
 *       200:
 *         description: Token is valid
 *       401:
 *         description: Unauthorized - Invalid token
 *       403:
 *         description: A token is required for authentication
 *       400:
 *         description: Bad request
 */
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
/**
 * @swagger
 * tags:
 *   - fonction
 * 
 * /getInfoToken:
 *   get:
 *     description: Decode token and get user's informations
 *     produces:
 *       - application/json
 *     responses:
 *       200:
 *         description: Token decoded successfully
 *       400:
 *         description: Invalid token
 *
 */
function getInfoToken(req, res) {
  const token = req.cookies['token'];
  let decodedToken = jwt_decode(token);
  return decodedToken;
}

//Vérifie l'ID du token et l'ID demandé dans l'URL correspond
/**
 * @swagger
 * tags:
 *   - fonction
 * 
 * /checkIDToken:
 *   get:
 *     description: Check user's ID in the token
 *     produces:
 *       - application/json
 *     responses:
 *       200:
 *         description: ID found in the token
 *       400:
 *         description: Invalid token or ID not found
 *
 */
function checkIDToken(req, res) {
  let decodedToken = JSON.stringify(getInfoToken(req, res).user.id);
}

/**
 * @swagger
 * tags:
 *   - fonction
 * 
 * /checkIfEmailExists:
 *   get:
 *     description: Check if email exists in database
 *     produces:
 *       - application/json
 *     parameters:
 *       - name: email
 *         in: query
 *         type: string
 *         required: true
 *         description: email to be checked
 *     responses:
 *       200:
 *         description: Email exists
 *       400:
 *         description: Email not found
 *
 */
async function checkIfEmailExists(email) {
  let pool = await sql.connect(config);
  const request = pool.request();
  request.input('email', sql.VarChar, email);
  const result = await request.query("SELECT COUNT(*) as count FROM dbo.person WHERE email = @email");
  return result.recordset[0].count > 0;
}
//#endregion

module.exports = app;