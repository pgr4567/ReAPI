import { Db, MongoClient, Cursor, Collection } from "mongodb";
import express from "express";
import bcrypt from 'bcrypt';
import moment from 'moment';
import cors from 'cors';

export type CollectionFieldValue = {
    "type": CollectionFieldValueType,
    "required": boolean,
    "unique": boolean,
    "readonly": boolean,
    "secret": boolean,
    "preInsert"?: (value: any, user?: CollectionDocument) => any,
    "preRead"?: (value: any) => any,
    "preDelete"?: (value: any, user?: CollectionDocument) => any,
    "preEdit"?: (value: any, user?: CollectionDocument) => any
};
export type CollectionFieldValueType = "string" | "number";
export type CollectionDescriptionAccessKey = "read" | "delete" | "edit" | "info" | "insert";
export type CollectionDescription = {
    "name": string,
    "fields": { [key: string]: CollectionFieldValue },
    "access": { [key in CollectionDescriptionAccessKey]: string }
    "custom"?: { [key: string]: any }
};
export type CollectionDocument = { [key: string]: any };

export class ReMongo {
    #client: MongoClient;
    #databaseName: string;
    #database: Db | null = null;
    #collections: { [name:string]: CollectionDescription | null } = {};

    #express: express.Application | null = null;
    readonly #saltRounds: number = 100;
    readonly #tokenLength: number = 128;
    readonly #idLength: number = 64;
    readonly #token_disallow_minutes: number = 60 * 8;
    //* Return messages
    #unauthorized = {
        "success": false,
        "message": "Unauthorized request."
    };
    #resNotFound = {
        "success": false,
        "message": "Requested ressource not found."
    };
    #malformedRequest = {
        "success": false,
        "message": "Request was malformed."
    };
    #requestFulfilled = {
        "success": true,
        "message": "Request was fulfilled successfully."
    };
    #internalServerError = {
        "success": false,
        "message": "An internal server error occured."
    };
    /**
     * Use this to create a new `ReMongo` instance.
     * @param connectionString The connection string with username and password filled out.
     * @param database The name of the database to connect to.
     * @param port The port to create the endpoints on.
     * @param hostname The host to create the endpoints on.
     */
    public constructor (connectionString: string, database: string, port: number, hostname: string) {
        this.#databaseName = database;
        this.#client = new MongoClient(connectionString, { useNewUrlParser: true, useUnifiedTopology: true });
        this.#express = express();
        this.#express.use(express.json());
        this.#express.use(cors());
        this.#express.listen(port, hostname, () => {
            console.log(`ReAPI listening at ${hostname}:${port}.`);
        });          
    }
    /** 
     * Use this to connect to MongoDB and the database.
     */
    public async connect (): Promise<void> {
        try {
            await this.#client.connect();
            this.#database = this.#client.db(this.#databaseName);
        } catch { 
            throw new Error("Could not connect to MongoDB. Please check your username and password.");
        }
    }
    /**
     * Use this to close the connection to MongoDB.
     * @returns Promise that resolves once the client closed the connection.
     */
    public close (): Promise<void> {
        return this.#client.close();
    }
    /**
     * Use to add/remove a collection from the API. The id field is added automatically.
     * @param collectionName The name of the collection to set.
     * @param collectionDescription The data that should be associated with the collection. If this is null, the collection will be ignored.
     */
    public setCollection<T extends string> (collectionName: T extends "Users" ? never : T, collectionDescription: CollectionDescription | null): void {
        if (collectionDescription !== null) {
            if ("id" in collectionDescription["fields"]) {
                throw new Error("The id field is added to every CollectionDescription automatically.");
            }
            collectionDescription["fields"]["id"] = {
                "type": "string",
                "required": false,
                "unique": true,
                "readonly": true,
                "secret": false
            };
        }
        this.#collections[collectionName] = collectionDescription;
    }
    /**
     * Use to add a user database to the API. Required fields such as username, id, password and token are already inputted.
     * @param customUserDataCollection Use this CollectionDescription to add custom data that should be associated with an user. If this is null, the collection will be ignored.
     */
    public setUserCollection (customUserDataCollection: CollectionDescription | null): void {
        if (customUserDataCollection === null) {
            this.#collections["Users"] = customUserDataCollection;
        }
        else if ("id" in customUserDataCollection["fields"]) {
            throw new Error("The id field is added to every CollectionDescription automatically.");
        }
        else {
            customUserDataCollection["name"] = "Users";
            customUserDataCollection["fields"]["username"] = {
                "type": "string",
                "required": true,
                "unique": true,
                "readonly": false,
                "secret": false
            };
            customUserDataCollection["fields"]["id"] = {
                "type": "string",
                "required": false,
                "unique": true,
                "readonly": true,
                "secret": false
            };
            customUserDataCollection["fields"]["password_hash"] = {
                "type": "string",
                "required": true,
                "unique": false,
                "readonly": true,
                "secret": true,
                "preInsert": async (password: string) => {
                    return await bcrypt.hash(password, this.#saltRounds);
                },
                "preEdit": async (password: string) => {
                    return await bcrypt.hash(password, this.#saltRounds);
                }
            };
            customUserDataCollection["fields"]["token"] = {
                "type": "string",
                "required": false,
                "unique": false,
                "readonly": true,
                "secret": true
            };
            customUserDataCollection["fields"]["token_disallow"] = {
                "type": "string",
                "required": false,
                "unique": false,
                "readonly": true,
                "secret": true
            };
            customUserDataCollection["access"] = {
                "read": "$id=&id",
                "delete": "$id=&id",
                "edit": "$id=&id",
                "info": "@everyone",
                "insert": "@everyone"
            };

            this.#collections["Users"] = customUserDataCollection;
        }
    }
    /**
     * Creates all needed endpoints for a given collection.
     * @param collectionName The name of the collection to create methods for.
     */
    #createCollection (collectionName: string): void {
        if (this.#express === null) {
            throw new Error("Express was null, should have been declared in constructor!");
        }
        const collectionDescription = this.#collections[collectionName] as CollectionDescription;
        const collection = this.#database?.collection(collectionName) as Collection<any>;

        this.#express.post(`/${this.#databaseName}/${collectionName}/query`, async (req, res) => {
            const temp = await this.#handleRequest(req, res, collection, collectionDescription, "read");
            if (typeof temp === "boolean") {
                res.status(500).send(JSON.stringify(this.#internalServerError));
                return;
            } else {
                const access = temp as CollectionDocument[];
                if (access.length > 0) {
                    for (let i = 0; i < access.length; i++) {
                        for (let x in collectionDescription["fields"]) {
                            try {
                                access[i][x] = await collectionDescription["fields"][x]["preRead"]!(access[i][x]);
                            } catch { }
                            if (collectionDescription["fields"][x]["secret"]) {
                                access[i][x] = null;
                            }
                        }
                    }
                    const response = {
                        "success": true,
                        "data": access
                    };
                    res.status(200).send(JSON.stringify(response));
                } else {
                    res.status(403).send(JSON.stringify(this.#unauthorized));
                }
            }
        });
        this.#express.post(`/${this.#databaseName}/${collectionName}/edit`, async (req, res) => {
            let user: (Cursor<any> | undefined) | CollectionDocument = this.#database?.collection("Users").find({$and:[{username: req.body.username}, {token: req.body.user_token}]});
            if (user !== undefined && user !== null && (await user.count()) !== 0) {
                user = (await user.next()) as CollectionDocument;
            }
            if (req.body.document_data === undefined) {
                res.status(400).send(JSON.stringify(this.#malformedRequest));
                return;
            }
            if (!(await this.#queryFulfillsUniqueFields(req.body.document_data, collectionDescription, collection))) {
                res.status(400).send(JSON.stringify(this.#malformedRequest));
                return;
            }
            if (!this.#queryHasCorrectTypes(req.body.document_data, collectionDescription)) {
                res.status(400).send(JSON.stringify(this.#malformedRequest));
                return;
            }
            if (this.#queryContainsReadonlyFields(req.body.document_data, collectionDescription)) {
                res.status(400).send(JSON.stringify(this.#malformedRequest));
                return;
            }
            let insertData = await this.#prepareInsertData(req.body.document_data, collection, collectionDescription);
            for (let field in insertData) {
                try {
                    insertData[field] = await collectionDescription["fields"][field]["preEdit"]!(insertData[field], user);
                } catch { }
            }
            const temp = await this.#handleRequest(req, res, collection, collectionDescription, "edit"); 
            if (typeof temp === "boolean") {
                res.status(500).send(JSON.stringify(this.#internalServerError));
                return;
            } else {
                const access = temp as CollectionDocument[];
                if (access.length > 0) {
                    for (let x of access) {
                        collection.updateOne({$and: [{id: x.id}]}, {$set: insertData});
                    }
                    res.status(200).send(JSON.stringify(this.#requestFulfilled));
                } else {
                    res.status(403).send(JSON.stringify(this.#unauthorized));
                }
            }
        });
        this.#express.post(`/${this.#databaseName}/${collectionName}/delete`, async (req, res) => {
            let user: (Cursor<any> | undefined) | CollectionDocument = this.#database?.collection("Users").find({$and:[{username: req.body.username}, {token: req.body.user_token}]});
            if (user !== undefined && user !== null && (await user.count()) !== 0) {
                user = (await user.next()) as CollectionDocument;
            }
            const temp = await this.#handleRequest(req, res, collection, collectionDescription, "delete"); 
            if (typeof temp === "boolean") {
                res.status(500).send(JSON.stringify(this.#internalServerError));
                return;
            } else {
                const access = temp as CollectionDocument[];
                if (access.length > 0) {
                    access.forEach(async (document: CollectionDocument) => {
                        for (let i in collectionDescription["fields"]) {
                            try {
                                await collectionDescription["fields"][i]["preDelete"]!(document[i], user);
                            } catch { }
                        }
                        collection.deleteOne({"$and": [{id: document["id"]}]});
                    });
                    res.status(200).send(JSON.stringify(this.#requestFulfilled));
                } else {
                    res.status(403).send(JSON.stringify(this.#unauthorized));
                }
            }
        });
        this.#express.post(`/${this.#databaseName}/${collectionName}/insert`, async (req, res) => {
            let user: (Cursor<any> | undefined) | CollectionDocument = this.#database?.collection("Users").find({$and:[{username: req.body.username}, {token: req.body.user_token}]});
            if (user !== undefined && user !== null && (await user.count()) !== 0) {
                user = (await user.next()) as CollectionDocument;
            }
            const temp = await this.#handleRequest(req, res, collection, collectionDescription, "insert"); 
            if (typeof temp === "boolean") {
                if (temp) {
                    if (req.body.document_data === undefined) {
                        res.status(400).send(JSON.stringify(this.#malformedRequest));
                        return;
                    }
                    if (!this.#queryHasRequiredFields(req.body.document_data, collectionDescription)) {
                        res.status(400).send(JSON.stringify(this.#malformedRequest));
                        return; 
                    }
                    if (!this.#queryHasCorrectTypes(req.body.document_data, collectionDescription)) {
                        res.status(400).send(JSON.stringify(this.#malformedRequest));
                        return; 
                    }
                    let insertData: { [key: string]: any } = req.body.document_data;
                    for (let field in collectionDescription["fields"]) {
                        if (!(field in insertData)) {
                            insertData[field] = null;
                        }
                    }
                    if (!(await this.#queryFulfillsUniqueFields(insertData, collectionDescription, collection))) {
                        res.status(400).send(JSON.stringify(this.#malformedRequest));
                        return;
                    }
                    insertData = await this.#prepareInsertData(insertData, collection, collectionDescription);
                    for (let field in insertData) {
                        if (collectionDescription["fields"][field]["preInsert"] !== undefined) {
                            try {
                                insertData[field] = await collectionDescription["fields"][field]["preInsert"]!(insertData[field], user);
                            } catch { }
                        }
                    }
                    collection?.insertOne(insertData);
                    res.status(200).send(JSON.stringify(this.#requestFulfilled));
                } else {
                    res.status(403).send(JSON.stringify(this.#unauthorized));
                }
            } else {
                res.status(500).send(JSON.stringify(this.#internalServerError));
                return;
            }
        });
        this.#express.post(`/${this.#databaseName}/${collectionName}/info`, async (req, res) => {
            const temp = await this.#handleRequest(req, res, collection, collectionDescription, "info"); 
            if (typeof temp === "boolean") {
                if (temp) {
                    res.status(200).send(JSON.stringify({
                        "success": true,
                        "data": {
                            "name": collectionDescription["name"],
                            "description": collectionDescription
                        }
                    }));
                } else {
                    res.status(403).send(JSON.stringify(this.#unauthorized));
                }
            } else {
                res.status(500).send(JSON.stringify(this.#internalServerError));
                return;
            }
        });
    }
    /**
     * Prepares data to insert/edit a collection.
     * @param data The data to prepare
     * @param collectionDescription The CollectionDescription of the Collection to prepare for.
     * @param collection The collection to prepare for.
     * @returns The prepared data.
     */
    async #prepareInsertData(data: { [key: string]: any }, collection: Collection, collectionDescription: CollectionDescription): Promise<{ [key: string]: any }> {
        for (let field in data) {
            if (field === "id") {
                let setId = this.#generateRandomString(this.#idLength);
                let result = this.#queryCollection(collection, `id|${setId}`, collectionDescription);
                let condition = result !== undefined;
                if (condition) {
                    condition = (await (result as Cursor<CollectionDocument>).count()) !== 0;
                }
                data[field] = setId;
                while (condition) {
                    setId = this.#generateRandomString(this.#idLength);
                    result = this.#queryCollection(collection, `id|${setId}`, collectionDescription);
                    condition = result !== undefined;
                    if (condition) {
                        condition = (await (result as Cursor<CollectionDocument>).count()) !== 0;
                    }
                    data[field] = setId;
                }
            }
        }
        return data;
    }
    /**
     * Detects whether the data to be inserted/edited fulfills the unique criteria. 
     * @param query The query to check.
     * @param collectionDescription The CollectionDescription of the collection to check for.
     * @param collection The collection to check for.
     * @returns Whether the checks passed.
     */
    async #queryFulfillsUniqueFields(query: { [key: string]: any }, collectionDescription: CollectionDescription, collection: Collection): Promise<boolean> {
        for (let field in query) {
            if (!(field in collectionDescription["fields"])) {
                return false;
            }
            if (collectionDescription["fields"][field]["unique"]) {
                const existingEntries = this.#queryCollection(collection, `${field}|${query[field]}`, collectionDescription);
                if (existingEntries !== undefined) {
                    const count = await existingEntries.count();
                    if (count !== 0) {
                        return false;
                    }
                }
            }
        }
        return true;
    }
    /**
     * Generates a random string of the inputted length to use for ids/tokens.
     * @param length The length of the string to generate.
     * @returns The generated string.
     */
    #generateRandomString(length: number): string {
        let result = '';
        const characters = 'ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789';
        const charactersLength = characters.length;
        for (let i = 0; i < length; i++) {
            result += characters.charAt(Math.floor(Math.random() * charactersLength));
        }
        return result;
    }
    /**
     * Detects whether a query has the fields to be inserted into a collection.
     * @param query The query to check.
     * @param collectionDescription The CollectionDescription of the collection to check the query for.
     * @returns Whether the checks passed.
     */
    #queryHasRequiredFields(query: { [key: string]: any }, collectionDescription: CollectionDescription): boolean {
        for (let field in collectionDescription["fields"]) {
            if (collectionDescription["fields"][field]["required"]) {
                if (!(field in query)) {
                    return false;
                }
            }
        }
        return true;
    }
    /**
     * Detects whether a query has the correct types to be inserted into a collection.
     * @param query The query to check.
     * @param collectionDescription The CollectionDescription of the collection to check the query for.
     * @returns Whether the checks passed.
     */
    #queryHasCorrectTypes(query: { [key: string]: any }, collectionDescription: CollectionDescription): boolean {
        for (let field in query) {
            if (collectionDescription["fields"][field]["type"] === "string") {
                if (typeof query[field] !== "string") {
                    return false;
                }
            } else if (collectionDescription["fields"][field]["type"] === "number") {
                if (typeof query[field] !== "number") {
                    return false;
                }
            }
        }
        return true;
    }
    /**
     * Detects whether a query tries to change a readonly field.
     * @param query The query to check.
     * @param collectionDescription The CollectionDescription of the collection to check the query for.
     * @returns Whether the checks passed.
     */
    #queryContainsReadonlyFields(query: { [key: string]: any }, collectionDescription: CollectionDescription): boolean {
        for (let field in query) {
            if (collectionDescription["fields"][field]["readonly"] === true) {
                return true;
            }
        }
        return false;
    }
    /**
     * Called from every collection endpoint to validate the access of the user.
     * @param req The express `req` parameter.
     * @param res The express `res` parameter.
     * @param collection The collection to act on.
     * @param collectionDescription The collectionDescription of the `collection`.
     * @param accessType The type of access the user requests.
     * @returns Either all documents that the user has access to or a boolean stating that the user has access to the collection.
     */
    async #handleRequest(req: any, res: any, collection: Collection, collectionDescription: CollectionDescription, accessType: CollectionDescriptionAccessKey): Promise<CollectionDocument[] | boolean> {
        // Get user document
        let user: (Cursor<any> | undefined) | CollectionDocument = this.#database?.collection("Users").find({$and:[{username: req.body.username}, {token: req.body.user_token}]});
        if (user === undefined || user == null || (await user.count()) == 0) {
            if (collectionDescription["name"] !== "Users") {
                res.status(403).send(JSON.stringify(this.#unauthorized));
                return false;
            }
            else {
                return this.#checkAccess(collectionDescription["access"][accessType] as string, null, null, collectionDescription);
            }
        }
        user = (await user.next()) as CollectionDocument;
        if (moment(user["token_disallow"], "DD-MM-YYYY|HH:mm").isBefore(moment())) {
            res.status(403).send(JSON.stringify(this.#unauthorized));
            return false;
        }

        // Get required document if needed.
        let result: Cursor<CollectionDocument> | null | undefined = null;
        if (accessType === "read" || accessType === "edit" || accessType === "delete") {
            if (req.body.query === undefined) {
                res.status(400).send(JSON.stringify(this.#malformedRequest));
                return false;
            }
            result = this.#queryCollection(collection, req.body.query, collectionDescription);
            if (result === undefined) {
                res.status(404).send(JSON.stringify(this.#resNotFound));
                return false;
            }
            // Check document access
            const accessibleDocuments: CollectionDocument[] = [];
            while (!result.isClosed() && await result.hasNext()) {
                const document = await result.next() as CollectionDocument;
                if (this.#checkAccess(collectionDescription["access"][accessType] as string, user, document, collectionDescription)) {
                    accessibleDocuments.push(document);
                }
            }
            return accessibleDocuments;
        }
        // Check access normally.
        else {
            return this.#checkAccess(collectionDescription["access"][accessType] as string, user, result, collectionDescription);
        }
    }
    /**
     * Checks whether a user has access to a document/collection.
     * @param accessString The string provided in the collectionDescription.
     * @param user The user document to check for.
     * @param document The document to check for.
     * @param collection The collection to check in.
     * @returns Whether the user has access or not.
     */
    #checkAccess(accessString: string, user: CollectionDocument | null, document: CollectionDocument | null, collection: CollectionDescription): boolean {
        if (accessString.startsWith("@")) {
            if (accessString === "@everyone") {
                return true;
            } else if (accessString === "@noone") {
                return false;
            } else if (accessString === "@everyuser" && user !== null) {
                return true;
            } else {
                return false;
            }
        }
        const expressionSides = accessString.split("=");
        let expressions: any[] = [];
        for (let i = 0; i < expressionSides.length; i++) {
            switch(expressionSides[i].substr(0, 1)) {
                case "$":
                    if (document === null) {
                        return false;
                    }
                    expressions[i] = document[expressionSides[i].substr(1)];
                    break;
                case "%":
                    expressions[i] = collection["fields"][expressionSides[i].substr(1)];
                    break;
                case "&":
                    if (user == null) {
                        return false;
                    }
                    expressions[i] = user[expressionSides[i].substr(1)];
                    break;
            }
        }
        return expressions[0] == expressions[1];
    }
    /**
     * Used internally to query a collection.
     * @param collection The collection to query.
     * @param queryString The query string, multiple clauses separated by `&`. The clause sides are separated by `|`.
     * @returns The queried ressources or undefined.
     */
    #queryCollection(collection: Collection, queryString: string, collectionDescription: CollectionDescription): Cursor<CollectionDocument> | undefined {
        const selectors: {}[] = queryString.split("&").map((v: string): {} => {
            let type = collectionDescription["fields"][v.split("|")[0]]["type"];
            let value: any = v.split("|")[1];
            switch (type) {
                case "string":
                    value = value;
                    break;
                case "number":
                    value = Number(value)
                    break;
            }
            return {
                [v.split("|")[0]]: value
            };
        });
        return collection.find({$and: selectors});
    }
    /**
     * Call to initialize ReAPI. Setsup all collection and express endpoints.
     */
    public create (): void {
        if (this.#express === null) {
            throw new Error("Express was null, should have been declared in constructor!");
        }
        if (!("Users" in this.#collections)) {
            throw new Error("The Library does not support databases without users! Did you forget to call setUserCollection?");
        }
        // Create all collections and endpoints.
        for (const collectionName in this.#collections) {
            if (this.#collections[collectionName] !== null) {
                this.#createCollection(collectionName);
            }
        }
        this.#express.post("/login", async (req, res) => {
            if (req.body.username === undefined || req.body.password === undefined) {
                res.status(400).send(JSON.stringify(this.#malformedRequest));
                return;
            }
            let user = await this.#database?.collection("Users").findOne({$and: [{username: req.body.username}]});
            if (user === undefined || user == null) {
                res.status(400).send(JSON.stringify(this.#malformedRequest));
                return;
            }
            user = user as CollectionDocument;
            let result = await bcrypt.compare(req.body.password, user["password_hash"]);
            if (!result) {
                res.status(403).send(JSON.stringify(this.#unauthorized));
                return;
            }
            let token = this.#generateRandomString(this.#tokenLength);
            await this.#database?.collection("Users").updateOne({$and: [{username: req.body.username}]}, {$set: {
                token: token,
                token_disallow: moment().add(this.#token_disallow_minutes, "minutes").format("DD-MM-YYYY|HH:mm")
            }});
            res.status(200).send(JSON.stringify({
                "success": true, 
                "data": {
                    "token": token
                }
            }));
        });
        this.#express.post("/logout", async (req, res) => {
            if (req.body.username === undefined || req.body.token === undefined) {
                res.status(400).send(JSON.stringify(this.#malformedRequest));
                return;
            }
            let user = await this.#database?.collection("Users").findOne({$and: [{username: req.body.username}, {token: req.body.token}]});
            if (user === undefined || user == null) {
                res.status(400).send(JSON.stringify(this.#malformedRequest));
                return;
            }
            user = user as CollectionDocument;
            await this.#database?.collection("Users").updateOne({$and: [{username: req.body.username}]}, {$set: {
                token: "",
                token_disallow: moment().subtract(this.#token_disallow_minutes, "minutes").format("DD-MM-YYYY|HH:mm")
            }});
            res.status(200).send(JSON.stringify(this.#requestFulfilled));
        });
        this.#express.post("/verifyToken", async (req, res) => {
            if (req.body.username === undefined || req.body.token === undefined) {
                res.status(400).send(JSON.stringify(this.#malformedRequest));
                return;
            }
            let user = await this.#database?.collection("Users").findOne({$and: [{username: req.body.username}, {token: req.body.token}]});
            if (user === undefined || user == null) {
                res.status(400).send(JSON.stringify(this.#malformedRequest));
                return;
            }
            res.status(200).send(JSON.stringify(this.#requestFulfilled));
        });

        this.#express.post("*", (_, res) => {
            res.status(404).send(JSON.stringify(this.#resNotFound));
        });
    }
}