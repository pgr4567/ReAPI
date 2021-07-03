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

export type CollectionFieldValueType = {
    valueType: "string" | "number" | "union" | { [key: string]: CollectionFieldValue },
    valueForm: "single" | "array",
    unionTypes?: string[]
};
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
    readonly #saltRounds: number = 10;
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
     * @param collectionName The name of the collection to set. This must end with an 's'.
     * @param collectionDescription The data that should be associated with the collection. If this is null, the collection will be ignored.
     */
    public setCollection<T extends string> (collectionName: T extends "Users" ? never : T, collectionDescription: CollectionDescription | null): void {
        if (!collectionName.endsWith("s")) {
            throw new Error("Collection names must end with an 's'.");
        }
        if (collectionDescription !== null) {
            if ("id" in collectionDescription["fields"]) {
                throw new Error("The id field is added to every CollectionDescription automatically.");
            }
            if (collectionDescription.name !== collectionName) {
                throw new Error("The collection names must be identical!");
            }
            collectionDescription["fields"]["id"] = {
                "type": {
                    "valueType": "string",
                    "valueForm": "single"
                },
                "required": false,
                "unique": true,
                "readonly": true,
                "secret": false
            };
            for (let f in collectionDescription["fields"]) {
                this.#checkFieldsRecursively(collectionDescription.fields[f]);
            }
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
                "type": {
                    "valueType": "string",
                    "valueForm": "single"
                },
                "required": true,
                "unique": true,
                "readonly": false,
                "secret": false
            };
            customUserDataCollection["fields"]["id"] = {
                "type": {
                    "valueType": "string",
                    "valueForm": "single"
                },
                "required": false,
                "unique": true,
                "readonly": true,
                "secret": false
            };
            customUserDataCollection["fields"]["password_hash"] = {
                "type": {
                    "valueType": "string",
                    "valueForm": "single"
                },
                "required": true,
                "unique": false,
                "readonly": false,
                "secret": true,
                "preInsert": async (password: string) => {
                    return await bcrypt.hash(password, this.#saltRounds);
                },
                "preEdit": async (password: string) => {
                    return await bcrypt.hash(password, this.#saltRounds);
                }
            };
            customUserDataCollection["fields"]["token"] = {
                "type": {
                    "valueType": "string",
                    "valueForm": "single"
                },
                "required": false,
                "unique": false,
                "readonly": true,
                "secret": true
            };
            customUserDataCollection["fields"]["token_disallow"] = {
                "type": {
                    "valueType": "string",
                    "valueForm": "single"
                },
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
            for (let f in customUserDataCollection["fields"]) {
                this.#checkFieldsRecursively(customUserDataCollection.fields[f]);
            }
            this.#collections["Users"] = customUserDataCollection;
        }
    }

    /**
     * This generates type definitions of the inserted collection to aid with type checking in the client application.
     * @returns The generated type definitions.
     */
    public createCollectionTypes(): string {
        let result = '';
        for (let c in this.#collections) {
            if (this.#collections[c] === null) {
                continue;
            }
            const collection = this.#collections[c] as CollectionDescription;
            result += `export type ${c.slice(0, -1)} = {\n`;
            for (let field in collection.fields) {
                result += `\t${field}`;
                if (!collection.fields[field].required && collection.fields[field].preInsert == undefined) {
                    result += '?';
                }
                if (collection.fields[field].type.valueType === "string" || collection.fields[field].type.valueType === "number") {
                    result += `: ${collection.fields[field].type.valueType}`;
                } else if (collection.fields[field].type.valueType === "union") {
                    result += `: ${collection.fields[field].type.unionTypes?.reduce((acc, curr, index) => index == 1 ? `"${acc}" | "${curr}"` : `${acc} | "${curr}"`)}`;
                } else {
                    result += `: ${this.#addRecursiveCollectionTypes(collection.fields[field].type.valueType as { [key: string]: CollectionFieldValue }, 1)}`;
                }
                if (collection.fields[field].type.valueForm === "array") {
                    result += '[]';
                }
                result += ';\n';
            }
            result += '};\n\n';
        }
        return result;
    }
    /**
     * Checks if the collection fields have a union type definition if their type is of type union.
     * @param fields The CollectionFields to check.
     */
    #checkFieldsRecursively(fields: CollectionFieldValue) {
        if (fields.type.valueType === "union" && fields.type.unionTypes == undefined) {
            throw new Error("If the valueType is union, the unionTypes must be set!");
        }
        if (fields.type.valueType !== "string" && fields.type.valueType !== "number") {
            for (let v in fields.type.valueType as { [key: string]: CollectionFieldValue }) {
                this.#checkFieldsRecursively((fields.type.valueType as { [key: string]: CollectionFieldValue })[v] as CollectionFieldValue);
            }
        }
    }
    /**
     * Used internally to generate type string recursively.
     * @param valueTypes The types still to add.
     * @param level How deep are we into recursion?
     * @returns The type string.
     */
    #addRecursiveCollectionTypes(valueTypes: { [key: string]: CollectionFieldValue }, level: number): string {
        let result = '{\n\t' + '\t'.repeat(level);
        for (let k in valueTypes) {
            if (valueTypes[k].type.valueType === "string" || valueTypes[k].type.valueType === "number") {
                result += `${k}: ${valueTypes[k].type.valueType}`;
            } else if (valueTypes[k].type.valueType === "union") {
                result += `${k}: ${valueTypes[k].type.unionTypes?.reduce((acc, curr, index) => index == 1 ? `"${acc}" | "${curr}"` : `${acc} | "${curr}"`)}`;
            } else {
                result += `${k}: ${this.#addRecursiveCollectionTypes(valueTypes[k].type.valueType as { [key: string]: CollectionFieldValue }, level + 1)}`;
            }
            if (valueTypes[k].type.valueForm === "array") {
                result += '[]';
            }
            result += ';\n\t' + '\t'.repeat(level);
        }
        result = result.substring(0, result.length - 1);
        result += '}';
        return result;
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
            if (!(await this.#queryFulfillsUniqueFields(req.body.document_data, collectionDescription.fields, collection))) {
                res.status(400).send(JSON.stringify(this.#malformedRequest));
                return;
            }
            if (!this.#queryHasCorrectTypes(req.body.document_data, this.#extractCollectionFieldValues(collectionDescription))) {
                res.status(400).send(JSON.stringify(this.#malformedRequest));
                return;
            }
            if (this.#queryContainsReadonlyFields(req.body.document_data, collectionDescription.fields)) {
                res.status(400).send(JSON.stringify(this.#malformedRequest));
                return;
            }
            let insertData = await this.#prepareInsertData(req.body.document_data, collection);
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
                    if (!this.#queryHasRequiredFields(req.body.document_data, collectionDescription.fields)) {
                        res.status(400).send(JSON.stringify(this.#malformedRequest));
                        return; 
                    }
                    if (!this.#queryHasCorrectTypes(req.body.document_data, this.#extractCollectionFieldValues(collectionDescription))) {
                        res.status(400).send(JSON.stringify(this.#malformedRequest));
                        return; 
                    }
                    if (this.#queryContainsReadonlyFields(req.body.document_data, collectionDescription.fields)) {
                        res.status(400).send(JSON.stringify(this.#malformedRequest));
                        return; 
                    }
                    let insertData: { [key: string]: any } = req.body.document_data;
                    for (let field in collectionDescription["fields"]) {
                        if (!(field in insertData)) {
                            insertData[field] = null;
                        }
                    }
                    if (!(await this.#queryFulfillsUniqueFields(insertData, collectionDescription.fields, collection))) {
                        res.status(400).send(JSON.stringify(this.#malformedRequest));
                        return;
                    }
                    insertData = await this.#prepareInsertData(insertData, collection);
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
     * @param collection The collection to prepare for.
     * @returns The prepared data.
     */
    async #prepareInsertData(data: { [key: string]: any }, collection: Collection): Promise<{ [key: string]: any }> {
        for (let field in data) {
            if (field === "id") {
                let setId = this.#generateRandomString(this.#idLength);
                let result = collection.find({id: setId});
                let condition = result !== undefined;
                if (condition) {
                    condition = (await (result as Cursor<CollectionDocument>).count()) !== 0;
                }
                data[field] = setId;
                while (condition) {
                    setId = this.#generateRandomString(this.#idLength);
                    result = collection.find({id: setId});
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
     * @param collectionFields The CollectionFields of the collection to check for.
     * @param collection The collection to check for.
     * @param override Whether a parent element is unique.
     * @returns Whether the checks passed.
     */
    async #queryFulfillsUniqueFields(query: { [key: string]: any }, collectionFields: { [key: string]: CollectionFieldValue }, collection: Collection, override: boolean = false): Promise<boolean> {
        for (let field in query) {
            if (!(field in collectionFields)) {
                return false;
            }
            if (collectionFields[field].type.valueType !== "string" && collectionFields[field].type.valueType !== "number" && collectionFields[field].type.valueType !== "union") {
                return await this.#queryFulfillsUniqueFields(query[field], collectionFields[field].type.valueType as { [key: string]: CollectionFieldValue }, collection, override || collectionFields[field]["unique"]);
            }
            if (collectionFields[field]["unique"] || override) {
                const queryDB: any = {};
                queryDB[field] = query[field];
                const existingEntries = collection.find(queryDB);
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
     * Maps a CollectionDescription to a dictionary of CollectionFieldValueTypes for use in {@link #queryHasCorrectTypes()}.
     * @param collectionDescription The CollectionDescription to iterate over.
     * @returns The generated dictionary of CollectionFieldValueTypes.
     */
    #extractCollectionFieldValues(collectionDescription: CollectionDescription): { [key: string]: CollectionFieldValue } {
        const result: { [key: string]: CollectionFieldValue } = { };
        for (let field in collectionDescription.fields) {
            result[field] = collectionDescription.fields[field];
        }
        return result;
    }
    /**
     * Detects whether a query has the fields to be inserted into a collection.
     * @param query The query to check.
     * @param collectionFields The CollectionDescription of the collection to check the query for.
     * @param override Whether a parent element is required.
     * @returns Whether the checks passed.
     */
    #queryHasRequiredFields(query: { [key: string]: any }, collectionFields: { [key: string]: CollectionFieldValue }, override: boolean = false): boolean {
        for (let field in collectionFields) {
            if (collectionFields[field].type.valueType !== "string" && collectionFields[field].type.valueType !== "number" && collectionFields[field].type.valueType !== "union") {
                return this.#queryHasRequiredFields(query[field], collectionFields[field].type.valueType as { [key: string]: CollectionFieldValue }, collectionFields[field].required || override);
            }
            if (collectionFields[field].required || override) {
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
     * @param collectionDescriptionFields The CollectionDescription of the collection to check the query for.
     * @returns Whether the checks passed.
     */
    #queryHasCorrectTypes(query: { [key: string]: any }, collectionDescriptionFields: { [key: string]: CollectionFieldValue }): boolean {
        for (let field in query) {
            if (collectionDescriptionFields[field].type.valueType === "string" || collectionDescriptionFields[field].type.valueType === "number") {
                if (collectionDescriptionFields[field].type.valueForm === "single") {
                    if (typeof query[field] !== collectionDescriptionFields[field].type.valueType) {
                        return false;
                    }
                } else {
                    for (let subField in query[field]) {
                        if (typeof query[field][subField] !== collectionDescriptionFields[field].type.valueType) {
                            return false;
                        }
                    }
                }
            } else if (collectionDescriptionFields[field].type.valueType === "union") {
                if (collectionDescriptionFields[field].type.valueForm === "single") {
                    let hit = false;
                    for (let union of collectionDescriptionFields[field].type.unionTypes!) {
                        if (query[field] === union) {
                            hit = true;
                            break;
                        }
                    }
                    if (!hit) {
                        return false;
                    }
                } else {
                    for (let subField in query[field]) {
                        let hit = false;
                        for (let union of collectionDescriptionFields[field].type.unionTypes!) {
                            if (query[field][subField] === union) {
                                hit = true;
                                break;
                            }
                        }
                        if (!hit) {
                            return false;
                        }
                    }
                }
            } else {
                this.#queryHasCorrectTypes(query[field], collectionDescriptionFields[field].type.valueType as { [key: string]: CollectionFieldValue });
            }
        }
        return true;
    }
    /**
     * Detects whether a query tries to change a readonly field.
     * @param query The query to check.
     * @param collectionDescription The CollectionDescription of the collection to check the query for.
     * @param override Whether a parent element is readonly.
     * @returns Whether the checks passed.
     */
    #queryContainsReadonlyFields(query: { [key: string]: any }, collectionFields: { [key: string]: CollectionFieldValue }, override: boolean = false): boolean {
        for (let field in query) {
            if (collectionFields[field].type.valueType !== "string" && collectionFields[field].type.valueType !== "string" && collectionFields[field].type.valueType !== "string") {
                return this.#queryContainsReadonlyFields(query[field], collectionFields[field].type.valueType as { [key: string]: CollectionFieldValue }, collectionFields[field].readonly || override);
            }
            if (collectionFields[field].readonly || override) {
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
                return this.#checkAccess(collectionDescription["access"][accessType] as string, null, null);
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
            result = collection.find(req.body.query);
            if (result === undefined) {
                res.status(404).send(JSON.stringify(this.#resNotFound));
                return false;
            }
            // Check document access
            const accessibleDocuments: CollectionDocument[] = [];
            while (!result.isClosed() && await result.hasNext()) {
                const document = await result.next() as CollectionDocument;
                if (this.#checkAccess(collectionDescription["access"][accessType] as string, user, document)) {
                    accessibleDocuments.push(document);
                }
            }
            return accessibleDocuments;
        }
        // Check access normally.
        else {
            return this.#checkAccess(collectionDescription["access"][accessType] as string, user, result);
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
    #checkAccess(accessString: string, user: CollectionDocument | null, document: CollectionDocument | null): boolean {
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