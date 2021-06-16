import { Db, MongoClient } from "mongodb";

export class ReMongo {
    #client: MongoClient;
    #databaseName: string;
    #database: Db | null = null;
    #collections: { [name:string]: { [key: string]: string } | null } = {};
    /**
     * Use this to create a new `ReMongo` instance.
     * @param connectionString The connection string with username and password filled out.
     * @param database The name of the database to connect to.
     */
    public constructor(connectionString: string, database: string) {
        this.#databaseName = database;
        this.#client = new MongoClient(connectionString, { useNewUrlParser: true, useUnifiedTopology: true });
    }
    /** 
     * Use this to connect to MongoDB and the database.
     */
    public async connect () {
        await this.#client.connect();
        this.#database = this.#client.db(this.#databaseName);
    }
    /**
     * Use this to close the connection to MongoDB.
     * @returns Promise that resolves once the client closed the connection.
     */
    public close () {
        return this.#client.close();
    }
}