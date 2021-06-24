# ReAPI

![npm](https://img.shields.io/npm/v/@pgr4567/reapi)
![GitHub](https://img.shields.io/github/license/pgr4567/ReAPI)
![Lines of code](https://img.shields.io/tokei/lines/github/pgr4567/ReAPI)
![npm bundle size](https://img.shields.io/bundlephobia/min/@pgr4567/reapi)
![npm type definitions](https://img.shields.io/npm/types/@pgr4567/reapi)
![npm](https://img.shields.io/npm/dw/@pgr4567/reapi)
![GitHub top language](https://img.shields.io/github/languages/top/pgr4567/ReAPI)

My personal API for webservers that use a database. You probably don't want to use this xd

## Summary
This projects enables me(and you) to create applications that use databases more easily. You simply have to populate ReAPI with your database schema and let it generate endpoints for all collections. These endpoints include authorization and authentication so you do not have to write the same backend every time you need a database. Just tell ReAPI that all users can create a Task, but only the Task owner can edit and delete it. ReAPI handles the rest and the client can simply call the endpoints, almost as if the client connected to the database directly.

## Documentation
### Setup
To use ReAPI, start by importing the module and creating a new ReMongo instance. Then call the connect function and add your collections. Lastly, call create and see your endpoints in action!
#### Example
```
import { CollectionDocument, ReMongo } from "@pgr4567/reapi";

const remongo = new ReMongo("connection_string", "database_name", 8000, "0.0.0.0");

async function run(): Promise<void> {
    await remongo.connect();

    remongo.setCollection("Tasks", {
        "name": "Tasks",
        "fields": {
            "owner_id": {
                "type": "string",
                "required": false,
                "unique": false,
                "readonly": true,
                "secret": false,
                "preInsert": (_: string, user?: CollectionDocument) => {
                    return user!["id"];
                }
            },
            "name": {
                "type": "string",
                "required": true,
                "unique": false,
                "readonly": false,
                "secret": false
            },
            "coolness": {
                "type": "number",
                "required": false,
                "unique": false,
                "readonly": false,
                "secret": false
            }
        },
        "access": {
            "read": "$owner_id=&id",
            "delete": "$owner_id=&id",
            "edit": "$owner_id=&id",
            "info": "@everyuser",
            "insert": "@everyuser"
        }
    });
    
    remongo.setUserCollection({
        "name": "",
        "fields": {},
        "access": {
            "read": "",
            "delete": "",
            "edit": "",
            "info": "",
            "insert": ""
        }
    });

    remongo.create();
}

run();
```
### Creation of collections
When creating a collection, the required access fields `read`, `edit`, `insert`, `info`, `delete` have the following format:
- The only supported operant is `=`.
- `$` references the fields of the document.
- `%` references the fields of the collection.
- `&` references the fields of the user document.

Use these rules to create a condition that enables said access right when true.

### Making requests to endpoints
- Every request is a POST request that must have all data in the body.
- Content-Type header must be application/json.
- `user_id` and `user_token` is required in every request.
- `query` is required when you want to target existing documents. The format is: 
    - Separate clauses must be separated by `&`.
    - Clause statements must be separated by `|`.
- `document_data` is required when you want to insert a new or edit an existing document.

## TODO
- Add more database types.
- Add more authentication methods.
- Add more value types:
  - Enums