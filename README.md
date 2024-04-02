# User Authentication and Registration Routes

This TypeScript file contains Express routes for user authentication and registration in a hotel management system.

## File Description

- **File Name:** `authRoutes.ts`
- **Description:** Contains routes for user login and registration, along with middleware functions for authentication and authorization.
- **Dependencies:** `express`, `body-parser`, `mongoose`, `bcrypt`, `jsonwebtoken`, `joi`

## Routes

- **POST /api/v1/users/login:** Endpoint for user login. Accepts username and password, validates credentials, and returns a JWT token upon successful authentication.
- **POST /api/v1/users/register:** Endpoint for user registration. Accepts username, password, and optional role, hashes the password, and stores the user in the database.

## Middleware

- **authenticateUser:** Middleware function for authenticating user requests using JWT tokens.
- **authorizeAdmin:** Middleware function for authorizing administrative access to certain routes.
- **validateData:** Middleware function for validating request data using Joi schema validation.

## Setup

1. Ensure all dependencies are installed (`express`, `body-parser`, `mongoose`, `bcrypt`, `jsonwebtoken`, `joi`).
2. Connect the application to a MongoDB database using Mongoose.
3. Configure JWT secret key for token generation.
4. Start the Express server.

## Usage

1. Send POST requests to `/api/v1/users/login` with valid credentials to obtain a JWT token for authentication.
2. Send POST requests to `/api/v1/users/register` with new user details to register a new user.
3. Use middleware functions (`authenticateUser`, `authorizeAdmin`) as needed for route protection and authorization.

## Contributing

Contributions are welcome! Feel free to open issues or pull requests for any improvements or bug fixes.

## License

This project is licensed under the [MIT License](LICENSE).
