import DBLocal from 'db-local'
import crypto from 'node:crypto'
import bcrypt from 'bcrypt'
import { SALT_ROUNDS } from './config.js'

const {Schema} = new DBLocal({path: './db'})

const User = Schema('User', {
    _id: {type: String, required: true},
    username: {type: String, required: true},
    password: {type: String, required: true}
});

export class UserRepository {
    static async create ({ username, password }) {
        //1. Validaciones de username (opcional: usar zod)
        Validation.username(username);
        Validation.password(password);
        
        //2. Asegurarse  que el username no existe
        const user = User.findOne({username});
        if (user) throw new Error('Username ya existe');

        const id = crypto.randomUUID();
       // const hasedPassword = bcrypt.hashSync(password, SALT_ROUNDS); // hashSync -> Bloquea el thread principal
       const hasedPassword = await bcrypt.hash(password, SALT_ROUNDS);

        User.create({
            _id: id,
            username,
            password: hasedPassword
        }).save();

        return id;

    }
    static async login ({ username, password }) {
        Validation.username(username);
        Validation.password(password);

        const user = User.findOne({username});
        if (!user) throw new Error ('El usuario no existe');

        const isValid = await bcrypt.compare(password, user.password);
        if (!isValid) throw new Error('La contraseña no es valida');

        const {password: _, ...publicUser} = user;

        return publicUser;
    }

   
}

class Validation {
    static username (username) {
        if (typeof username !== 'string') throw new Error('El usuario debe ser una cadena');
        if (username.length < 3 ) throw new Error('El usuario debe ser mayor o igual a tres caracteres');
    }

    static password (password) {
        if (typeof password !== 'string') throw new Error('La contraseña debe ser una cadena')
        if (password.length < 6) throw new Error('La contraseña deber ser mayor o igual a tres caracteres'); 
    }
}