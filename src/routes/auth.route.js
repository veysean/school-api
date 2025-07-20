import express from 'express';
import {
    register,
    login,
    authenticateToken

} from '../controllers/auth.controller.js';


const router = express.Router();

router.post('/register', register);
router.get('/login', login);
router.get('/user', authenticateToken);

export default router;