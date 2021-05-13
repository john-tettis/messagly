const jwt = require("jsonwebtoken");
const Router = require("express").Router;
const router = new Router();
const {authenticateJWT, ensureLoggedIn} = require('../middleware/auth')

const User = require("../models/user");
const Message = require("../models/message");
const {SECRET_KEY} = require("../config");
const ExpressError = require("../expressError");

/** GET /:id - get detail of message.
 *
 * => {message: {id,
 *               body,
 *               sent_at,
 *               read_at,
 *               from_user: {username, first_name, last_name, phone},
 *               to_user: {username, first_name, last_name, phone}}
 *
 * Make sure that the currently-logged-in users is either the to or from user.
 *
 **/
router.get('/:id',ensureLoggedIn, async function(req, res, next){
    try{
        let message = await Message.get(+req.params.id)
        if(req.user.username === message.from_user.username || req.user === message.to_user.username){
            return res.send(message)
        }
        else{
            throw new ExpressError('Unauhtorized',401)
        }

    }catch(e){
        next(e)
    }
})


/** POST / - post message.
 *
 * {to_username, body} =>
 *   {message: {id, from_username, to_username, body, sent_at}}
 *
 **/
router.post('/', ensureLoggedIn, async function(req, res, next){
    try{
        let info = {
            from_username:req.user.username,
            to_username:req.body.to_username,
            body:req.body.body
        }
        let message = await Message.create(info)
        if(message){
            return res.send({message})
        }
        else{
            throw new ExpressError('Message note created',500)
        }

    }catch(e){
        next(e)
    }
})


/** POST/:id/read - mark message as read:
 *
 *  => {message: {id, read_at}}
 *
 * Make sure that the only the intended recipient can mark as read.
 *
 **/
router.post('/:id/read', ensureLoggedIn, async function(req, res, next){
    try{
        let message = await Message.get(+req.params.id)
        if(req.user.username === message.to_user.username){
            let message = await Message.markRead(+req.params.id)
        return res.send({message})
        }
        else{
            throw new ExpressError('Unauthorized',401)
        }
        
    }catch(e){

        next(e)
    }
})

 module.exports = router