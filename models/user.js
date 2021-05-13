/** User class for message.ly */
const db = require('../db')
const bcrypt = require('bcrypt')
const {BCRYPT_WORK_FACTOR} = require('../config')
const ExpressError = require('../expressError')


/** User of the site. */

class User {

  /** register new user -- returns
   *    {username, password, first_name, last_name, phone}
   */

  static async register({username, password, first_name, last_name, phone}) { 
    const pass = await bcrypt.hash(password,BCRYPT_WORK_FACTOR)
    const results = await db.query(`INSERT INTO users (username,password,first_name,last_name,phone, join_at,last_login_at) 
    VALUES($1,$2,$3,$4,$5, current_timestamp,current_timestamp) RETURNING username,password,first_name,last_name,phone`,[username,pass,first_name,last_name,phone])
    return results.rows[0]
  }

  /** Authenticate: is this username/password valid? Returns boolean. */

  static async authenticate(username, password) { 
    let user = await db.query('SELECT password FROM users WHERE username=$1',[username])
    console.log(user.rows)
    if(user.rows.length ===0) throw new ExpressError('Invalid username',400)
    let payload = await bcrypt.compare(password, user.rows[0].password)
    return payload
  }

  /** Update last_login_at for user */

  static async updateLoginTimestamp(username) {
    let results = await db.query('UPDATE users SET last_login_at=current_timestamp WHERE username = $1 RETURNING username',[username])
    if(!results.rows[0]){
      throw new ExpressError('User does not exist',404)
    }
  }

  /** All: basic info on all users:
   * [{username, first_name, last_name, phone}, ...] */

  static async all() {
    let results = await db.query(`SELECT username, first_name, last_name, phone FROM users`)
    return results.rows
  }

  /** Get: get user by username
   *
   * returns {username,
   *          first_name,
   *          last_name,
   *          phone,
   *          join_at,
   *          last_login_at } */

  static async get(username) { 
    let user = await db.query('SELECT username,first_name,last_name,phone, join_at,last_login_at FROM users WHERE username = $1',[username])
    return user.rows[0]
  }

  /** Return messages from this user.
   *
   * [{id, to_user, body, sent_at, read_at}]
   *
   * where to_user is
   *   {username, first_name, last_name, phone}
   */

  static async messagesFrom(username) { 
    let results = await db.query(`SELECT m.id,
      m.to_username,
      u.first_name,
      u.last_name,
      u.phone,
      m.body,
      m.sent_at,
      m.read_at
      FROM messages AS m
      JOIN users AS u ON m.to_username = u.username
      WHERE from_username = $1`,
      [username])
    return results.rows.map(row =>({
      id:row.id,
      to_user:{
        username:row.to_username,
        first_name:row.first_name,
        last_name:row.last_name,
        phone:row.phone
      },
      body:row.body,
      sent_at:row.sent_at,
      read_at:row.read_at
    }))
  }

  /** Return messages to this user.
   *
   * [{id, from_user, body, sent_at, read_at}]
   *
   * where from_user is
   *   {id, first_name, last_name, phone}
   */

  static async messagesTo(username) {
    let results = await db.query(`SELECT m.id,
    m.from_username,
    u.first_name,
    u.last_name,
    u.phone,
    m.body,
    m.sent_at,
    m.read_at
    FROM messages AS m
    JOIN users AS u ON m.from_username = u.username
    WHERE to_username = $1`,
    [username])
  return results.rows.map(row =>({
    id:row.id,
    from_user:{
      username:row.from_username,
      first_name:row.first_name,
      last_name:row.last_name,
      phone:row.phone
    },
    body:row.body,
    sent_at:row.sent_at,
    read_at:row.read_at
    }))
  }
}


module.exports = User;