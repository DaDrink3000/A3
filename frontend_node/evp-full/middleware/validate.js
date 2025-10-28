const Joi = require('joi');

function validate(schema){
  return function(req,res,next){
    const data = { body: req.body, params: req.params, query: req.query };
    const resu = schema.validate(data, { abortEarly:false, allowUnknown:true });
    if(resu.error){
      return res.status(400).json({ ok:false, error: 'ValidationError', details: resu.error.details.map(d=>d.message) });
    }
    next();
  }
}

// Schemas
const loginSchema = Joi.object({
  body: Joi.object({
    username: Joi.string().min(3).max(64).required(),
    password: Joi.string().min(3).max(128).required()
  }).required()
});

const voteConfirmSchema = Joi.object({
  body: Joi.object({
    choice: Joi.string().valid('A','B').required()
  }).required()
});

const mfaVerifySchema = Joi.object({
  body: Joi.object({
    token: Joi.string().pattern(/^[0-9]{6}$/).required()
  }).required()
});

module.exports = { validate, loginSchema, voteConfirmSchema, mfaVerifySchema };
