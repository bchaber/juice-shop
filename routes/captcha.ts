/*
 * Copyright (c) 2014-2022 Bjoern Kimminich & the OWASP Juice Shop contributors.
 * SPDX-License-Identifier: MIT
 */

import { Request, Response, NextFunction } from 'express'
import { Captcha } from '../data/types'
import { CaptchaModel } from '../models/captcha'

const crypto = require('crypto')

function captchas () {
  return async (req: Request, res: Response) => {
    const captchaId = req.app.locals.captchaId++
    const operators = ['*', '+', '-']

    const firstTerm = Math.floor((Math.random() * 10) + 1)
    const secondTerm = Math.floor((Math.random() * 10) + 1)
    const thirdTerm = Math.floor((Math.random() * 10) + 1)

    const firstOperator = operators[Math.floor((Math.random() * 3))]
    const secondOperator = operators[Math.floor((Math.random() * 3))]

    const expression = firstTerm.toString() + firstOperator + secondTerm.toString() + secondOperator + thirdTerm.toString()
    const answer = eval(expression).toString() // eslint-disable-line no-eval

    const key = Buffer.from('8e064f50b6961f2149830801a865f508863caa6869dfd5d61466dd263ca29a77', 'hex')
    const iv = Buffer.from('b94c06260c6c95f6226a18e2dfe7b68c', 'hex')
  
    const cipher = crypto.createCipheriv('aes-256-cbc', key, iv)
    cipher.update(answer)
    
    const captcha = {
      captchaId: captchaId,
      captcha: expression,
      answer: iv.toString('hex') + ':' + cipher.final().toString('hex')
    }
    console.info("> " + captcha.answer)
    const captchaInstance = CaptchaModel.build(captcha)
    await captchaInstance.save()
    res.json(captcha)
  }
}

captchas.verifyCaptcha = () => (req: Request, res: Response, next: NextFunction) => {
  console.info(req.body);
  const iv_with_enc = req.body.captchaAnswer.split(":")

  const key = Buffer.from('8e064f50b6961f2149830801a865f508863caa6869dfd5d61466dd263ca29a77', 'hex')
  const iv = Buffer.from(iv_with_enc[0], 'hex')
  const enc = Buffer.from(iv_with_enc[1], 'hex')

  try {
    const cipher = crypto.createDecipheriv('aes-256-cbc', key, iv)
    cipher.update(enc)
    const answer = cipher.final()
    console.info("Answer should be '" + answer + "' and is '" + req.body.captcha + "'");
    if (req.body.captcha == answer) {
      next()
    } else {
      res.status(401).send(res.__('Wrong answer to CAPTCHA. Please try again, dude.'))
    }
  } catch (error) {
    next(error)
  }
}

module.exports = captchas
