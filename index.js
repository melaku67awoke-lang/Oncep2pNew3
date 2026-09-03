'use strict';

// Once P2P V115
// NOTE: This is a starter index.js placeholder package.
// Replace this file with your full backend before deployment.

const express = require('express');
const app = express();

app.get('/api/health',(req,res)=>{
  res.json({ok:true, app:'Once P2P V115'});
});

app.listen(process.env.PORT || 3000);
