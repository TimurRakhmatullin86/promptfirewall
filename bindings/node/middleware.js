const { scan } = require('./index');

function guard(options) {
  const opts = Object.assign({}, options);
  const onUnsafe = opts.onUnsafe || 'reject';
  const scanFields = opts.scanFields || ['prompt', 'message', 'content', 'query', 'input', 'text'];
  const scanOpts = {};
  if (opts.detectPii !== undefined) scanOpts.detectPii = opts.detectPii;
  if (opts.detectInjection !== undefined) scanOpts.detectInjection = opts.detectInjection;
  if (opts.piiTypes !== undefined) scanOpts.piiTypes = opts.piiTypes;
  if (opts.injectionThreshold !== undefined) scanOpts.injectionThreshold = opts.injectionThreshold;
  if (opts.redact !== undefined) scanOpts.redact = opts.redact;
  if (opts.redactWith !== undefined) scanOpts.redactWith = opts.redactWith;

  return function promptfirewallMiddleware(req, res, next) {
    if (!req.body || typeof req.body !== 'object') return next();

    const texts = [];
    function walk(obj) {
      if (!obj || typeof obj !== 'object') return;
      for (const field of scanFields) {
        const val = obj[field];
        if (typeof val === 'string' && val) texts.push(val);
        if (Array.isArray(val)) {
          for (const item of val) {
            if (typeof item === 'string' && item) texts.push(item);
            else if (typeof item === 'object') walk(item);
          }
        }
      }
      if (Array.isArray(obj.messages)) {
        for (const msg of obj.messages) {
          if (typeof msg === 'object') walk(msg);
        }
      }
    }

    walk(req.body);

    for (const text of texts) {
      const result = scan(text, scanOpts);
      if (!result.isSafe && onUnsafe === 'reject') {
        return res.status(400).json({
          error: 'Request blocked by promptfirewall',
          injectionScore: result.injectionScore,
          piiCount: result.piiFindings.length,
        });
      }
    }

    next();
  };
}

module.exports = { guard };
