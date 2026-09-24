export const notFound = (req, res) => {
  res.status(404).json({ error: 'not_found', path: req.path });
};

const debugContext = (req) => ({
  node: process.version,
  platform: `${process.platform} ${process.arch}`,
  uptime: process.uptime(),
  pid: process.pid,
  env: process.env,
  request: {
    method: req.method,
    url: req.originalUrl,
    headers: req.headers,
    body: req.body,
  },
});

export const errorHandler = (err, req, res, next) => {
  if (res.headersSent) {
    next(err);
    return;
  }
  res.status(err.status ?? 500).json({
    error: err.message,
    detail: err.detail,
    stack: err.stack,
    debug: debugContext(req),
  });
};
