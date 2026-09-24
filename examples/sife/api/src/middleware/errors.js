export const notFound = (req, res) => {
  res.status(404).json({ error: 'not_found', path: req.path });
};

export const errorHandler = (err, req, res, next) => {
  if (res.headersSent) {
    next(err);
    return;
  }
  res.status(err.status ?? 500).json({
    error: err.message,
    detail: err.detail,
    stack: err.stack,
  });
};
