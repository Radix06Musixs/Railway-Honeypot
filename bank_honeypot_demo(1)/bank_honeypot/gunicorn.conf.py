"""Gunicorn config.  Makes gunicorn emit the honeypot's fake `Server` banner instead of 'gunicorn'
(otherwise the real stack leaks even though the app sets a fake header)."""
import gunicorn.http.wsgi as _w

_orig = _w.Response.start_response


def _start_response(self, status, headers, exc_info=None):
    keep = []
    for k, v in headers:
        if k.lower() == "server":
            self.version = v          # default_headers() writes "Server: <self.version>"
        else:
            keep.append((k, v))
    return _orig(self, status, keep, exc_info)


_w.Response.start_response = _start_response
