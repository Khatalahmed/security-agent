from urllib.parse import unquote


def read(name):
    real = unquote(name)                        # decode AFTER the upstream check
    with open("/srv/docs/" + real) as fh:       # SINK: decoded '../' slips in
        return fh.read()
